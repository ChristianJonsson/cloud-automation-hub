<#
.SYNOPSIS
Updates missing Entra ID userType values for confidently classified users, e.g. Members or Guests.

.DESCRIPTION
Retrieves users from Microsoft Graph (or reuses cached Graph query results), identifies accounts where userType is null,
classifies users with high confidence as Member or Guest, exports review/audit files,
and updates userType based on selected target mode.

.NOTES
Requires Microsoft Graph PowerShell authentication with permission to read and update users.
Use -UseCachedGraphResults to reuse cached `$users` and `$verifiedDomains` variables from the current PowerShell session.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$DryRun,
    [ValidateSet('Member', 'Guest', 'Both')]
    [string]$TargetType = 'Member',
    [switch]$UseCachedGraphResults,
    [switch]$EnableGuestUpdates,
    [Alias('h')]
    [switch]$Help
)

if ($Help) {
    @"
Usage:
    .\Update-Users-Where-UserType-Missing.ps1 [-TargetType Member|Guest|Both] [-UseCachedGraphResults] [-EnableGuestUpdates] [-DryRun] [-WhatIf] [-Confirm] [-Help|-h]

Options:
    -TargetType
        Selects which inferred user types to process when UserType is null.
        Values: Member (default), Guest, Both.

    -UseCachedGraphResults
        Reuses cached Graph query variables from the current PowerShell session when valid.
        Cached variables checked: `$users and `$verifiedDomains.
        Falls back to live Graph queries when cached values are missing or invalid.

    -EnableGuestUpdates
        Safety gate for real guest writes. Required for non-preview Guest/Both runs.

    -DryRun
        Preview mode. No updates are written.

    -WhatIf
        Standard PowerShell simulation via ShouldProcess.

    -Confirm
        Prompts before each update operation.

    -Help, -h
        Show this help text.

Notes:
    - Skipped users are always exported to:
        .\Review_Skipped_Users\SkippedUsers-<timestamp>.csv
    - Preview exports (DryRun/WhatIf) are written to:
        .\Review_Would_Update_Members\WouldUpdateMembers-<timestamp>.csv
        .\Review_Would_Update_Guests\WouldUpdateGuests-<timestamp>.csv
        - Log entries are written to .\Logs\UserUpdate.log for preview and non-preview runs.
    - Cached Graph data reuse is in-memory only and applies to the current PowerShell session.
      If cached values are not present or do not match expected structure, live Graph queries are used.
    - Guest writes can have broader policy impact. Use -DryRun or -WhatIf first.
"@ | Write-Host
    return
}

# Logging module configuration
$Global:LogFilePath = ".\UserUpdate.log"
$moduleRoot = Join-Path $PSScriptRoot 'Modules\UserTypeNullRemediation'
Import-Module (Join-Path $moduleRoot 'Logging.psm1')
Import-Module (Join-Path $moduleRoot 'GraphConnection.psm1')
Import-Module (Join-Path $moduleRoot 'GraphData.psm1')
Import-Module (Join-Path $moduleRoot 'Classification.psm1')
Set-LogFilePath -Path (Join-Path $PSScriptRoot 'Logs\UserUpdate.log')

# Console banner
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Updating Missing UserType Accounts" -ForegroundColor Cyan
Write-Host "=====================================`n" -ForegroundColor Cyan

Write-Log("Starting UserType processing. TargetType=$TargetType")

$isPreviewMode = $DryRun.IsPresent -or [bool]$WhatIfPreference

$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$skippedReviewFolder = Join-Path $PSScriptRoot 'Review_Skipped_Users'
$memberPreviewFolder = Join-Path $PSScriptRoot 'Review_Would_Update_Members'
$guestPreviewFolder = Join-Path $PSScriptRoot 'Review_Would_Update_Guests'
$skippedExportPath = Join-Path $skippedReviewFolder "SkippedUsers-$runTimestamp.csv"
$memberPreviewExportPath = Join-Path $memberPreviewFolder "WouldUpdateMembers-$runTimestamp.csv"
$guestPreviewExportPath = Join-Path $guestPreviewFolder "WouldUpdateGuests-$runTimestamp.csv"

if (-not (Test-Path -Path $skippedReviewFolder)) {
    New-Item -ItemType Directory -Path $skippedReviewFolder -Force | Out-Null
}

if ($isPreviewMode -and -not (Test-Path -Path $memberPreviewFolder)) {
    New-Item -ItemType Directory -Path $memberPreviewFolder -Force | Out-Null
}

if ($isPreviewMode -and -not (Test-Path -Path $guestPreviewFolder)) {
    New-Item -ItemType Directory -Path $guestPreviewFolder -Force | Out-Null
}

if ($DryRun) {
    Write-Log("DryRun mode enabled. No update writes will be attempted.")
}

if ($WhatIfPreference) {
    Write-Log("WhatIf mode enabled. ShouldProcess will simulate update writes.")
}

if (($TargetType -in @('Guest', 'Both')) -and -not $isPreviewMode -and -not $EnableGuestUpdates) {
    $guestSafetyError = "Guest writes requested without -EnableGuestUpdates. Use -DryRun/-WhatIf first or re-run with -EnableGuestUpdates."
    Write-Log($guestSafetyError)
    Write-Error $guestSafetyError -ErrorAction Stop
}


# Ensure Microsoft Graph PowerShell is available, imported, and connected with needed scopes.
try {
    Connect-MgGraphWithRequirements -GraphModuleNames @('Microsoft.Graph.Users', 'Microsoft.Graph.Identity.DirectoryManagement') -RequiredScopes @('User.Read.All', 'User.ReadWrite.All', 'Organization.Read.All')
}
catch {
    $graphSetupError = "Stopping script because Graph prerequisites failed: $($_.Exception.Message)"
    Write-Log($graphSetupError)
    Write-Error $graphSetupError -ErrorAction Stop
}


# User properties required for filtering, logging, and future update logic.
$properties = @(
    'id','userType','displayName','userPrincipalName','mail','createdDateTime',
    'creationType','accountEnabled','assignedLicenses','identities',
    'externalUserState',
    'ServiceProvisioningErrors','onPremisesSyncEnabled',
    'onPremisesDistinguishedName','onPremisesDomainName',
    'onPremisesSamAccountName','onPremisesSecurityIdentifier',
    'onPremisesImmutableId','onPremisesLastSyncDateTime',
    'onPremisesUserPrincipalName',
    'onPremisesExtensionAttributes'
)

$requiredCachedUserProperties = @(
    'Id','UserType','DisplayName','UserPrincipalName',
    'CreationType','ExternalUserState','AccountEnabled','AssignedLicenses','Identities',
    'OnPremisesSyncEnabled','OnPremisesDistinguishedName',
    'OnPremisesSecurityIdentifier','OnPremisesImmutableId'
)

# Show selected properties for traceability.
Write-Host "User Properties selected:"
foreach ($prop in $properties){ Write-Host "  - $prop" }

$usersResult = Get-UsersFromGraphOrCache -UseCachedGraphResults:$UseCachedGraphResults -Properties $properties -RequiredCachedUserProperties $requiredCachedUserProperties
$users = @($usersResult.Users)
$Global:users = $users

# Force array output so Count is reliable for 0/1/many results.
$usersWithNoUserType = @($users | Where-Object { $_.UserType -eq $null })
Write-Log("Users missing 'UserType' property: $($usersWithNoUserType.Count)...")

$domainsResult = Get-VerifiedDomainsFromGraphOrCache -UseCachedGraphResults:$UseCachedGraphResults
$verifiedDomains = @($domainsResult.Domains)
$Global:verifiedDomains = $verifiedDomains

if ($verifiedDomains.Count -gt 0) {
    Write-Log("Domain check enabled: users with missing UserType and UPN suffix in verified domains can be treated as confident cloud-only members.")
}
else {
    Write-Log("Domain check disabled: no verified domains were loaded, so only synced identity signals will mark members as confident.")
}

$classifiedUsers = foreach ($user in $usersWithNoUserType) {
    $memberClassification = $null
    $guestClassification = $null

    $proposedUserType = $null
    $reason = $null

    switch ($TargetType) {
        'Member' {
            $memberClassification = Test-ConfidentMemberCandidate -User $user -TenantDomains $verifiedDomains
            if ($memberClassification.IsConfidentMember) {
                $proposedUserType = 'Member'
                $reason = $memberClassification.Reason
            }
            else {
                $reason = "Not selected for Member: $($memberClassification.Reason)"
            }
        }
        'Guest' {
            $guestClassification = Test-ConfidentGuestCandidate -User $user -TenantDomains $verifiedDomains
            if ($guestClassification.IsConfidentGuest) {
                $proposedUserType = 'Guest'
                $reason = $guestClassification.Reason
            }
            else {
                $reason = "Not selected for Guest: $($guestClassification.Reason)"
            }
        }
        'Both' {
            # In Both mode we must evaluate both classifiers to detect conflicts.
            $memberClassification = Test-ConfidentMemberCandidate -User $user -TenantDomains $verifiedDomains
            $guestClassification = Test-ConfidentGuestCandidate -User $user -TenantDomains $verifiedDomains

            if ($memberClassification.IsConfidentMember -and $guestClassification.IsConfidentGuest) {
                $proposedUserType = $null
                $reason = "Conflicting classification signals. Member=$($memberClassification.Reason) | Guest=$($guestClassification.Reason)"
            }
            elseif ($memberClassification.IsConfidentMember) {
                $proposedUserType = 'Member'
                $reason = $memberClassification.Reason
            }
            elseif ($guestClassification.IsConfidentGuest) {
                $proposedUserType = 'Guest'
                $reason = $guestClassification.Reason
            }
            else {
                $reason = "No confident classification. Member=$($memberClassification.Reason) | Guest=$($guestClassification.Reason)"
            }
        }
    }

    [pscustomobject]@{
        User = $user
        ProposedUserType = $proposedUserType
        Reason = $reason
        MemberReason = if ($null -ne $memberClassification) { $memberClassification.Reason } else { 'Not evaluated for this TargetType' }
        GuestReason = if ($null -ne $guestClassification) { $guestClassification.Reason } else { 'Not evaluated for this TargetType' }
    }
}

$updateCandidates = @($classifiedUsers | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ProposedUserType) })
$memberCandidates = @($updateCandidates | Where-Object { $_.ProposedUserType -eq 'Member' })
$guestCandidates = @($updateCandidates | Where-Object { $_.ProposedUserType -eq 'Guest' })
$skippedCandidates = @($classifiedUsers | Where-Object { [string]::IsNullOrWhiteSpace($_.ProposedUserType) })

Write-Log("Confident member candidates to update: $($memberCandidates.Count)")
Write-Log("Confident guest candidates to update: $($guestCandidates.Count)")
Write-Log("Skipped candidates (insufficient confidence or guest indicators): $($skippedCandidates.Count)")

foreach ($skipped in $skippedCandidates) {
    Write-Log("Skipped $($skipped.User.UserPrincipalName): $($skipped.Reason)")
}

$skippedExport = $skippedCandidates | ForEach-Object {
    New-PolicyImpactRecord -User $_.User -Reason $_.Reason -ProposedUserType ''
}

$skippedExport | Export-Csv -Path $skippedExportPath -NoTypeInformation -Encoding UTF8
Write-Log("Skipped users exported to: $skippedExportPath")

if ($isPreviewMode) {
    $memberPreviewExport = $memberCandidates | ForEach-Object {
        New-PolicyImpactRecord -User $_.User -Reason $_.Reason -ProposedUserType 'Member'
    }
    $guestPreviewExport = $guestCandidates | ForEach-Object {
        New-PolicyImpactRecord -User $_.User -Reason $_.Reason -ProposedUserType 'Guest'
    }

    $memberPreviewExport | Export-Csv -Path $memberPreviewExportPath -NoTypeInformation -Encoding UTF8
    $guestPreviewExport | Export-Csv -Path $guestPreviewExportPath -NoTypeInformation -Encoding UTF8

    Write-Log("Preview member candidates exported to: $memberPreviewExportPath")
    Write-Log("Preview guest candidates exported to: $guestPreviewExportPath")
}

Write-Host "Updating users where UserType is missing..." -ForegroundColor Cyan

# Progress tracking
$total = @($updateCandidates).Count
$counter = 0

if ($total -eq 0) {
    Write-Log("No users need updating. Exiting.")
    Write-Host "No confidently classified users found for TargetType '$TargetType'." -ForegroundColor Yellow
    return
}

foreach ($candidate in $updateCandidates) {
    $user = $candidate.User

    $counter++
    
    # Use integer-safe progress math for large datasets and clamp to valid range.
    if ($counter -ge $total) {
        $percent = 100
    }
    else {
        $percent = [int](($counter * 100.0) / $total)
    }

    if ($percent -lt 0) { $percent = 0 }
    if ($percent -gt 100) { $percent = 100 }

    Write-Progress -Activity "Updating UserType ($TargetType)" `
                    -Status "Processing $counter of $total ($percent%)" `
                    -PercentComplete $percent

    $shouldLogThisItem = ($counter -eq 1) -or ($counter -eq $total) -or ($counter % 250 -eq 0)

    # Log at meaningful checkpoints to keep progress bar readable in large runs.
    if ($shouldLogThisItem) {
        Write-Log("Updating user ${counter} of ${total}: $($user.UserPrincipalName) | TargetType=$($candidate.ProposedUserType) | Reason: $($candidate.Reason)")
    }

    if ($DryRun) {
        if ($shouldLogThisItem) {
            Write-Log("DRYRUN: Would update $($user.UserPrincipalName) (UserId: $($user.Id)) to UserType='$($candidate.ProposedUserType)'")
        }
        Start-Sleep -Milliseconds 20
        continue
    }

    if (-not $PSCmdlet.ShouldProcess($user.UserPrincipalName, "Set UserType to '$($candidate.ProposedUserType)'")) {
        Start-Sleep -Milliseconds 20
        continue
    }

    try {
        Update-MgUser -UserId $user.Id -UserType $candidate.ProposedUserType -ErrorAction Stop
    }
    catch {
        Write-Log("Failed to update $($user.UserPrincipalName): $($_.Exception.Message)")
        continue
    }

    # Delay for easier visual progress tracking during manual runs.
    Start-Sleep -Milliseconds 150
}

Write-Progress -Activity "Updating UserType" -Completed

