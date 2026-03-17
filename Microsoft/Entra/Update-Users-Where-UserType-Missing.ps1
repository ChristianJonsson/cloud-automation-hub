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
    - Skipped users are exported only when one or more skipped candidates exist:
        .\Reports\UserTypeNullRemediation\Reports_Skipped_Users\SkippedUsersReport-<timestamp>.csv
    - Preview exports (DryRun/WhatIf) are written only when matching candidates exist:
        .\Reports\UserTypeNullRemediation\Reports_Would_Update_Members\WouldUpdateMembersReport-<timestamp>.csv
        .\Reports\UserTypeNullRemediation\Reports_Would_Update_Guests\WouldUpdateGuestsReport-<timestamp>.csv
    - Log entries are written to .\Logs\UserUpdate.log for preview and non-preview runs.
    - Cached Graph data reuse is in-memory only and applies to the current PowerShell session.
      If cached values are not present or do not match expected structure, live Graph queries are used.
    - Guest writes can have broader policy impact. Use -DryRun or -WhatIf first.
"@ | Write-Host
    return
}

# Logging module configuration
$Global:LogFilePath = ".\UserUpdate.log"
$commonSharedModuleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'Common\Modules\Shared'
$entraSharedModuleRoot = Join-Path $PSScriptRoot 'Modules\Shared'
$featureModuleRoot = Join-Path $PSScriptRoot 'Modules\UserTypeNullRemediation'
Import-Module (Join-Path $commonSharedModuleRoot 'Logging.psm1') -Force
Import-Module (Join-Path $entraSharedModuleRoot 'GraphConnection.psm1') -Force
Import-Module (Join-Path $entraSharedModuleRoot 'GraphData.psm1') -Force
Import-Module (Join-Path $featureModuleRoot 'Classification.psm1') -Force
Set-LogFilePath -Path (Join-Path $PSScriptRoot 'Logs\UserUpdate.log')

function Ensure-DirectoryIfNeeded {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [bool]$Condition = $true
    )

    if ($Condition -and -not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Export-PolicyImpactCsvIfAny {
    param(
        [object[]]$Candidates = @(),

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$ProposedUserType = '',

        [Parameter(Mandatory = $true)]
        [string]$SuccessPrefix,

        [Parameter(Mandatory = $true)]
        [string]$EmptyMessage
    )

    $candidateArray = @($Candidates)
    if ($candidateArray.Count -eq 0) {
        Write-Log($EmptyMessage)
        return
    }

    $exportRows = $candidateArray | ForEach-Object {
        New-PolicyImpactRecord -User $_.User -Reason $_.Reason -ProposedUserType $ProposedUserType
    }

    $exportRows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    Write-Log("${SuccessPrefix}: $Path")
}

function Test-IsCheckpointIteration {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Counter,

        [Parameter(Mandatory = $true)]
        [int]$Total,

        [int]$Interval = 50
    )

    return ($Counter -eq 1) -or ($Counter -eq $Total) -or ($Counter % $Interval -eq 0)
}

# Console banner
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Updating Missing UserType Accounts" -ForegroundColor Cyan
Write-Host "=====================================`n" -ForegroundColor Cyan

Write-Log("Starting UserType processing. TargetType=$TargetType")

$isPreviewMode = $DryRun.IsPresent -or [bool]$WhatIfPreference

$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$reportsRootFolder = Join-Path $PSScriptRoot 'Reports\UserTypeNullRemediation'
$skippedReportFolder = Join-Path $reportsRootFolder 'Reports_Skipped_Users'
$memberPreviewReportFolder = Join-Path $reportsRootFolder 'Reports_Would_Update_Members'
$guestPreviewReportFolder = Join-Path $reportsRootFolder 'Reports_Would_Update_Guests'
$skippedExportPath = Join-Path $skippedReportFolder "SkippedUsersReport-$runTimestamp.csv"
$memberPreviewExportPath = Join-Path $memberPreviewReportFolder "WouldUpdateMembersReport-$runTimestamp.csv"
$guestPreviewExportPath = Join-Path $guestPreviewReportFolder "WouldUpdateGuestsReport-$runTimestamp.csv"

Ensure-DirectoryIfNeeded -Path $skippedReportFolder
Ensure-DirectoryIfNeeded -Path $memberPreviewReportFolder -Condition $isPreviewMode
Ensure-DirectoryIfNeeded -Path $guestPreviewReportFolder -Condition $isPreviewMode

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
    'jobTitle','companyName','department','officeLocation',
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
    'JobTitle','CompanyName','Department','OfficeLocation',
    'CreationType','ExternalUserState','AccountEnabled','AssignedLicenses','Identities',
    'OnPremisesSyncEnabled','OnPremisesDistinguishedName',
    'OnPremisesSecurityIdentifier','OnPremisesImmutableId',
    'OnPremisesExtensionAttributes'
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

Export-PolicyImpactCsvIfAny -Candidates $skippedCandidates `
                            -Path $skippedExportPath `
                            -ProposedUserType '' `
                            -SuccessPrefix 'Skipped users exported to' `
                            -EmptyMessage 'Skipped users export not created because there are no skipped candidates.'

if ($isPreviewMode) {
    Export-PolicyImpactCsvIfAny -Candidates $memberCandidates `
                                -Path $memberPreviewExportPath `
                                -ProposedUserType 'Member' `
                                -SuccessPrefix 'Preview member candidates exported to' `
                                -EmptyMessage 'Preview member export not created because there are no member candidates.'

    Export-PolicyImpactCsvIfAny -Candidates $guestCandidates `
                                -Path $guestPreviewExportPath `
                                -ProposedUserType 'Guest' `
                                -SuccessPrefix 'Preview guest candidates exported to' `
                                -EmptyMessage 'Preview guest export not created because there are no guest candidates.'
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

    $shouldLogThisItem = Test-IsCheckpointIteration -Counter $counter -Total $total

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

