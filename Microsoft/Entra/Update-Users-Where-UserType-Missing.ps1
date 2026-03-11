<#
.SYNOPSIS
Updates missing Entra ID userType values for confidently classified users, e.g. Members or Guests.

.DESCRIPTION
Retrieves users from Microsoft Graph, identifies accounts where userType is null,
classifies users with high confidence as Member or Guest, exports review/audit files,
and updates userType based on selected target mode.

.NOTES
Requires Microsoft Graph PowerShell authentication with permission to read and update users.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$DryRun,
    [ValidateSet('Member', 'Guest', 'Both')]
    [string]$TargetType = 'Member',
    [switch]$EnableGuestUpdates,
    [Alias('h')]
    [switch]$Help
)

if ($Help) {
    @"
Usage:
    .\Update-Users-Where-UserType-Missing.ps1 [-TargetType Member|Guest|Both] [-EnableGuestUpdates] [-DryRun] [-WhatIf] [-Confirm] [-Help|-h]

Options:
    -TargetType
        Selects which inferred user types to process when UserType is null.
        Values: Member (default), Guest, Both.

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
    - Guest writes can have broader policy impact. Use -DryRun or -WhatIf first.
"@ | Write-Host
    return
}

# Logging module configuration
$Global:LogFilePath = ".\UserUpdate.log"
$moduleRoot = Join-Path $PSScriptRoot 'Modules\UserTypeNullRemediation'
Import-Module (Join-Path $moduleRoot 'Logging.psm1')
Import-Module (Join-Path $moduleRoot 'GraphConnection.psm1')
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

function Get-IdentitiesSummary {
    param([object[]]$Identities)

    if (-not $Identities -or $Identities.Count -eq 0) {
        return ''
    }

    $parts = foreach ($identity in $Identities) {
        $signInType = "$($identity.SignInType)"
        $issuer = "$($identity.Issuer)"
        $issuerAssignedId = "$($identity.IssuerAssignedId)"
        "$signInType|$issuer|$issuerAssignedId"
    }

    return ($parts -join '; ')
}

function New-PolicyImpactRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [string]$ProposedUserType = ''
    )

    [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        UserPrincipalName = $User.UserPrincipalName
        DisplayName = $User.DisplayName
        Id = $User.Id
        CurrentUserType = $User.UserType
        ProposedUserType = $ProposedUserType
        Reason = $Reason
        CreationType = $User.CreationType
        ExternalUserState = $User.ExternalUserState
        AccountEnabled = $User.AccountEnabled
        OnPremisesSyncEnabled = $User.OnPremisesSyncEnabled
        OnPremisesImmutableId = $User.OnPremisesImmutableId
        OnPremisesSecurityIdentifier = $User.OnPremisesSecurityIdentifier
        AssignedLicensesCount = @($User.AssignedLicenses).Count
        IdentitiesSummary = Get-IdentitiesSummary -Identities $User.Identities
        PolicyImpactNotes = 'Review Conditional Access, dynamic group rules, app/group assignments, and entitlement policies before write.'
    }
}

function Get-TenantVerifiedDomains {
    if (-not (Get-Command -Name Get-MgOrganization -ErrorAction SilentlyContinue)) {
        Write-Log("Get-MgOrganization is unavailable. Domain-based confidence checks will be skipped.")
        return @()
    }

    try {
        $organization = Get-MgOrganization -Property VerifiedDomains -ErrorAction Stop | Select-Object -First 1
        $domains = @($organization.VerifiedDomains.Name | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        Write-Log("Loaded $($domains.Count) verified tenant domains for confidence checks.")
        return $domains
    }
    catch {
        Write-Log("Could not read verified tenant domains: $($_.Exception.Message). Domain-based checks will be skipped.")
        return @()
    }
}

function Test-ConfidentMemberCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [string[]]$TenantDomains = @()
    )

    $signals = @()

    if (-not [string]::IsNullOrWhiteSpace($User.UserType)) {
        return [pscustomobject]@{
            IsConfidentMember = $false
            Reason = "UserType already set to '$($User.UserType)'"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($User.UserPrincipalName) -and $User.UserPrincipalName -match '#EXT#') {
        return [pscustomobject]@{
            IsConfidentMember = $false
            Reason = 'Guest indicator: UPN contains #EXT#'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($User.ExternalUserState)) {
        return [pscustomobject]@{
            IsConfidentMember = $false
            Reason = "Guest indicator: ExternalUserState = '$($User.ExternalUserState)'"
        }
    }

    if ($User.CreationType -eq 'Invitation') {
        return [pscustomobject]@{
            IsConfidentMember = $false
            Reason = "Guest indicator: CreationType = '$($User.CreationType)'"
        }
    }

    if ($User.OnPremisesSyncEnabled -eq $true) {
        $signals += 'OnPremisesSyncEnabled=true'
    }

    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesImmutableId)) {
        $signals += 'OnPremisesImmutableId present'
    }

    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesSecurityIdentifier)) {
        $signals += 'OnPremisesSecurityIdentifier present'
    }

    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesDistinguishedName)) {
        $signals += 'OnPremisesDistinguishedName present'
    }

    if ($signals.Count -gt 0) {
        return [pscustomobject]@{
            IsConfidentMember = $true
            Reason = "Confident member (synced): $($signals -join '; ')"
        }
    }

    $upn = "$($User.UserPrincipalName)"
    if ($upn -match '@') {
        $domain = ($upn.Split('@')[-1]).ToLowerInvariant()
        $knownDomains = @($TenantDomains | ForEach-Object { $_.ToLowerInvariant() })
        if ($knownDomains -contains $domain) {
            return [pscustomobject]@{
                IsConfidentMember = $true
                Reason = "Confident member (cloud-only): UPN domain '$domain' is a verified tenant domain"
            }
        }
    }

    return [pscustomobject]@{
        IsConfidentMember = $false
        Reason = 'Insufficient evidence to classify as Member with confidence'
    }
}

function Test-ConfidentGuestCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [string[]]$TenantDomains = @()
    )

    if (-not [string]::IsNullOrWhiteSpace($User.UserType)) {
        return [pscustomobject]@{
            IsConfidentGuest = $false
            Reason = "UserType already set to '$($User.UserType)'"
        }
    }

    $internalSignals = @()
    if ($User.OnPremisesSyncEnabled -eq $true) { $internalSignals += 'OnPremisesSyncEnabled=true' }
    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesImmutableId)) { $internalSignals += 'OnPremisesImmutableId present' }
    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesSecurityIdentifier)) { $internalSignals += 'OnPremisesSecurityIdentifier present' }
    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesDistinguishedName)) { $internalSignals += 'OnPremisesDistinguishedName present' }

    if ($internalSignals.Count -gt 0) {
        return [pscustomobject]@{
            IsConfidentGuest = $false
            Reason = "Internal/synced indicator(s): $($internalSignals -join '; ')"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($User.UserPrincipalName) -and $User.UserPrincipalName -match '#EXT#') {
        return [pscustomobject]@{
            IsConfidentGuest = $true
            Reason = 'Confident guest: UPN contains #EXT#'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($User.ExternalUserState)) {
        return [pscustomobject]@{
            IsConfidentGuest = $true
            Reason = "Confident guest: ExternalUserState = '$($User.ExternalUserState)'"
        }
    }

    if ($User.CreationType -eq 'Invitation') {
        return [pscustomobject]@{
            IsConfidentGuest = $true
            Reason = "Confident guest: CreationType = '$($User.CreationType)'"
        }
    }

    $upn = "$($User.UserPrincipalName)"
    if ($upn -match '@') {
        $domain = ($upn.Split('@')[-1]).ToLowerInvariant()
        $knownDomains = @($TenantDomains | ForEach-Object { $_.ToLowerInvariant() })
        if ($knownDomains -contains $domain) {
            return [pscustomobject]@{
                IsConfidentGuest = $false
                Reason = "UPN domain '$domain' is a verified tenant domain and no strong guest indicator is present"
            }
        }
    }

    return [pscustomobject]@{
        IsConfidentGuest = $false
        Reason = 'Insufficient evidence to classify as Guest with confidence'
    }
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
# Show selected properties for traceability.
Write-Host "User Properties selected:"
foreach ($prop in $properties){ Write-Host "  - $prop" }
# Query all users using eventual consistency for large-tenant pagination scenarios.
Write-Host "Retrieving users from Microsoft Graph... This will take several minutes..." -ForegroundColor Cyan
$users = Get-MgUser -All -ConsistencyLevel eventual -Property $properties
Write-Log("Found $($users.Count) users...")

# Force array output so Count is reliable for 0/1/many results.
$usersWithNoUserType = @($users | Where-Object { $_.UserType -eq $null })
Write-Log("Users missing 'UserType' property: $($usersWithNoUserType.Count)...")

$verifiedDomains = Get-TenantVerifiedDomains
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

