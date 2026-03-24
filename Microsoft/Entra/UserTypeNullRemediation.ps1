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
For policy-impact preflight checks, delegated read scopes are also required:
Policy.Read.All, Directory.Read.All, EntitlementManagement.Read.All, RoleManagement.Read.Directory.
The script validates report, export, and preflight artifact paths before Graph operations begin.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Member', 'Guest', 'Both')]
    [string]$TargetType = 'Member',
    [switch]$UseCachedGraphResults,
    [switch]$EnableGuestUpdates,
    [ValidateSet('Strict', 'Balanced', 'Permissive')]
    [string]$StrictnessMode = 'Balanced',
    [ValidateRange(0, 2147483647)]
    [int]$TopUsers = 0,
    [switch]$IncludePolicyImpactNamesInLog,
    [Alias('h')]
    [switch]$Help
)

if ($Help) {
    @"
Usage:
    .\UserTypeNullRemediation.ps1 [-TargetType Member|Guest|Both] [-UseCachedGraphResults] [-EnableGuestUpdates] [-StrictnessMode Strict|Balanced|Permissive] [-TopUsers <count>] [-IncludePolicyImpactNamesInLog] [-WhatIf] [-Confirm] [-Help|-h]

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

    -StrictnessMode
        Controls how policy prerequisite findings are enforced in write mode.
        Strict = advisory and critical failures block writes.
        Balanced (default) = only critical failures block writes.
        Permissive = allows write mode to continue when EntitlementManagement checks are unavailable.
        Permissive still records partial coverage in logs/CSV metadata and blocks on other critical failures.

    -TopUsers
        Limits classification, policy evaluation, and update/preview processing to the first N users
        from the set of accounts where userType is null.
        Default: 0 (process all matching users).

    -IncludePolicyImpactNamesInLog
        Includes per-user policy impact name details in log lines for candidate processing.
        Default behavior keeps logs concise and writes only aggregate count/risk summary.

    -WhatIf
        Preview mode. Generates CSV exports and preflight artifacts without writing user updates.
        Per-item ShouldProcess messages are suppressed for readability on large runs;
        review the WouldUpdate CSV exports instead.

    -Confirm
        Prompts before each update operation.

    -Help, -h
        Show this help text.

Notes:
    - Skipped users are exported only when one or more skipped candidates exist:
        .\Reports\UserTypeNullRemediation\Reports_Skipped_Users\SkippedUsers-<timestamp>.csv
    - Preview exports (WhatIf) are written only when matching candidates exist:
        .\Reports\UserTypeNullRemediation\Reports_Would_Update_Members\WouldUpdateMembers-<timestamp>.csv
        .\Reports\UserTypeNullRemediation\Reports_Would_Update_Guests\WouldUpdateGuests-<timestamp>.csv
    - Non-preview update outcome exports are written only when matching records exist:
        .\Reports\UserTypeNullRemediation\Reports_Updated_Users\UpdatedUsers-<timestamp>.csv
        .\Reports\UserTypeNullRemediation\Reports_Failed_Updates\FailedUpdates-<timestamp>.csv
    - Preflight artifacts are written to:
        .\Reports\UserTypeNullRemediation\Preflight.preview-<timestamp>.json (preview / -WhatIf)
        .\Reports\UserTypeNullRemediation\Preflight-<timestamp>.json (non-preview)
    - Log entries are written to .\Logs\UserUpdate.preview.log for preview (-WhatIf) runs
      and .\Logs\UserUpdate.log for non-preview runs.
        - Report/export/preflight paths are validated before Graph operations begin.
            Invalid or empty path values stop execution early with a clear error.
    - Cached Graph data reuse is in-memory only and applies to the current PowerShell session.
      If cached values are not present or do not match expected structure, live Graph queries are used.
    - Guest writes can have broader policy impact. Use -WhatIf first.
    - -TopUsers limits processing to the first N users with missing userType after the
      null-userType filter is applied.
    - Delegated read scopes for policy checks:
        Policy.Read.All, Directory.Read.All, EntitlementManagement.Read.All,
        RoleManagement.Read.Directory.
    - Policy impact checks are executed for these areas (all critical unless noted):
      ConditionalAccess: IncludeUsers/ExcludeUsers, IncludeGroups/ExcludeGroups matching.
        Disabled policies are not filtered and still count as matches.
        GuestsOrExternalUsers conditions, named locations, device compliance, and app
        conditions are not evaluated.
      DynamicGroups: flags groups whose MembershipRule contains 'user.userType', 'userType',
        or the proposed type value. For each match, calls POST /groups/{id}/evaluateDynamicMembership
        to check current membership for the specific user, then combines with -eq/-ne pattern
        extraction to estimate post-change membership. Reports WouldJoin, WouldLeave,
        RequiresManualReview, or NoChange (not counted). Complex rule expressions beyond
        simple -eq/-ne comparisons on user.userType are not evaluated.
      GroupAndAppAssignments: counts direct group memberships (Get-MgUserMemberOf) and app
        role assignments (Get-MgUserAppRoleAssignment). Transitive group nesting is not
        resolved beyond what the API returns directly.
      EntitlementManagement: counts active access package assignments for the user.
        In Permissive mode, an unavailable scope records partial coverage but does not block.
        Access package policy userType rules are not evaluated.
      DirectoryRoleAssignments: matches direct role assignments by PrincipalId.
        PIM eligible assignments and group-based role assignments are not included.
      LicensingHeuristics (advisory): probe only. No per-user counter is computed.
      TeamsExchangeHeuristics (advisory): disabled. Per-user Teams and mailbox probes are
        not executed. TeamsCount and HasMailbox will be absent from policy impact output.
      Non-preview runs stop before writes when critical policy checks are unavailable.
    - Each run writes a compact preflight summary to log and a detailed preflight JSON artifact.
    - Exported CSV rows include preflight metadata, computed policy-impact counters,
      and policy/group/role/entitlement detail-name columns with JSON detail payloads.
"@ | Write-Host
    return
}

# Logging module configuration
$isPreviewMode = [bool]$WhatIfPreference
$commonSharedModuleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'Common\Modules\Shared'
$entraSharedModuleRoot = Join-Path $PSScriptRoot 'Modules\Shared'
$featureModuleRoot = Join-Path $PSScriptRoot 'Modules\UserTypeNullRemediation'
Import-Module (Join-Path $commonSharedModuleRoot 'Logging.psm1') -Force
Import-Module (Join-Path $entraSharedModuleRoot 'GraphConnection.psm1') -Force
Import-Module (Join-Path $entraSharedModuleRoot 'GraphData.psm1') -Force
Import-Module (Join-Path $featureModuleRoot 'Classification.psm1') -Force
Import-Module (Join-Path $featureModuleRoot 'PolicyImpactExport.psm1') -Force
Import-Module (Join-Path $featureModuleRoot 'PolicyImpactValidation.psm1') -Force
$Global:LogFilePath = Get-DefaultUserUpdateLogPath -PreviewMode:$isPreviewMode -BaseDirectory $PSScriptRoot
Set-LogFilePath -Path $Global:LogFilePath

# Console banner
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "  Updating Missing UserType Accounts" -ForegroundColor Cyan
Write-Host "=====================================`n" -ForegroundColor Cyan

Write-Log("Starting UserType processing. TargetType=$TargetType")
Write-Log("StrictnessMode set to '$StrictnessMode'.")
Write-Log("TopUsers limit set to: $(if ($TopUsers -gt 0) { $TopUsers } else { 'All matching users' }).")
Write-Log("Log file path for this run: $Global:LogFilePath")

$policyImpactScopeMatrix = @(Get-PolicyImpactScopeMatrix)

$baseRequiredScopes = @('User.Read.All', 'User.ReadWrite.All', 'Organization.Read.All')
$policyRequiredScopes = @($policyImpactScopeMatrix | ForEach-Object { @($_.RequiredScopes) })
$allRequiredScopes = @($baseRequiredScopes + $policyRequiredScopes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
Write-Log("Graph delegated scopes requested for this run: $($allRequiredScopes -join ', ')")

$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$preflightRunId = "UserTypePreflight-$runTimestamp"
$reportFolderMap = [ordered]@{
    ReportsRoot = Join-Path $PSScriptRoot 'Reports\UserTypeNullRemediation'
}
$reportFolderMap['SkippedReview'] = Join-Path $reportFolderMap.ReportsRoot 'Reports_Skipped_Users'
$reportFolderMap['MemberPreview'] = Join-Path $reportFolderMap.ReportsRoot 'Reports_Would_Update_Members'
$reportFolderMap['GuestPreview'] = Join-Path $reportFolderMap.ReportsRoot 'Reports_Would_Update_Guests'
$reportFolderMap['UpdatedUsers'] = Join-Path $reportFolderMap.ReportsRoot 'Reports_Updated_Users'
$reportFolderMap['FailedUpdates'] = Join-Path $reportFolderMap.ReportsRoot 'Reports_Failed_Updates'

$reportsRootFolder = $reportFolderMap.ReportsRoot
$skippedReviewFolder = $reportFolderMap.SkippedReview
$memberPreviewFolder = $reportFolderMap.MemberPreview
$guestPreviewFolder = $reportFolderMap.GuestPreview
$updatedUsersFolder = $reportFolderMap.UpdatedUsers
$failedUpdatesFolder = $reportFolderMap.FailedUpdates

$exportFileMap = [ordered]@{
    Skipped = "SkippedUsers-$runTimestamp.csv"
    MemberPreview = "WouldUpdateMembers-$runTimestamp.csv"
    GuestPreview = "WouldUpdateGuests-$runTimestamp.csv"
    Updated = "UpdatedUsers-$runTimestamp.csv"
    Failed = "FailedUpdates-$runTimestamp.csv"
}

$skippedExportPath = Join-Path $skippedReviewFolder $exportFileMap.Skipped
$memberPreviewExportPath = Join-Path $memberPreviewFolder $exportFileMap.MemberPreview
$guestPreviewExportPath = Join-Path $guestPreviewFolder $exportFileMap.GuestPreview
$updatedUsersExportPath = Join-Path $updatedUsersFolder $exportFileMap.Updated
$failedUpdatesExportPath = Join-Path $failedUpdatesFolder $exportFileMap.Failed
$preflightArtifactPath = Get-DefaultUserUpdatePreflightArtifactPath -Timestamp $runTimestamp -PreviewMode:$isPreviewMode -BaseDirectory $PSScriptRoot

function Assert-RunPathsValid {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$PathEntries
    )

    $invalidPathChars = [System.IO.Path]::GetInvalidPathChars()

    foreach ($entry in @($PathEntries)) {
        $pathLabel = "$(if ($entry.Label) { $entry.Label } else { 'UnlabeledPath' })"
        $pathValue = "$(if ($null -ne $entry.Path) { $entry.Path } else { '' })"

        if ([string]::IsNullOrWhiteSpace($pathValue)) {
            $message = "Path validation failed for '$pathLabel': value is empty."
            Write-Log($message)
            Write-Error $message -ErrorAction Stop
        }

        if ($pathValue.IndexOfAny($invalidPathChars) -ge 0) {
            $message = "Path validation failed for '$pathLabel': path contains invalid filesystem characters. Value='$pathValue'"
            Write-Log($message)
            Write-Error $message -ErrorAction Stop
        }

        if (-not (Test-Path -Path $pathValue -IsValid)) {
            $message = "Path validation failed for '$pathLabel': path is not valid for this filesystem. Value='$pathValue'"
            Write-Log($message)
            Write-Error $message -ErrorAction Stop
        }
    }
}

$runPathEntries = @(
    [pscustomobject]@{ Label = 'ReportsRoot'; Path = $reportsRootFolder }
    [pscustomobject]@{ Label = 'SkippedReviewFolder'; Path = $skippedReviewFolder }
    [pscustomobject]@{ Label = 'MemberPreviewFolder'; Path = $memberPreviewFolder }
    [pscustomobject]@{ Label = 'GuestPreviewFolder'; Path = $guestPreviewFolder }
    [pscustomobject]@{ Label = 'UpdatedUsersFolder'; Path = $updatedUsersFolder }
    [pscustomobject]@{ Label = 'FailedUpdatesFolder'; Path = $failedUpdatesFolder }
    [pscustomobject]@{ Label = 'SkippedExportPath'; Path = $skippedExportPath }
    [pscustomobject]@{ Label = 'MemberPreviewExportPath'; Path = $memberPreviewExportPath }
    [pscustomobject]@{ Label = 'GuestPreviewExportPath'; Path = $guestPreviewExportPath }
    [pscustomobject]@{ Label = 'UpdatedUsersExportPath'; Path = $updatedUsersExportPath }
    [pscustomobject]@{ Label = 'FailedUpdatesExportPath'; Path = $failedUpdatesExportPath }
    [pscustomobject]@{ Label = 'PreflightArtifactPath'; Path = $preflightArtifactPath }
)
Assert-RunPathsValid -PathEntries $runPathEntries

$directoryInitializationPlans = @(
    [pscustomobject]@{ Path = $reportsRootFolder; Condition = $true }
    [pscustomobject]@{ Path = $skippedReviewFolder; Condition = $true }
    [pscustomobject]@{ Path = $memberPreviewFolder; Condition = $isPreviewMode }
    [pscustomobject]@{ Path = $guestPreviewFolder; Condition = $isPreviewMode }
    [pscustomobject]@{ Path = $updatedUsersFolder; Condition = (-not $isPreviewMode) }
    [pscustomobject]@{ Path = $failedUpdatesFolder; Condition = (-not $isPreviewMode) }
)

foreach ($directoryPlan in $directoryInitializationPlans) {
    Initialize-DirectoryIfNeeded -Path $directoryPlan.Path -Condition $directoryPlan.Condition
}

if ($WhatIfPreference) {
    Write-Log("WhatIf mode enabled. Preview CSV exports will be written; no update writes will be attempted.")
}

if (($TargetType -in @('Guest', 'Both')) -and -not $isPreviewMode -and -not $EnableGuestUpdates) {
    $guestSafetyError = "Guest writes requested without -EnableGuestUpdates. Use -WhatIf first or re-run with -EnableGuestUpdates."
    Write-Log($guestSafetyError)
    Write-Error $guestSafetyError -ErrorAction Stop
}


# Ensure Microsoft Graph PowerShell is available, imported, and connected with needed scopes.
try {
    Connect-MgGraphWithRequirements -GraphModuleNames @(
        'Microsoft.Graph.Users',
        'Microsoft.Graph.Identity.DirectoryManagement',
        'Microsoft.Graph.Groups',
        'Microsoft.Graph.Identity.SignIns',
        'Microsoft.Graph.Identity.Governance'
    ) -RequiredScopes $allRequiredScopes
}
catch {
    $graphSetupError = "Stopping script because Graph prerequisites failed: $($_.Exception.Message)"
    Write-Log($graphSetupError)
    Write-Error $graphSetupError -ErrorAction Stop
}

foreach ($scopeEntry in $policyImpactScopeMatrix) {
    $severity = if ($scopeEntry.IsCritical) { 'Critical' } else { 'Advisory' }
    Write-Log("Policy check scope requirements [$severity] $($scopeEntry.Area): $($scopeEntry.RequiredScopes -join ', ')")
}

try {
    $policyPrerequisiteResult = Test-PolicyImpactPrerequisites -IsPreviewMode:$isPreviewMode -StrictnessMode $StrictnessMode

    foreach ($result in @($policyPrerequisiteResult.Results)) {
        $severity = if ($result.IsCritical) { 'Critical' } else { 'Advisory' }
        Write-Log("Policy prerequisite [$severity] $($result.Area): $($result.Status) - $($result.Message)")
    }

    $preflightSummary = $policyPrerequisiteResult.Summary
    Write-Log("Policy preflight summary: $preflightSummary")

    $preflightArtifact = [pscustomobject]@{
        RunTimestamp = $runTimestamp
        PreflightRunId = $preflightRunId
        IsPreviewMode = $isPreviewMode
        TargetType = $TargetType
        StrictnessMode = $StrictnessMode
        Summary = $preflightSummary
        Result = $policyPrerequisiteResult
    }
    Initialize-DirectoryIfNeeded -Path (Split-Path -Path $preflightArtifactPath -Parent)
    $preflightArtifact | ConvertTo-Json -Depth 8 | Set-Content -Path $preflightArtifactPath -Encoding UTF8 -WhatIf:$false
    Write-Log("Policy preflight artifact exported to: $preflightArtifactPath")

    if (-not $policyPrerequisiteResult.CanProceed) {
        Write-Log($policyPrerequisiteResult.BlockingMessage)
        Write-Error $policyPrerequisiteResult.BlockingMessage -ErrorAction Stop
    }

    if ($policyPrerequisiteResult.AdvisoryFindings.Count -gt 0) {
        Write-Log("Policy advisory findings: $((@($policyPrerequisiteResult.AdvisoryFindings | ForEach-Object { $_.Area }) -join ', '))")
    }
}
catch {
    $policyPreflightError = "Stopping script because policy prerequisite validation failed: $($_.Exception.Message)"
    Write-Log($policyPreflightError)
    Write-Error $policyPreflightError -ErrorAction Stop
}

$policyImpactContext = Initialize-PolicyImpactContext -PrerequisiteResult $policyPrerequisiteResult
Write-Log('Initialized policy impact context from preflight results.')


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

if ($TopUsers -gt 0) {
    if ($usersWithNoUserType.Count -gt $TopUsers) {
        Write-Log("WARNING: Limiting processing to the first $TopUsers of $($usersWithNoUserType.Count) users with missing UserType due to -TopUsers.")
        $usersWithNoUserType = @($usersWithNoUserType | Select-Object -First $TopUsers)
    }
    else {
        Write-Log("TopUsers limit requested ($TopUsers), but only $($usersWithNoUserType.Count) users with missing UserType were found.")
    }
}

Write-Log("Users selected for classification, evaluation, and update processing: $($usersWithNoUserType.Count).")

$domainsResult = Get-VerifiedDomainsFromGraphOrCache -UseCachedGraphResults:$UseCachedGraphResults
$verifiedDomains = @($domainsResult.Domains)
$Global:verifiedDomains = $verifiedDomains

if ($verifiedDomains.Count -gt 0) {
    Write-Log("Domain check enabled: users with missing UserType and UPN suffix in verified domains can be treated as confident cloud-only members.")
}
else {
    Write-Log("Domain check disabled: no verified domains were loaded, so only synced identity signals will mark members as confident.")
}

$classificationTotal = @($usersWithNoUserType).Count
$classificationCounter = 0

$classifiedUsers = foreach ($user in $usersWithNoUserType) {
    $classificationCounter++

    if ($classificationTotal -gt 0) {
        $classificationPercent = if ($classificationCounter -ge $classificationTotal) {
            100
        }
        else {
            [int](($classificationCounter * 100.0) / $classificationTotal)
        }

        if ($classificationPercent -lt 0) { $classificationPercent = 0 }
        if ($classificationPercent -gt 100) { $classificationPercent = 100 }

        Write-Progress -Activity "Classifying users and evaluating policy impact" `
                       -Status "Processing $classificationCounter of $classificationTotal ($classificationPercent%)" `
                       -PercentComplete $classificationPercent
    }

    Write-Log -Message "Evaluating user ${classificationCounter} of ${classificationTotal}: $($user.UserPrincipalName)" -NoConsole

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

    $policyImpact = if (-not [string]::IsNullOrWhiteSpace($proposedUserType)) {
        Write-Log -Message "Classification result ${classificationCounter} of ${classificationTotal}: $($user.UserPrincipalName) => ProposedUserType='$proposedUserType' | Reason: $reason" -NoConsole
        Get-UserPolicyImpact -User $user -ProposedUserType $proposedUserType -PolicyContext $policyImpactContext
    }
    else {
        Write-Log -Message "Classification result ${classificationCounter} of ${classificationTotal}: $($user.UserPrincipalName) skipped | Reason: $reason" -NoConsole
        [pscustomobject]@{
            CoverageLevel = 'NotEvaluated'
            RiskLevel = 'None'
            ConditionalAccessCount = 0
            DynamicGroupRuleCount = 0
            GroupMembershipCount = 0
            AppRoleAssignmentCount = 0
            DirectoryRoleAssignmentCount = 0
            EntitlementAssignmentCount = 0
            TeamsCount = 0
            HasMailbox = $false
            BlockingFlags = ''
            Summary = 'No proposed userType; policy impact not evaluated.'
        }
    }

    [pscustomobject]@{
        User = $user
        ProposedUserType = $proposedUserType
        Reason = $reason
        MemberReason = if ($null -ne $memberClassification) { $memberClassification.Reason } else { 'Not evaluated for this TargetType' }
        GuestReason = if ($null -ne $guestClassification) { $guestClassification.Reason } else { 'Not evaluated for this TargetType' }
        PolicyImpact = $policyImpact
    }
}

Write-Progress -Activity "Classifying users and evaluating policy impact" -Completed
Write-Log("Completed classification and policy impact evaluation for $classificationCounter user(s) with missing UserType.")

$updateCandidates = @($classifiedUsers | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ProposedUserType) })
$memberCandidates = @($updateCandidates | Where-Object { $_.ProposedUserType -eq 'Member' })
$guestCandidates = @($updateCandidates | Where-Object { $_.ProposedUserType -eq 'Guest' })
$skippedCandidates = @($classifiedUsers | Where-Object { [string]::IsNullOrWhiteSpace($_.ProposedUserType) })

Write-Log("Confident member candidates to update: $($memberCandidates.Count)")
Write-Log("Confident guest candidates to update: $($guestCandidates.Count)")
Write-Log("Skipped candidates (insufficient confidence or guest indicators): $($skippedCandidates.Count)")

foreach ($skipped in $skippedCandidates) {
    Write-Log -Message "Skipped $($skipped.User.UserPrincipalName): $($skipped.Reason)" -NoConsole
}

$preUpdateExportPlans = @(
    [pscustomobject]@{
        Candidates = $skippedCandidates
        Path = $skippedExportPath
        ProposedUserType = ''
        SuccessPrefix = 'Skipped users exported to'
        EmptyMessage = 'Skipped users export not created because there are no skipped candidates.'
        Enabled = $true
    }
    [pscustomobject]@{
        Candidates = $memberCandidates
        Path = $memberPreviewExportPath
        ProposedUserType = 'Member'
        SuccessPrefix = 'Preview member candidates exported to'
        EmptyMessage = 'Preview member export not created because there are no member candidates.'
        Enabled = $isPreviewMode
    }
    [pscustomobject]@{
        Candidates = $guestCandidates
        Path = $guestPreviewExportPath
        ProposedUserType = 'Guest'
        SuccessPrefix = 'Preview guest candidates exported to'
        EmptyMessage = 'Preview guest export not created because there are no guest candidates.'
        Enabled = $isPreviewMode
    }
)

foreach ($exportPlan in @($preUpdateExportPlans | Where-Object { $_.Enabled })) {
    Export-PolicyImpactCsvIfAny -Candidates $exportPlan.Candidates `
                                -Path $exportPlan.Path `
                                -ProposedUserType $exportPlan.ProposedUserType `
                                -SuccessPrefix $exportPlan.SuccessPrefix `
                                -EmptyMessage $exportPlan.EmptyMessage `
                                -PreflightRunId $preflightRunId `
                                -PreflightSummary $preflightSummary
}

if ($isPreviewMode) {
    Write-Host "Previewing users where UserType is missing (WhatIf - no changes will be written)..." -ForegroundColor Yellow
} else {
    Write-Host "Updating users where UserType is missing..." -ForegroundColor Cyan
}

# Progress tracking
$total = @($updateCandidates).Count
$counter = 0
$successfulUpdates = @()
$failedUpdates = @()

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

    $progressActivity = if ($isPreviewMode) { "Previewing UserType updates ($TargetType) - WhatIf" } else { "Updating UserType ($TargetType)" }
    Write-Progress -Activity $progressActivity `
                    -Status "Processing $counter of $total ($percent%)" `
                    -PercentComplete $percent

    $detailNameLogSegment = ''
    if ($IncludePolicyImpactNamesInLog) {
        $detailNameLogSegment = " | CAPolicies=$($candidate.PolicyImpact.ConditionalAccessPolicyNames) | DynamicGroups=$($candidate.PolicyImpact.DynamicGroupNames) | GroupMemberships=$($candidate.PolicyImpact.GroupMembershipNames) | AppAssignments=$($candidate.PolicyImpact.AppRoleAssignmentNames) | DirectoryRoles=$($candidate.PolicyImpact.DirectoryRoleNames) | Entitlements=$($candidate.PolicyImpact.EntitlementPackageNames)"
    }

    Write-Log -Message "Processing update candidate ${counter} of ${total}: $($user.UserPrincipalName) | TargetType=$($candidate.ProposedUserType) | Reason: $($candidate.Reason) | PolicyRisk=$($candidate.PolicyImpact.RiskLevel) | PolicySummary=$($candidate.PolicyImpact.Summary)$detailNameLogSegment" -NoConsole

    if ($isPreviewMode) {
        Write-Log -Message "WHATIF: Would update $($user.UserPrincipalName) (UserId: $($user.Id)) to UserType='$($candidate.ProposedUserType)'" -NoConsole
        Start-Sleep -Milliseconds 20
        continue
    }

    if (-not $PSCmdlet.ShouldProcess($user.UserPrincipalName, "Set UserType to '$($candidate.ProposedUserType)'")) {
        Write-Log -Message "WARNING: Update cancelled by ShouldProcess for $($user.UserPrincipalName) (UserId: $($user.Id)); requested UserType='$($candidate.ProposedUserType)'" -NoConsole
        Start-Sleep -Milliseconds 20
        continue
    }

    try {
        Update-MgUser -UserId $user.Id -UserType $candidate.ProposedUserType -ErrorAction Stop
        Write-Log -Message "Updated $($user.UserPrincipalName) (UserId: $($user.Id)) to UserType='$($candidate.ProposedUserType)' successfully." -NoConsole
        $successfulUpdates += [pscustomobject]@{
            User = $user
            ProposedUserType = $candidate.ProposedUserType
            Reason = $candidate.Reason
            PolicyImpact = $candidate.PolicyImpact
        }
    }
    catch {
        $updateFailureMessage = $_.Exception.Message
        Write-Log -Message "ERROR: Failed to update $($user.UserPrincipalName) (UserId: $($user.Id)) to UserType='$($candidate.ProposedUserType)': $updateFailureMessage" -NoConsole
        $failedUpdates += [pscustomobject]@{
            User = $user
            ProposedUserType = $candidate.ProposedUserType
            Reason = "Update failed: $updateFailureMessage | Classification: $($candidate.Reason)"
            PolicyImpact = $candidate.PolicyImpact
        }
        continue
    }

    # Delay for easier visual progress tracking during manual runs.
    Start-Sleep -Milliseconds 150
}

Write-Progress -Activity $(if ($isPreviewMode) { "Previewing UserType updates ($TargetType) - WhatIf" } else { "Updating UserType ($TargetType)" }) -Completed

$postUpdateExportPlans = @(
    [pscustomobject]@{
        Candidates = $successfulUpdates
        Path = $updatedUsersExportPath
        ProposedUserType = ''
        SuccessPrefix = 'Updated users exported to'
        EmptyMessage = 'Updated users export not created because there were no successful updates.'
        Enabled = (-not $isPreviewMode)
    }
    [pscustomobject]@{
        Candidates = $failedUpdates
        Path = $failedUpdatesExportPath
        ProposedUserType = ''
        SuccessPrefix = 'Failed updates exported to'
        EmptyMessage = 'Failed updates export not created because there were no failed updates.'
        Enabled = (-not $isPreviewMode)
    }
)

foreach ($exportPlan in @($postUpdateExportPlans | Where-Object { $_.Enabled })) {
    Export-PolicyImpactCsvIfAny -Candidates $exportPlan.Candidates `
                                -Path $exportPlan.Path `
                                -ProposedUserType $exportPlan.ProposedUserType `
                                -SuccessPrefix $exportPlan.SuccessPrefix `
                                -EmptyMessage $exportPlan.EmptyMessage `
                                -PreflightRunId $preflightRunId `
                                -PreflightSummary $preflightSummary
}

