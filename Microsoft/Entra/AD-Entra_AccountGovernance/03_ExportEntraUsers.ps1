# ==============================================================================
# 03_ExportEntraUsers.ps1
# Purpose : Fetch all Entra users once, split into three audit buckets,
#           export as NDJSON (safe against newlines/special chars in values)
# Run on  : Any machine with Microsoft.Graph PowerShell module
# Output  : <RunOutputPath>\Entra_*.ndjson
# Requires: 00_Config.ps1 (shared configuration)
#
# Why NDJSON: User properties can contain newline characters and other special
# characters that corrupt CSV exports. NDJSON (one JSON object per line) is safe.
#
# Bucket logic:
#   Bucket 1 - Actively synced  : OnPremisesSyncEnabled = True
#   Bucket 2 - Previously synced: OnPremisesSyncEnabled != True AND ImmutableId set
#   Bucket 3 - Cloud only       : OnPremisesSyncEnabled != True AND ImmutableId null
# ==============================================================================

. "$PSScriptRoot\00_Config.ps1"

# --- Module imports -----------------------------------------------------------
$loggingModulePath   = Join-Path $PSScriptRoot '..\..\Common\Modules\Shared\Logging.psm1'
$graphConnModulePath = Join-Path $PSScriptRoot '..\Modules\Shared\GraphConnection.psm1'
$graphDataModulePath = Join-Path $PSScriptRoot '..\Modules\Shared\GraphData.psm1'

Import-Module $loggingModulePath   -Force -ErrorAction Stop
Import-Module $graphConnModulePath -Force -ErrorAction Stop
Import-Module $graphDataModulePath -Force -ErrorAction Stop

# --- Run output directory -----------------------------------------------------
# When called from Run-AccountGovernanceAudit.ps1, $RunOutputPath is already set
# in the caller's scope and is reused here. For standalone runs a new timestamped
# directory is created so each run's output is preserved independently.
if (-not (Get-Variable -Name RunOutputPath -ErrorAction SilentlyContinue)) {
    $RunOutputPath = Join-Path $OutputPath (Get-Date -Format 'yyyy-MM-dd_HHmmss')
    New-Item -ItemType Directory -Path $RunOutputPath -Force | Out-Null
}
Set-LogFilePath -Path (Join-Path $RunOutputPath 'AccountGovernance.log')
Write-Log "=== 03_ExportEntraUsers started (ImmutableIdMethod: $ImmutableIdMethod) ==="

# --- Connect to Microsoft Graph -----------------------------------------------
Connect-MgGraphWithRequirements `
    -GraphModuleNames @('Microsoft.Graph.Users') `
    -RequiredScopes @('User.Read.All', 'Directory.Read.All', 'AuditLog.Read.All')

# --- Property list ------------------------------------------------------------
$properties = @(
    "Id", "DisplayName", "GivenName", "Surname",
    "UserPrincipalName", "Mail", "MailNickname", "UserType",
    "OtherMails", "ProxyAddresses", "Identities",
    "AccountEnabled", "CreatedDateTime", "DeletedDateTime",
    "LastPasswordChangeDateTime", "PasswordPolicies",
    "SignInSessionsValidFromDateTime",
    "ExternalUserState", "ExternalUserStateChangeDateTime",
    "IsResourceAccount", "IsManagementRestricted",
    "Department", "JobTitle", "CompanyName", "EmployeeId", "EmployeeType",
    "UsageLocation", "AssignedLicenses", "AssignedPlans",
    "OnPremisesSyncEnabled", "OnPremisesLastSyncDateTime",
    "OnPremisesDistinguishedName", "OnPremisesDomainName",
    "OnPremisesSamAccountName", "OnPremisesImmutableId",
    "OnPremisesSecurityIdentifier", "OnPremisesProvisioningErrors",
    "OnPremisesExtensionAttributes",
    "SignInActivity"
) -join ","

# --- Flatten function ---------------------------------------------------------
# Multi-value fields are kept as JSON arrays (not semicolon-joined strings) to
# preserve structure and avoid data corruption when values contain semicolons.
function Flatten-User ($user, [string]$BucketLabel = $null) {
    $extAttribs = $user.OnPremisesExtensionAttributes

    [PSCustomObject]@{
        Bucket                              = $BucketLabel

        # Core identity
        Id                                  = $user.Id
        DisplayName                         = $user.DisplayName
        UserPrincipalName                   = $user.UserPrincipalName
        Mail                                = $user.Mail
        MailNickname                        = $user.MailNickname
        OtherMails                          = @($user.OtherMails)
        ProxyAddresses                      = @($user.ProxyAddresses)
        Identities                          = @($user.Identities | ForEach-Object {
                                                [PSCustomObject]@{
                                                    SignInType       = $_.SignInType
                                                    Issuer          = $_.Issuer
                                                    IssuerAssignedId = $_.IssuerAssignedId
                                                }
                                              })
        UserType                            = $user.UserType

        # Account state
        AccountEnabled                      = $user.AccountEnabled
        IsResourceAccount                   = $user.IsResourceAccount
        IsManagementRestricted              = $user.IsManagementRestricted
        CreatedDateTime                     = $user.CreatedDateTime
        DeletedDateTime                     = $user.DeletedDateTime
        LastPasswordChangeDateTime          = $user.LastPasswordChangeDateTime
        PasswordPolicies                    = $user.PasswordPolicies
        SignInSessionsValidFromDateTime     = $user.SignInSessionsValidFromDateTime
        LastSignInDateTime                  = $user.SignInActivity.LastSignInDateTime
        LastNonInteractiveSignInDateTime    = $user.SignInActivity.LastNonInteractiveSignInDateTime

        # External / guest
        ExternalUserState                   = $user.ExternalUserState
        ExternalUserStateChangeDateTime     = $user.ExternalUserStateChangeDateTime

        # Organisation
        Department                          = $user.Department
        JobTitle                            = $user.JobTitle
        CompanyName                         = $user.CompanyName
        EmployeeId                          = $user.EmployeeId
        EmployeeType                        = $user.EmployeeType

        # Licensing
        UsageLocation                       = $user.UsageLocation
        AssignedLicenses                    = @($user.AssignedLicenses | ForEach-Object { $_.SkuId })
        AssignedPlans                       = @($user.AssignedPlans | ForEach-Object {
                                                [PSCustomObject]@{
                                                    Service         = $_.Service
                                                    ServicePlanId   = $_.ServicePlanId
                                                    CapabilityStatus = $_.CapabilityStatus
                                                }
                                              })

        # On-premises sync
        OnPremisesSyncEnabled               = $user.OnPremisesSyncEnabled
        OnPremisesLastSyncDateTime          = $user.OnPremisesLastSyncDateTime
        OnPremisesDistinguishedName         = $user.OnPremisesDistinguishedName
        OnPremisesDomainName                = $user.OnPremisesDomainName
        OnPremisesSamAccountName            = $user.OnPremisesSamAccountName
        OnPremisesImmutableId               = $user.OnPremisesImmutableId
        OnPremisesSecurityIdentifier        = $user.OnPremisesSecurityIdentifier
        OnPremisesProvisioningErrors        = @($user.OnPremisesProvisioningErrors | ForEach-Object {
                                                [PSCustomObject]@{
                                                    Category              = $_.Category
                                                    OccurredDateTime      = $_.OccurredDateTime
                                                    PropertyCausingError  = $_.PropertyCausingError
                                                    Value                 = $_.Value
                                                }
                                              })

        # Extension attributes (flattened from nested object)
        ExtensionAttribute1                 = $extAttribs.ExtensionAttribute1
        ExtensionAttribute2                 = $extAttribs.ExtensionAttribute2
        ExtensionAttribute3                 = $extAttribs.ExtensionAttribute3
        ExtensionAttribute4                 = $extAttribs.ExtensionAttribute4
        ExtensionAttribute5                 = $extAttribs.ExtensionAttribute5
        ExtensionAttribute6                 = $extAttribs.ExtensionAttribute6
        ExtensionAttribute7                 = $extAttribs.ExtensionAttribute7
        ExtensionAttribute8                 = $extAttribs.ExtensionAttribute8
        ExtensionAttribute9                 = $extAttribs.ExtensionAttribute9
        ExtensionAttribute10                = $extAttribs.ExtensionAttribute10
        ExtensionAttribute11                = $extAttribs.ExtensionAttribute11
        ExtensionAttribute12                = $extAttribs.ExtensionAttribute12
        ExtensionAttribute13                = $extAttribs.ExtensionAttribute13
        ExtensionAttribute14                = $extAttribs.ExtensionAttribute14
        ExtensionAttribute15                = $extAttribs.ExtensionAttribute15
    }
}

# --- Single fetch (run once, filter in memory) --------------------------------
# In large tenants this fetch can take 20-35 minutes - do not run multiple times
Write-Log "Fetching all users from Entra (may take 20+ minutes in large tenants)..."
$startTime = Get-Date

$allUsers = Invoke-GraphOperationWithRetry -OperationName 'Get-MgUser full tenant listing' -Operation {
    Get-MgUser -All -Property $properties -ErrorAction Stop
}

$elapsed = (Get-Date) - $startTime
Write-Log "Fetch complete: $($allUsers.Count) total users in $([int]$elapsed.TotalMinutes) minutes"

# --- Bucket 1: Actively synced ------------------------------------------------
Write-Log "Processing Bucket 1 - Actively synced..."
$synced = $allUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true }
Write-Log "  Count: $($synced.Count)"
$synced | ForEach-Object { Flatten-User $_ "ActivelySynced" | ConvertTo-Json -Compress -Depth 5 } |
    Out-File (Join-Path $RunOutputPath 'Entra_SyncedUsers.ndjson') -Encoding UTF8
Write-Log "  Written -> Entra_SyncedUsers.ndjson"

# --- Bucket 2: Previously synced ----------------------------------------------
Write-Log "Processing Bucket 2 - Previously synced..."
$prevSynced = $allUsers | Where-Object {
    $_.OnPremisesSyncEnabled -ne $true -and $_.OnPremisesImmutableId -ne $null
}
Write-Log "  Count: $($prevSynced.Count)"
$prevSynced | ForEach-Object { Flatten-User $_ "PreviouslySynced" | ConvertTo-Json -Compress -Depth 5 } |
    Out-File (Join-Path $RunOutputPath 'Entra_PreviouslySynced.ndjson') -Encoding UTF8
Write-Log "  Written -> Entra_PreviouslySynced.ndjson"

# --- Bucket 3: Cloud only -----------------------------------------------------
Write-Log "Processing Bucket 3 - Cloud only..."
$cloudOnly = $allUsers | Where-Object {
    $_.OnPremisesSyncEnabled -ne $true -and $_.OnPremisesImmutableId -eq $null
}
Write-Log "  Count: $($cloudOnly.Count)"
$cloudOnly | ForEach-Object { Flatten-User $_ "CloudOnly" | ConvertTo-Json -Compress -Depth 5 } |
    Out-File (Join-Path $RunOutputPath 'Entra_CloudOnly.ndjson') -Encoding UTF8
Write-Log "  Written -> Entra_CloudOnly.ndjson"

# --- All users (combined) -----------------------------------------------------
# Concatenate the three bucket files — no re-processing, Bucket field identifies origin
Write-Log "Writing combined export..."
Get-Content (Join-Path $RunOutputPath 'Entra_SyncedUsers.ndjson'),
            (Join-Path $RunOutputPath 'Entra_PreviouslySynced.ndjson'),
            (Join-Path $RunOutputPath 'Entra_CloudOnly.ndjson') |
    Out-File (Join-Path $RunOutputPath 'Entra_AllUsers.ndjson') -Encoding UTF8
Write-Log "  Written -> Entra_AllUsers.ndjson"

# --- Summary ------------------------------------------------------------------
$check = $synced.Count + $prevSynced.Count + $cloudOnly.Count
Write-Log "=== 03_ExportEntraUsers complete ==="
Write-Log "  Total users in Entra  : $($allUsers.Count)"
Write-Log "  Bucket 1 - Synced     : $($synced.Count)"
Write-Log "  Bucket 2 - Prev synced: $($prevSynced.Count)"
Write-Log "  Bucket 3 - Cloud only : $($cloudOnly.Count)"
Write-Log "  Bucket total          : $check (should equal total above)"
Write-Log "  Output directory      : $RunOutputPath"
