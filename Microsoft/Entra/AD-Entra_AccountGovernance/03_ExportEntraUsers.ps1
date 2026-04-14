# ==============================================================================
# 03_ExportEntraUsers.ps1
# Purpose : Fetch all Entra users once, split into three audit buckets,
#           export as NDJSON (safe against newlines/special chars in values)
# Run on  : Any machine with Microsoft.Graph PowerShell module
# Output  : <OutputPath>\Entra_*.ndjson
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

# --- Module check -------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
    Write-Error @"
The Microsoft.Graph PowerShell module is not installed. Install it and re-run.

  Install-Module Microsoft.Graph -Scope CurrentUser

If already installed but not found, ensure the install scope matches the session:
  Install-Module Microsoft.Graph -Scope AllUsers
"@
    exit 1
}

Import-Module Microsoft.Graph.Users -ErrorAction Stop

Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All"

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
    "OnPremisesExtensionAttributes"
) -join ","

# --- Flatten function ---------------------------------------------------------
# Handles nested/array objects:
#   AssignedLicenses, AssignedPlans, OnPremisesProvisioningErrors,
#   OnPremisesExtensionAttributes, OtherMails, ProxyAddresses, Identities
function Flatten-User ($user, [string]$BucketLabel = $null) {
    $extAttribs     = $user.OnPremisesExtensionAttributes
    $licenses       = ($user.AssignedLicenses | ForEach-Object { $_.SkuId }) -join ";"
    $provErrors     = ($user.OnPremisesProvisioningErrors | ForEach-Object {
        "$($_.Category):$($_.OccurredDateTime):$($_.PropertyCausingError):$($_.Value)"
    }) -join ";"
    $otherMails     = ($user.OtherMails) -join ";"
    $proxyAddresses = ($user.ProxyAddresses) -join ";"
    $identities     = ($user.Identities | ForEach-Object {
        "$($_.SignInType):$($_.Issuer):$($_.IssuerAssignedId)"
    }) -join ";"
    $assignedPlans  = ($user.AssignedPlans | ForEach-Object {
        "$($_.Service):$($_.ServicePlanId):$($_.CapabilityStatus)"
    }) -join ";"

    [PSCustomObject]@{
        Bucket                              = $BucketLabel

        # Core identity
        Id                                  = $user.Id
        DisplayName                         = $user.DisplayName
        #GivenName                           = $user.GivenName
        #Surname                             = $user.Surname
        UserPrincipalName                   = $user.UserPrincipalName
        Mail                                = $user.Mail
        MailNickname                        = $user.MailNickname
        OtherMails                          = $otherMails
        ProxyAddresses                      = $proxyAddresses
        Identities                          = $identities
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
        AssignedLicenses                    = $licenses
        AssignedPlans                       = $assignedPlans

        # On-premises sync
        OnPremisesSyncEnabled               = $user.OnPremisesSyncEnabled
        OnPremisesLastSyncDateTime          = $user.OnPremisesLastSyncDateTime
        OnPremisesDistinguishedName         = $user.OnPremisesDistinguishedName
        OnPremisesDomainName                = $user.OnPremisesDomainName
        OnPremisesSamAccountName            = $user.OnPremisesSamAccountName
        OnPremisesImmutableId               = $user.OnPremisesImmutableId
        OnPremisesSecurityIdentifier        = $user.OnPremisesSecurityIdentifier
        OnPremisesProvisioningErrors        = $provErrors

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
Write-Host "Fetching all users from Entra (may take 20+ minutes in large tenants)..." -ForegroundColor Yellow
$startTime = Get-Date

$allUsers = Get-MgUser -All -Property $properties

$elapsed = (Get-Date) - $startTime
Write-Host "Fetch complete: $($allUsers.Count) total users in $([int]$elapsed.TotalMinutes) minutes" -ForegroundColor Green

# --- Bucket 1: Actively synced ------------------------------------------------
Write-Host "`nProcessing Bucket 1 - Actively synced..." -ForegroundColor Cyan
$synced = $allUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true }
Write-Host "  Count: $($synced.Count)"
$synced | ForEach-Object { Flatten-User $_ "ActivelySynced" | ConvertTo-Json -Compress } |
    Out-File "${OutputPath}Entra_SyncedUsers.ndjson" -Encoding UTF8
Write-Host "  Written -> ${OutputPath}Entra_SyncedUsers.ndjson" -ForegroundColor Green

# --- Bucket 2: Previously synced ----------------------------------------------
Write-Host "`nProcessing Bucket 2 - Previously synced..." -ForegroundColor Cyan
$prevSynced = $allUsers | Where-Object {
    $_.OnPremisesSyncEnabled -ne $true -and $_.OnPremisesImmutableId -ne $null
}
Write-Host "  Count: $($prevSynced.Count)"
$prevSynced | ForEach-Object { Flatten-User $_ "PreviouslySynced" | ConvertTo-Json -Compress } |
    Out-File "${OutputPath}Entra_PreviouslySynced.ndjson" -Encoding UTF8
Write-Host "  Written -> ${OutputPath}Entra_PreviouslySynced.ndjson" -ForegroundColor Green

# --- Bucket 3: Cloud only -----------------------------------------------------
Write-Host "`nProcessing Bucket 3 - Cloud only..." -ForegroundColor Cyan
$cloudOnly = $allUsers | Where-Object {
    $_.OnPremisesSyncEnabled -ne $true -and $_.OnPremisesImmutableId -eq $null
}
Write-Host "  Count: $($cloudOnly.Count)"
$cloudOnly | ForEach-Object { Flatten-User $_ "CloudOnly" | ConvertTo-Json -Compress } |
    Out-File "${OutputPath}Entra_CloudOnly.ndjson" -Encoding UTF8
Write-Host "  Written -> ${OutputPath}Entra_CloudOnly.ndjson" -ForegroundColor Green

# --- All users (combined) -----------------------------------------------------
# Concatenate the three bucket files — no re-processing, Bucket field identifies origin
Write-Host "`nWriting combined export..." -ForegroundColor Cyan
Get-Content "${OutputPath}Entra_SyncedUsers.ndjson",
            "${OutputPath}Entra_PreviouslySynced.ndjson",
            "${OutputPath}Entra_CloudOnly.ndjson" |
    Out-File "${OutputPath}Entra_AllUsers.ndjson" -Encoding UTF8
Write-Host "  Written -> ${OutputPath}Entra_AllUsers.ndjson" -ForegroundColor Green

# --- Summary ------------------------------------------------------------------
Write-Host "`n=== SUMMARY ===" -ForegroundColor Yellow
Write-Host "Total users in Entra  : $($allUsers.Count)"
Write-Host "Bucket 1 - Synced     : $($synced.Count)"
Write-Host "Bucket 2 - Prev synced: $($prevSynced.Count)"
Write-Host "Bucket 3 - Cloud only : $($cloudOnly.Count)"
$check = $synced.Count + $prevSynced.Count + $cloudOnly.Count
Write-Host "Bucket total          : $check (should equal total above)"
Write-Host "Combined file         : ${OutputPath}Entra_AllUsers.ndjson (Bucket field identifies origin)"
