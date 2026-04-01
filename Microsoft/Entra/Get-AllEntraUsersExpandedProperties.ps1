<#
.SYNOPSIS
Exports all Entra ID users with expanded manager information to a flat CSV file.

.DESCRIPTION
Retrieves all users from Microsoft Graph with every selectable property and the manager
navigation property expanded. Flattens complex and multi-valued properties to
semicolon-delimited strings, expands nested objects (employeeOrgData,
onPremisesExtensionAttributes) into individual columns, and writes one CSV row per user.

Uses shared modules for Graph authentication, retry logic, and timestamped logging.
Outputs a dated CSV under Reports\GetAllEntraUsers\EntraUsersExport\ and a log file
under Logs\.

.NOTES
Requires Microsoft Graph PowerShell connectivity with the following delegated scopes:
  User.Read.All
  Directory.Read.All
#>

# --------------------------------------------------
# Import shared modules
# --------------------------------------------------
$commonSharedModuleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'Common\Modules\Shared'
$entraSharedModuleRoot  = Join-Path $PSScriptRoot 'Modules\Shared'

Import-Module (Join-Path $commonSharedModuleRoot 'Logging.psm1') -Force
Import-Module (Join-Path $entraSharedModuleRoot 'GraphConnection.psm1') -Force
Import-Module (Join-Path $entraSharedModuleRoot 'GraphData.psm1') -Force

# --------------------------------------------------
# Configure logging
# --------------------------------------------------
$logPath = Join-Path $PSScriptRoot (Join-Path 'Logs' 'EntraUsersExport.log')
Set-LogFilePath -Path $logPath

# --------------------------------------------------
# Connect to Microsoft Graph
# --------------------------------------------------
Connect-MgGraphWithRequirements -RequiredScopes @('User.Read.All', 'Directory.Read.All')

# --------------------------------------------------
# Define selectable user properties
# --------------------------------------------------
$selectProperties = @(
    "id", "displayName", "givenName", "surname", "userPrincipalName",
    "mail", "mailNickname", "userType", "accountEnabled",
    "assignedLicenses", "assignedPlans",
    "businessPhones", "mobilePhone", "faxNumber",
    "city", "country", "state", "streetAddress", "postalCode", "officeLocation",
    "companyName", "department", "division", "jobTitle", "employeeId",
    "employeeType", "employeeHireDate", "employeeOrgData",
    "usageLocation", "preferredLanguage", "preferredDataLocation",
    "createdDateTime", "deletedDateTime", "lastPasswordChangeDateTime",
    "passwordPolicies",
    "onPremisesSyncEnabled", "onPremisesLastSyncDateTime",
    "onPremisesDistinguishedName", "onPremisesDomainName",
    "onPremisesSamAccountName", "onPremisesUserPrincipalName",
    "onPremisesImmutableId", "onPremisesSecurityIdentifier",
    "onPremisesExtensionAttributes",
    "externalUserState", "externalUserStateChangeDateTime",
    "identities", "otherMails", "proxyAddresses",
    "showInAddressList", "signInSessionsValidFromDateTime",
    "ageGroup", "consentProvidedForMinor", "legalAgeGroupClassification",
    "imAddresses", "isResourceAccount", "isManagementRestricted"
)

# --------------------------------------------------
# Fetch all users with manager expansion
# --------------------------------------------------
Write-Log('Fetching users from Microsoft Graph with expanded manager...')

$users = Invoke-GraphOperationWithRetry -OperationName 'Get-MgUser all users with manager expand' -Operation {
    Get-MgUser -All -Property $selectProperties -ExpandProperty "manager" -ConsistencyLevel eventual -ErrorAction Stop
}

Write-Log("Retrieved $($users.Count) users.")

# --------------------------------------------------
# Flatten and shape export data
# --------------------------------------------------
Write-Log("Processing $($users.Count) users for export...")

$exportData = foreach ($user in $users) {

    # Flatten onPremisesExtensionAttributes (extensionAttribute1-15)
    $extAttribs = $user.OnPremisesExtensionAttributes

    # Flatten assignedLicenses to a delimited string
    $licenses = ($user.AssignedLicenses | ForEach-Object { $_.SkuId }) -join ";"

    # Flatten assignedPlans to a delimited string
    $assignedPlans = ($user.AssignedPlans | ForEach-Object { "$($_.Service):$($_.CapabilityStatus)" }) -join ";"

    # Flatten identities
    $identities = ($user.Identities | ForEach-Object { "$($_.SignInType):$($_.IssuerAssignedId)" }) -join ";"

    # Flatten proxyAddresses
    $proxyAddresses = $user.ProxyAddresses -join ";"

    # Flatten otherMails
    $otherMails = $user.OtherMails -join ";"

    # Flatten businessPhones
    $businessPhones = $user.BusinessPhones -join ";"

    # Manager display name
    $managerName = if ($user.Manager) { $user.Manager.AdditionalProperties["displayName"] } else { $null }
    $managerId   = if ($user.Manager) { $user.Manager.Id } else { $null }

    # EmployeeOrgData
    $employeeOrgData = $user.EmployeeOrgData
    $employeeOrgDataCostCenter = if ($employeeOrgData) { $employeeOrgData.CostCenter } else { $null }
    $employeeOrgDataDivision   = if ($employeeOrgData) { $employeeOrgData.Division } else { $null }

    [PSCustomObject]@{
        # Core identity
        Id                              = $user.Id
        DisplayName                     = $user.DisplayName
        GivenName                       = $user.GivenName
        Surname                         = $user.Surname
        UserPrincipalName               = $user.UserPrincipalName
        Mail                            = $user.Mail
        MailNickname                    = $user.MailNickname
        UserType                        = $user.UserType
        AccountEnabled                  = $user.AccountEnabled

        # Contact
        BusinessPhones                  = $businessPhones
        MobilePhone                     = $user.MobilePhone
        FaxNumber                       = $user.FaxNumber
        OtherMails                      = $otherMails
        ImAddresses                     = ($user.ImAddresses -join ";")
        ProxyAddresses                  = $proxyAddresses

        # Location / address
        City                            = $user.City
        Country                         = $user.Country
        State                           = $user.State
        StreetAddress                   = $user.StreetAddress
        PostalCode                      = $user.PostalCode
        OfficeLocation                  = $user.OfficeLocation
        UsageLocation                   = $user.UsageLocation
        PreferredDataLocation           = $user.PreferredDataLocation

        # Organisation
        CompanyName                     = $user.CompanyName
        Department                      = $user.Department
        Division                        = $user.Division
        JobTitle                        = $user.JobTitle
        EmployeeId                      = $user.EmployeeId
        EmployeeType                    = $user.EmployeeType
        EmployeeHireDate                = $user.EmployeeHireDate
        EmployeeOrgDataCostCenter       = $employeeOrgDataCostCenter
        EmployeeOrgDataDivision         = $employeeOrgDataDivision
        ManagerDisplayName              = $managerName
        ManagerId                       = $managerId

        # Dates
        CreatedDateTime                 = $user.CreatedDateTime
        LastPasswordChangeDateTime      = $user.LastPasswordChangeDateTime
        SignInSessionsValidFromDateTime = $user.SignInSessionsValidFromDateTime
        DeletedDateTime                 = $user.DeletedDateTime

        # Auth / sync
        OnPremisesSyncEnabled           = $user.OnPremisesSyncEnabled
        OnPremisesLastSyncDateTime      = $user.OnPremisesLastSyncDateTime
        OnPremisesDistinguishedName     = $user.OnPremisesDistinguishedName
        OnPremisesDomainName            = $user.OnPremisesDomainName
        OnPremisesSamAccountName        = $user.OnPremisesSamAccountName
        OnPremisesUserPrincipalName     = $user.OnPremisesUserPrincipalName
        OnPremisesImmutableId           = $user.OnPremisesImmutableId
        OnPremisesSecurityIdentifier    = $user.OnPremisesSecurityIdentifier
        PasswordPolicies                = $user.PasswordPolicies
        Identities                      = $identities

        # Licensing
        AssignedLicenses                = $licenses
        AssignedPlans                   = $assignedPlans

        # Age / consent
        AgeGroup                        = $user.AgeGroup
        ConsentProvidedForMinor         = $user.ConsentProvidedForMinor
        LegalAgeGroupClassification     = $user.LegalAgeGroupClassification

        # Misc
        PreferredLanguage               = $user.PreferredLanguage
        ShowInAddressList               = $user.ShowInAddressList
        ExternalUserState               = $user.ExternalUserState
        ExternalUserStateChangeDateTime = $user.ExternalUserStateChangeDateTime
        IsResourceAccount               = $user.IsResourceAccount
        IsManagementRestricted          = $user.IsManagementRestricted

        # Extension attributes (onPremisesExtensionAttributes) - expanded to own columns
        ExtensionAttribute1             = $extAttribs.ExtensionAttribute1
        ExtensionAttribute2             = $extAttribs.ExtensionAttribute2
        ExtensionAttribute3             = $extAttribs.ExtensionAttribute3
        ExtensionAttribute4             = $extAttribs.ExtensionAttribute4
        ExtensionAttribute5             = $extAttribs.ExtensionAttribute5
        ExtensionAttribute6             = $extAttribs.ExtensionAttribute6
        ExtensionAttribute7             = $extAttribs.ExtensionAttribute7
        ExtensionAttribute8             = $extAttribs.ExtensionAttribute8
        ExtensionAttribute9             = $extAttribs.ExtensionAttribute9
        ExtensionAttribute10            = $extAttribs.ExtensionAttribute10
        ExtensionAttribute11            = $extAttribs.ExtensionAttribute11
        ExtensionAttribute12            = $extAttribs.ExtensionAttribute12
        ExtensionAttribute13            = $extAttribs.ExtensionAttribute13
        ExtensionAttribute14            = $extAttribs.ExtensionAttribute14
        ExtensionAttribute15            = $extAttribs.ExtensionAttribute15
    }
}

# --------------------------------------------------
# Export to CSV
# --------------------------------------------------
$reportsDir = Join-Path $PSScriptRoot 'Reports\GetAllEntraUsers\EntraUsersExport'
if (-not (Test-Path $reportsDir)) {
    New-Item -ItemType Directory -Path $reportsDir -Force | Out-Null
}

$outputPath = Join-Path $reportsDir "EntraUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$exportData | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

Write-Log("Export complete: $outputPath ($($exportData.Count) users)")

Disconnect-MgGraph
