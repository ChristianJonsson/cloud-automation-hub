# ==============================================================================
# 06_ExportADUsers.ps1
# Purpose : Export all AD user accounts for cross-reference against Entra buckets
# Run on  : Domain-joined machine with RSAT AD module
# Output  : <RunOutputPath>\AD_AllUsers_<ForestName>_<RunFileSuffix>.ndjson
# Requires: 00_Config.ps1 (shared configuration)
#
# Approach:
#   1. Export all AD users with key properties
#   2. Calculate ImmutableId using the method configured in $ImmutableIdMethod:
#        ObjectGUID            - Base64-encodes the AD ObjectGUID (default)
#        mS-DS-ConsistencyGuid - Base64-encodes the mS-DS-ConsistencyGuid attribute
#        Custom                - Reads the attribute named in $CustomImmutableIdAttribute
#   3. ImmutableId is used in 07_CrossReference.ps1 to match against Entra's
#      OnPremisesImmutableId
# ==============================================================================

param(
    [string]$ForestName = "default",
    [string]$Server     = $null      # Optional: target a specific DC for this forest
)

. "$PSScriptRoot\00_Config.ps1"

# --- Module imports -----------------------------------------------------------
$loggingModulePath = Join-Path $PSScriptRoot '..\..\Common\Modules\Shared\Logging.psm1'
Import-Module $loggingModulePath -Force -ErrorAction Stop

# --- Run output directory -----------------------------------------------------
if (-not (Get-Variable -Name RunOutputPath -ErrorAction SilentlyContinue)) {
    $standaloneDate = Get-Date
    $RunOutputPath = Join-Path $OutputPath $standaloneDate.ToString('yyyy-MM-dd_HHmmss')
    $RunFileSuffix = Get-RunFileSuffix -RunDate $standaloneDate
    New-Item -ItemType Directory -Path $RunOutputPath -Force | Out-Null
}
if (-not (Get-Variable -Name RunFileSuffix -ErrorAction SilentlyContinue) -or [string]::IsNullOrEmpty($RunFileSuffix)) {
    $RunFileSuffix = ConvertTo-RunFileSuffix -DirectoryName (Split-Path $RunOutputPath -Leaf)
    if ([string]::IsNullOrEmpty($RunFileSuffix)) { $RunFileSuffix = Get-RunFileSuffix }
}
Set-LogFilePath -Path (Join-Path $RunOutputPath 'AccountGovernance.log')
Write-Log "=== 06_ExportADUsers started (ForestName: $ForestName, ImmutableIdMethod: $ImmutableIdMethod) ==="

# --- Module check -------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Log "ERROR: ActiveDirectory PowerShell module is not installed."
    Write-Error @"
The ActiveDirectory PowerShell module is not installed. Install it and re-run.

  Windows 10/11:
    Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

  Windows Server:
    Install-WindowsFeature RSAT-AD-PowerShell
"@
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

# --- Property list ------------------------------------------------------------
$adProperties = @(
    # Core identity
    "SamAccountName",
    "UserPrincipalName",
    "DisplayName",
    "GivenName",
    "Surname",
    "Description",
    "DistinguishedName",    # ObjectGUID is a default property — do not list explicitly or some AD module
                            # versions return it as ADPropertyValueCollection instead of System.Guid

    # Account state
    "Enabled",
    "AccountExpirationDate",
    "Created",
    "Modified",
    "LastLogonDate",
    "LogonCount",
    "BadLogonCount",
    "LastBadPasswordAttempt",

    # Password / lockout policy
    "PasswordLastSet",
    "PasswordNeverExpires",
    "PasswordExpired",
    "PasswordNotRequired",
    "LockedOut",

    # Security / delegation flags
    "adminCount",
    "ServicePrincipalNames",
    "DoesNotRequirePreAuth",
    "TrustedForDelegation",
    "TrustedToAuthForDelegation",

    # Organisation
    "Department",
    "Title",
    "Company",
    "Manager",

    # Contact
    "Mail",
    "MobilePhone",
    "proxyAddresses",

    # Extension attributes (AD standard, 1-15)
    "extensionAttribute1",
    "extensionAttribute2",
    "extensionAttribute3",
    "extensionAttribute4",
    "extensionAttribute5",
    "extensionAttribute6",
    "extensionAttribute7",
    "extensionAttribute8",
    "extensionAttribute9",
    "extensionAttribute10",
    "extensionAttribute11",
    "extensionAttribute12",
    "extensionAttribute13",
    "extensionAttribute14",
    "extensionAttribute15",

    # Cloud extension attributes (msDS-cloudExtensionAttribute1-20)
    # Populated by Entra Connect or custom provisioning
    "msDS-cloudExtensionAttribute1",
    "msDS-cloudExtensionAttribute2",
    "msDS-cloudExtensionAttribute3",
    "msDS-cloudExtensionAttribute4",
    "msDS-cloudExtensionAttribute5",
    "msDS-cloudExtensionAttribute6",
    "msDS-cloudExtensionAttribute7",
    "msDS-cloudExtensionAttribute8",
    "msDS-cloudExtensionAttribute9",
    "msDS-cloudExtensionAttribute10",
    "msDS-cloudExtensionAttribute11",
    "msDS-cloudExtensionAttribute12",
    "msDS-cloudExtensionAttribute13",
    "msDS-cloudExtensionAttribute14",
    "msDS-cloudExtensionAttribute15",
    "msDS-cloudExtensionAttribute16",
    "msDS-cloudExtensionAttribute17",
    "msDS-cloudExtensionAttribute18",
    "msDS-cloudExtensionAttribute19",
    "msDS-cloudExtensionAttribute20"
)

# Add source anchor attribute to the property list if it isn't already included
if ($ImmutableIdMethod -eq "mS-DS-ConsistencyGuid") {
    $adProperties += "mS-DS-ConsistencyGuid"
} elseif ($ImmutableIdMethod -eq "Custom" -and $CustomImmutableIdAttribute) {
    $adProperties += $CustomImmutableIdAttribute
}

# Add any org-specific additional properties from config
if ($AdditionalAdProperties.Count -gt 0) {
    $adProperties += $AdditionalAdProperties
}

Write-Log "Fetching all AD users (ImmutableIdMethod: $ImmutableIdMethod)..."

$getAdUserParams = @{
    Filter     = '*'
    Properties = $adProperties
    ErrorAction = 'Stop'
}
if ($Server) { $getAdUserParams['Server'] = $Server }

try {
    $adUsers = Get-ADUser @getAdUserParams
} catch {
    Write-Log "ERROR: Failed to query Active Directory: $_"
    Write-Error "Failed to query Active Directory: $_`n`nEnsure this machine is domain-joined and can reach a domain controller (AD Web Services must be running)."
    exit 1
}

Write-Log "Fetched $($adUsers.Count) AD users. Processing..."

$adOutputFileName = "AD_AllUsers_${ForestName}_${RunFileSuffix}.ndjson"
$outputFile = Join-Path $RunOutputPath $adOutputFileName

$adUsers | ForEach-Object {
    # Resolve ObjectGUID once — depending on AD module version, ObjectGUID is
    # returned either as System.Guid directly or wrapped in an
    # ADPropertyValueCollection. Unwrap via @()[0] then reconstruct from string
    # to handle both cases safely.
    $guid = $null
    try { $guid = [System.Guid]::new([string](@($_.ObjectGUID)[0])) } catch { }

    # Calculate ImmutableId based on the configured source anchor method
    $immutableId = switch ($ImmutableIdMethod) {
        "ObjectGUID" {
            if ($null -ne $guid) {
                [System.Convert]::ToBase64String($guid.ToByteArray())
            } else { $null }
        }
        "mS-DS-ConsistencyGuid" {
            $cg = $_."mS-DS-ConsistencyGuid"
            if ($cg) { [System.Convert]::ToBase64String($cg) } else { $null }
        }
        "Custom" {
            if ($CustomImmutableIdAttribute) { $_.$CustomImmutableIdAttribute } else { $null }
        }
        default {
            if ($null -ne $guid) {
                [System.Convert]::ToBase64String($guid.ToByteArray())
            } else { $null }
        }
    }

    # Build record as ordered hashtable to allow dynamic additional properties
    $record = [ordered]@{
        # Core identity
        SamAccountName                  = $_.SamAccountName
        UserPrincipalName               = $_.UserPrincipalName
        DisplayName                     = $_.DisplayName
        GivenName                       = $_.GivenName
        Surname                         = $_.Surname
        Description                     = $_.Description
        ObjectGUID                      = if ($null -ne $guid) { $guid.ToString() } else { $null }
        ImmutableId                     = $immutableId   # Matches Entra OnPremisesImmutableId
        DistinguishedName               = $_.DistinguishedName

        # Account state
        Enabled                         = $_.Enabled
        AccountExpirationDate           = $_.AccountExpirationDate
        Created                         = $_.Created
        Modified                        = $_.Modified
        LastLogonDate                   = $_.LastLogonDate
        LogonCount                      = $_.LogonCount
        BadLogonCount                   = $_.BadLogonCount
        LastBadPasswordAttempt          = $_.LastBadPasswordAttempt

        # Password / lockout policy
        PasswordLastSet                 = $_.PasswordLastSet
        PasswordNeverExpires            = $_.PasswordNeverExpires
        PasswordExpired                 = $_.PasswordExpired
        PasswordNotRequired             = $_.PasswordNotRequired
        LockedOut                       = $_.LockedOut

        # Security / delegation flags
        adminCount                      = $_.adminCount
        ServicePrincipalNames           = @($_.ServicePrincipalNames)
        DoesNotRequirePreAuth           = $_.DoesNotRequirePreAuth
        TrustedForDelegation            = $_.TrustedForDelegation
        TrustedToAuthForDelegation      = $_.TrustedToAuthForDelegation

        # Organisation
        Department                      = $_.Department
        Title                           = $_.Title
        Company                         = $_.Company
        Manager                         = $_.Manager

        # Contact
        Mail                            = $_.Mail
        MobilePhone                     = $_.MobilePhone
        ProxyAddresses                  = @($_.proxyAddresses)

        # Extension attributes (AD standard, 1-15)
        ExtensionAttribute1             = $_.extensionAttribute1
        ExtensionAttribute2             = $_.extensionAttribute2
        ExtensionAttribute3             = $_.extensionAttribute3
        ExtensionAttribute4             = $_.extensionAttribute4
        ExtensionAttribute5             = $_.extensionAttribute5
        ExtensionAttribute6             = $_.extensionAttribute6
        ExtensionAttribute7             = $_.extensionAttribute7
        ExtensionAttribute8             = $_.extensionAttribute8
        ExtensionAttribute9             = $_.extensionAttribute9
        ExtensionAttribute10            = $_.extensionAttribute10
        ExtensionAttribute11            = $_.extensionAttribute11
        ExtensionAttribute12            = $_.extensionAttribute12
        ExtensionAttribute13            = $_.extensionAttribute13
        ExtensionAttribute14            = $_.extensionAttribute14
        ExtensionAttribute15            = $_.extensionAttribute15

        # Cloud extension attributes (msDS-cloudExtensionAttribute1-20)
        CloudExtensionAttribute1        = $_."msDS-cloudExtensionAttribute1"
        CloudExtensionAttribute2        = $_."msDS-cloudExtensionAttribute2"
        CloudExtensionAttribute3        = $_."msDS-cloudExtensionAttribute3"
        CloudExtensionAttribute4        = $_."msDS-cloudExtensionAttribute4"
        CloudExtensionAttribute5        = $_."msDS-cloudExtensionAttribute5"
        CloudExtensionAttribute6        = $_."msDS-cloudExtensionAttribute6"
        CloudExtensionAttribute7        = $_."msDS-cloudExtensionAttribute7"
        CloudExtensionAttribute8        = $_."msDS-cloudExtensionAttribute8"
        CloudExtensionAttribute9        = $_."msDS-cloudExtensionAttribute9"
        CloudExtensionAttribute10       = $_."msDS-cloudExtensionAttribute10"
        CloudExtensionAttribute11       = $_."msDS-cloudExtensionAttribute11"
        CloudExtensionAttribute12       = $_."msDS-cloudExtensionAttribute12"
        CloudExtensionAttribute13       = $_."msDS-cloudExtensionAttribute13"
        CloudExtensionAttribute14       = $_."msDS-cloudExtensionAttribute14"
        CloudExtensionAttribute15       = $_."msDS-cloudExtensionAttribute15"
        CloudExtensionAttribute16       = $_."msDS-cloudExtensionAttribute16"
        CloudExtensionAttribute17       = $_."msDS-cloudExtensionAttribute17"
        CloudExtensionAttribute18       = $_."msDS-cloudExtensionAttribute18"
        CloudExtensionAttribute19       = $_."msDS-cloudExtensionAttribute19"
        CloudExtensionAttribute20       = $_."msDS-cloudExtensionAttribute20"
    }

    # Append any org-specific additional properties from $AdditionalAdProperties
    foreach ($prop in $AdditionalAdProperties) {
        $record[$prop] = $_.$prop
    }

    [PSCustomObject]$record

} | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 } |
    Out-File $outputFile -Encoding UTF8

Write-Log "=== 06_ExportADUsers complete ==="
Write-Log "  Written -> $adOutputFileName ($($adUsers.Count) users)"
