# ==============================================================================
# 00_Config.ps1
# Purpose : Shared configuration for all AD-Entra governance scripts.
#           Edit the values in this file to match your environment before
#           running any of the numbered scripts.
#           See ENVIRONMENT.md for a per-setting reference and worked example.
# ==============================================================================

# Output directory for all exported files (resolved relative to this config file)
$OutputPath = Join-Path $PSScriptRoot 'Output'

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "Created output directory: $OutputPath" -ForegroundColor DarkGray
}

# --- Source anchor / ImmutableID method ---------------------------------------
# Determines how AD user objects are matched to Entra's OnPremisesImmutableId.
# Supported values:
#   "ObjectGUID"            - Standard default. Base64-encodes the AD ObjectGUID.
#                             Use this for most new/standard single-forest deployments.
#   "mS-DS-ConsistencyGuid" - Microsoft recommended for large orgs or multi-forest.
#                             Base64-encodes the mS-DS-ConsistencyGuid attribute.
#   "Custom"                - Uses a custom AD attribute. Set $CustomImmutableIdAttribute.
$ImmutableIdMethod = "ObjectGUID"

# Only used when $ImmutableIdMethod = "Custom".
# Set to the AD attribute name that holds the source anchor value.
# Example: "extensionAttribute1"
$CustomImmutableIdAttribute = $null

# --- Connector settings -------------------------------------------------------
# ConnectorTypeName used to identify the AD connector in Entra Connect.
# Standard value is "AD". Only change if your environment uses a non-standard type.
$ADConnectorTypeName = "AD"

# --- Sync rules to inspect in detail (used by 02_SyncRules.ps1) ---------------
# "In from AD - User Dirsync Disconnector" is a standard Microsoft-generated rule
# present in most environments. Add any custom rules your tenant uses.
$KeySyncRuleNames = @(
    "In from AD - User Dirsync Disconnector"
    # Example: "ORGPREFIX - In from AD - usageLocation"
)

# --- Additional AD user properties (used by 06_ExportADUsers.ps1) -------------
# Add any org-specific or custom schema AD attributes to include in the export.
# These are appended to the fixed property list and added as extra columns in
# the output. Standard attributes and extensionAttribute1-15 are already included.
# Examples: "employeeNumber", "msDS-cloudExtensionAttribute21", "l", "st"
$AdditionalAdProperties = @(
    # "employeeNumber"
)

# --- Permissions audit settings (used by 04_ExportEntraRoles.ps1) -------------
# When $true, the role export queries PIM eligible role assignments in addition
# to active assignments. Set to $false to skip the PIM call entirely (e.g. on
# tenants without Entra ID P2). The script also catches license/permission
# errors from the PIM endpoint and writes an empty eligibilities file so a
# missing P2 license never aborts the run.
$IncludePimEligibilities = $true

# --- Stale admin threshold (used by 08_BuildAdminSummary.ps1) -----------------
# Days since last interactive sign-in beyond which an admin account is flagged
# as stale in the admin summary report.
$StaleAdminThresholdDays = 90

# --- Manager lookup (used by 03_ExportEntraUsers.ps1) -------------------------
# When $true, the user export adds $expand=manager to the bulk Get-MgUser call
# so each user record carries ManagerId and ManagerDisplayName. Doubles the
# response payload from Graph but enables manager-by-admin reporting and
# attestation workflows. Set to $false to skip — manager fields will emit as
# null but the output schema stays stable.
$IncludeManagerLookup = $true

# --- Multi-forest configuration -----------------------------------------------
# List each AD forest name that should be included in the audit. The name is
# used as a suffix on the AD export file (AD_AllUsers_<ForestName>_<RunFileSuffix>.ndjson) and
# as a sub-directory label in run manifests. Single-forest environments use the
# default entry. For multiple forests run 06_ExportADUsers.ps1 once per forest
# (the orchestrator does this automatically).
# Example: $Forests = @("corp.local", "subsidiary.com")
$Forests = @("default")

# --- Run file-suffix helpers --------------------------------------------------
# Output filenames in this pipeline carry a per-run suffix '<base>_yyyyMMdd_HHmm.ndjson'
# so they remain self-identifying when copied out of the timestamped run dir.
# The orchestrator sets $RunFileSuffix once at run start; standalone script
# runs derive it either from a fresh Get-Date or from the run dir's name.

function Get-RunFileSuffix {
    param([datetime]$RunDate = (Get-Date))
    return $RunDate.ToString('yyyyMMdd_HHmm')
}

function ConvertTo-RunFileSuffix {
    param([Parameter(Mandatory)] [string]$DirectoryName)
    try {
        $parsed = [datetime]::ParseExact($DirectoryName, 'yyyy-MM-dd_HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
        return Get-RunFileSuffix -RunDate $parsed
    }
    catch {
        return $null
    }
}

# --- Config validation --------------------------------------------------------
# Called by the orchestrator before any script runs. Can also be called manually
# to validate the configuration before a standalone run.
function Assert-GovernanceConfig {
    $validMethods = @("ObjectGUID", "mS-DS-ConsistencyGuid", "Custom")
    if ($ImmutableIdMethod -notin $validMethods) {
        throw "Invalid ImmutableIdMethod '$ImmutableIdMethod'. Must be one of: $($validMethods -join ', ')"
    }

    if ($ImmutableIdMethod -eq "Custom" -and [string]::IsNullOrWhiteSpace($CustomImmutableIdAttribute)) {
        throw "ImmutableIdMethod is 'Custom' but CustomImmutableIdAttribute is not set."
    }

    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        throw "OutputPath is empty. Set a valid output directory in 00_Config.ps1."
    }

    try {
        New-Item -ItemType Directory -Path $OutputPath -Force -ErrorAction Stop | Out-Null
    } catch {
        throw "OutputPath '$OutputPath' is not writable: $_"
    }

    if ($null -eq $IncludePimEligibilities -or $IncludePimEligibilities -isnot [bool]) {
        throw "IncludePimEligibilities must be `$true or `$false (currently: $IncludePimEligibilities)."
    }

    if ($StaleAdminThresholdDays -isnot [int] -or $StaleAdminThresholdDays -lt 1) {
        throw "StaleAdminThresholdDays must be a positive integer (currently: $StaleAdminThresholdDays)."
    }

    if ($null -eq $IncludeManagerLookup -or $IncludeManagerLookup -isnot [bool]) {
        throw "IncludeManagerLookup must be `$true or `$false (currently: $IncludeManagerLookup)."
    }
}
