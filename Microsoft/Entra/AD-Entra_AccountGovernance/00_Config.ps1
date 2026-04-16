# ==============================================================================
# 00_Config.ps1
# Purpose : Shared configuration for all AD-Entra governance scripts.
#           Edit the values in this file to match your environment before
#           running any of the numbered scripts.
#           See ENVIRONMENT.md for a per-setting reference and worked example.
# ==============================================================================

# Output directory for all exported files (include trailing backslash)
$OutputPath = ".\Output\"

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

# --- Additional AD user properties (used by 04_ExportADUsers.ps1) -------------
# Add any org-specific or custom schema AD attributes to include in the export.
# These are appended to the fixed property list and added as extra columns in
# the output. Standard attributes and extensionAttribute1-15 are already included.
# Examples: "employeeNumber", "msDS-cloudExtensionAttribute21", "l", "st"
$AdditionalAdProperties = @(
    # "employeeNumber"
)
