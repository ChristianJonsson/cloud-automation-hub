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

# --- Sign-in activity (used by 03_ExportEntraUsers.ps1, 08_BuildAdminSummary.ps1)
# When $true, the user export requests the SignInActivity property and
# AuditLog.Read.All scope. Reading SignInActivity is gated by Microsoft Graph
# and requires the calling user to hold one of: Reports Reader, Security
# Reader, Global Reader, Helpdesk/Auth/Priv Auth Administrator, User
# Administrator, or Global Administrator. Some tenants gate it more strictly.
# Set to $false when your account / tenant configuration cannot satisfy the
# role gate — the three sign-in timestamp fields emit as null and step 08's
# staleness detection is skipped (IsStale and StaleAdminUsers become null
# rather than reporting misleading "all admins are stale" results).
$IncludeSignInActivity = $false

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

# Sanitises a token (e.g. a forest name) for safe use inside a file name by
# replacing any character that is illegal on the filesystem with '_'. Must be
# applied consistently anywhere a forest name is turned into a file name so that
# the writer (06) and the reader (07) agree on the resulting path.
function ConvertTo-SafeFileNameToken {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string]$Token)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $pattern = '[{0}]' -f [regex]::Escape(-join $invalid)
    return ([regex]::Replace($Token, $pattern, '_'))
}

# Decides whether to reuse an inherited $RunOutputPath or create a fresh one.
#
# Bug guarded against: when an export script is dot-sourced repeatedly in a
# long-lived PowerShell session (e.g. VS Code's integrated terminal), the
# $RunOutputPath set by the first run sticks around and silently sends every
# subsequent run's output into the original (now stale) folder. This helper
# detects that case and regenerates the path.
#
# Logic:
#   - If $Global:GovernanceOrchestratorActive is $true, the orchestrator is
#     in charge — trust the inherited path unconditionally so all child
#     scripts share the same run dir.
#   - Otherwise (standalone), parse the inherited path's timestamp. If it
#     parses and is younger than $StaleHours, reuse it (allows quick reruns
#     after a failure). If older or unparseable, create a fresh run dir and
#     emit a warning so the caller knows what happened.
function Resolve-RunOutputPath {
    param(
        [Parameter(Mandatory)] [string]$OutputPathRoot,
        [string]$ExistingPath = $null,
        [int]$StaleHours      = 1
    )

    $orchestratorRun = Get-Variable -Name GovernanceOrchestratorActive -Scope Global -ErrorAction SilentlyContinue
    $reused          = $false

    if (-not [string]::IsNullOrWhiteSpace($ExistingPath)) {
        if ($orchestratorRun -and $orchestratorRun.Value -eq $true) {
            $reused = $true
        } else {
            try {
                $dirName     = Split-Path $ExistingPath -Leaf
                $existingDate = [datetime]::ParseExact($dirName, 'yyyy-MM-dd_HHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
                $ageHours    = ((Get-Date) - $existingDate).TotalHours
                if ($ageHours -lt $StaleHours) {
                    $reused = $true
                } else {
                    Write-Warning ("Inherited RunOutputPath '{0}' is {1:N1}h old; creating fresh run dir for this standalone run." -f $ExistingPath, $ageHours)
                }
            }
            catch {
                Write-Warning "Inherited RunOutputPath '$ExistingPath' could not be parsed as a run timestamp; creating fresh run dir."
            }
        }
    }

    if ($reused) {
        $suffix = ConvertTo-RunFileSuffix -DirectoryName (Split-Path $ExistingPath -Leaf)
        if ([string]::IsNullOrEmpty($suffix)) { $suffix = Get-RunFileSuffix }
        return [PSCustomObject]@{
            RunOutputPath = $ExistingPath
            RunFileSuffix = $suffix
            Reused        = $true
        }
    }

    $now     = Get-Date
    $newPath = Join-Path $OutputPathRoot $now.ToString('yyyy-MM-dd_HHmmss')
    if (-not (Test-Path $newPath)) {
        New-Item -ItemType Directory -Path $newPath -Force | Out-Null
    }

    return [PSCustomObject]@{
        RunOutputPath = $newPath
        RunFileSuffix = Get-RunFileSuffix -RunDate $now
        Reused        = $false
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

    if ($null -eq $IncludeSignInActivity -or $IncludeSignInActivity -isnot [bool]) {
        throw "IncludeSignInActivity must be `$true or `$false (currently: $IncludeSignInActivity)."
    }
}
