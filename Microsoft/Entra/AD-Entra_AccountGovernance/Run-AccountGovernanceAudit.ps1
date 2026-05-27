# ==============================================================================
# Run-AccountGovernanceAudit.ps1
# Purpose : Orchestrate a complete AD-Entra account governance audit run.
#           Runs the numbered scripts in sequence, sharing a single timestamped
#           output directory across all steps and writing a run manifest on
#           completion.
#
# Usage:
#   .\Run-AccountGovernanceAudit.ps1
#   .\Run-AccountGovernanceAudit.ps1 -Forest "corp.local"
#   .\Run-AccountGovernanceAudit.ps1 -SkipEntraExport   # reuse prior Entra NDJSON
#   .\Run-AccountGovernanceAudit.ps1 -SkipRoleExport -SkipGroupExport
#   .\Run-AccountGovernanceAudit.ps1 -SkipConvertToJson # NDJSON only, skip .json
#
# Notes:
#   - Scripts 01 and 02 (Entra Connect server scripts) are not included here;
#     they run on a separate server and are out of scope for this orchestrator.
#   - Scripts are dot-sourced so their variables are visible here for the manifest.
#   - Edit 00_Config.ps1 before running to set ImmutableIdMethod, Forests, etc.
# ==============================================================================

[CmdletBinding(SupportsShouldProcess)]
param(
    # Limit the AD export to a single named forest (must match an entry in $Forests).
    # When omitted, all forests defined in $Forests are exported.
    [string]$Forest = $null,

    # Skip script 03 (Entra user export). Useful when reusing a prior Entra
    # export and only re-running the AD and cross-reference steps. Requires
    # the Entra NDJSON files from a previous run to already exist in $RunOutputPath.
    [switch]$SkipEntraExport,

    # Skip script 04 (Entra role export). Useful when reusing prior role data
    # or when RoleManagement.Read.Directory consent isn't yet granted.
    [switch]$SkipRoleExport,

    # Skip script 05 (Entra group export). Useful when reusing prior group data
    # or running a faster pipeline without the heaviest step.
    [switch]$SkipGroupExport,

    # Skip script 06 (AD user export). Useful when AD files were transferred
    # manually from a domain-joined machine.
    [switch]$SkipADExport,

    # Skip script 08 (admin summary derivation). Useful when only the raw
    # role/group/user data is needed and downstream reporting is offline.
    [switch]$SkipAdminSummary,

    # Skip script 09 (NDJSON to JSON conversion). Use when only NDJSON output
    # is needed (e.g., for pipeline consumption rather than Excel).
    [switch]$SkipConvertToJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Bootstrap ----------------------------------------------------------------
. "$PSScriptRoot\00_Config.ps1"

$loggingModulePath = Join-Path $PSScriptRoot '..\..\Common\Modules\Shared\Logging.psm1'
Import-Module $loggingModulePath -Force -ErrorAction Stop

# Create a single timestamped directory shared by all steps. $RunFileSuffix is
# the same moment formatted for use inside output filenames so each file is
# self-identifying when copied out of the run dir.
$runStartDate  = Get-Date
$RunTimestamp  = $runStartDate.ToString('yyyy-MM-dd_HHmmss')
$RunFileSuffix = Get-RunFileSuffix -RunDate $runStartDate
$RunOutputPath = Join-Path $OutputPath $RunTimestamp
New-Item -ItemType Directory -Path $RunOutputPath -Force | Out-Null

# Sentinel that tells child scripts the orchestrator is in charge of the run
# path. Without this, child scripts run via dot-source might inherit a stale
# $RunOutputPath from a previous standalone run in the same PowerShell session
# and silently write today's output into yesterday's folder. Cleared in finally
# so a failed orchestrator run doesn't leave the flag set.
$Global:GovernanceOrchestratorActive = $true

try {

Set-LogFilePath -Path (Join-Path $RunOutputPath 'AccountGovernance.log')
Write-Log "================================================================"
Write-Log "AccountGovernance Audit started — RunTimestamp: $RunTimestamp"
Write-Log "Output directory : $RunOutputPath"
Write-Log "================================================================"

# --- Pre-flight config validation --------------------------------------------
Write-Log "Running pre-flight config validation..."
Assert-GovernanceConfig
Write-Log "Config validation passed."

# --- Determine forest scope ---------------------------------------------------
$forestsToRun = if ($Forest) { @($Forest) } else { $Forests }
Write-Log "Forests in scope: $($forestsToRun -join ', ')"

$auditStart = Get-Date

# --- Step 03: Entra user export -----------------------------------------------
if (-not $SkipEntraExport) {
    Write-Log "--- Step 03: Entra user export ---"
    try {
        . "$PSScriptRoot\03_ExportEntraUsers.ps1"
    } catch {
        Write-Log "Step 03 FAILED: $_"
        throw
    }
} else {
    Write-Log "--- Step 03: Skipped (SkipEntraExport) ---"
}

# --- Step 04: Entra role export -----------------------------------------------
if (-not $SkipRoleExport) {
    Write-Log "--- Step 04: Entra role export ---"
    try {
        . "$PSScriptRoot\04_ExportEntraRoles.ps1"
    } catch {
        Write-Log "Step 04 FAILED: $_"
        throw
    }
} else {
    Write-Log "--- Step 04: Skipped (SkipRoleExport) ---"
}

# --- Step 05: Entra group export ----------------------------------------------
if (-not $SkipGroupExport) {
    Write-Log "--- Step 05: Entra group export ---"
    try {
        . "$PSScriptRoot\05_ExportEntraGroups.ps1"
    } catch {
        Write-Log "Step 05 FAILED: $_"
        throw
    }
} else {
    Write-Log "--- Step 05: Skipped (SkipGroupExport) ---"
}

# --- Step 06: AD user export (one per forest) ---------------------------------
if (-not $SkipADExport) {
    foreach ($forestName in $forestsToRun) {
        Write-Log "--- Step 06: AD user export for forest '$forestName' ---"
        try {
            . "$PSScriptRoot\06_ExportADUsers.ps1" -ForestName $forestName
        } catch {
            Write-Log "Step 06 FAILED for forest '$forestName': $_"
            throw
        }
    }
} else {
    Write-Log "--- Step 06: Skipped (SkipADExport) ---"
}

# --- Step 07: Cross-reference -------------------------------------------------
Write-Log "--- Step 07: Cross-reference ---"
try {
    . "$PSScriptRoot\07_CrossReference.ps1"
} catch {
    Write-Log "Step 07 FAILED: $_"
    throw
}

# --- Step 08: Admin summary ---------------------------------------------------
if (-not $SkipAdminSummary) {
    Write-Log "--- Step 08: Admin summary ---"
    try {
        . "$PSScriptRoot\08_BuildAdminSummary.ps1"
    } catch {
        Write-Log "Step 08 FAILED: $_"
        throw
    }
} else {
    Write-Log "--- Step 08: Skipped (SkipAdminSummary) ---"
}

# --- Step 09: Convert NDJSON to JSON ------------------------------------------
if (-not $SkipConvertToJson) {
    Write-Log "--- Step 09: Convert NDJSON to JSON ---"
    try {
        . "$PSScriptRoot\09_ConvertToJson.ps1"
    } catch {
        Write-Log "Step 09 FAILED: $_"
        throw
    }
} else {
    Write-Log "--- Step 09: Skipped (SkipConvertToJson) ---"
}

# --- Run manifest -------------------------------------------------------------
# Variables from dot-sourced scripts are available here: $synced, $prevSynced,
# $cloudOnly, $adOnly, $withErrors, $adUsers, $roleDefinitions, $roleAssignments,
# $roleEligibilities, $allGroups, $memberCount, $ownerCount, $effectiveAdmins,
# $nonUserRoleHolders
$auditEnd = Get-Date

$manifest = [ordered]@{
    AuditStartTime    = $auditStart.ToString('yyyy-MM-dd HH:mm:ss')
    AuditEndTime      = $auditEnd.ToString('yyyy-MM-dd HH:mm:ss')
    DurationMinutes   = [Math]::Round(($auditEnd - $auditStart).TotalMinutes, 1)
    Forests           = $forestsToRun
    ImmutableIdMethod = $ImmutableIdMethod
    OutputDirectory   = $RunOutputPath
    Counts            = [ordered]@{
        EntraSynced        = if (Get-Variable -Name synced            -ErrorAction SilentlyContinue) { @($synced).Count }            else { $null }
        EntraPrevSynced    = if (Get-Variable -Name prevSynced         -ErrorAction SilentlyContinue) { @($prevSynced).Count }         else { $null }
        EntraCloudOnly     = if (Get-Variable -Name cloudOnly          -ErrorAction SilentlyContinue) { @($cloudOnly).Count }          else { $null }
        RoleDefinitions    = if (Get-Variable -Name roleDefinitions    -ErrorAction SilentlyContinue) { @($roleDefinitions).Count }    else { $null }
        RoleAssignments    = if (Get-Variable -Name roleAssignments    -ErrorAction SilentlyContinue) { @($roleAssignments).Count }    else { $null }
        RoleEligibilities  = if (Get-Variable -Name roleEligibilities  -ErrorAction SilentlyContinue) { @($roleEligibilities).Count }  else { $null }
        Groups             = if (Get-Variable -Name allGroups          -ErrorAction SilentlyContinue) { @($allGroups).Count }          else { $null }
        GroupMembers       = if (Get-Variable -Name memberCount        -ErrorAction SilentlyContinue) { $memberCount }                  else { $null }
        GroupOwners        = if (Get-Variable -Name ownerCount         -ErrorAction SilentlyContinue) { $ownerCount }                   else { $null }
        ADTotal            = if (Get-Variable -Name adUsers            -ErrorAction SilentlyContinue) { @($adUsers).Count }            else { $null }
        ADOnly             = if (Get-Variable -Name adOnly             -ErrorAction SilentlyContinue) { @($adOnly).Count }             else { $null }
        ProvisioningErrors = if (Get-Variable -Name withErrors         -ErrorAction SilentlyContinue) { @($withErrors).Count }         else { $null }
        EffectiveAdmins    = if (Get-Variable -Name effectiveAdmins    -ErrorAction SilentlyContinue) { @($effectiveAdmins).Count }    else { $null }
        NonUserRoleHolders = if (Get-Variable -Name nonUserRoleHolders -ErrorAction SilentlyContinue) { @($nonUserRoleHolders).Count } else { $null }
    }
    SkippedSteps      = @(
        if ($SkipEntraExport)   { "03_ExportEntraUsers" }
        if ($SkipRoleExport)    { "04_ExportEntraRoles" }
        if ($SkipGroupExport)   { "05_ExportEntraGroups" }
        if ($SkipADExport)      { "06_ExportADUsers" }
        if ($SkipAdminSummary)  { "08_BuildAdminSummary" }
        if ($SkipConvertToJson) { "09_ConvertToJson" }
    )
}

$manifestPath = Join-Path $RunOutputPath "RunManifest_$RunFileSuffix.json"
$manifest | ConvertTo-Json -Depth 5 | Out-File $manifestPath -Encoding UTF8
Write-Log "Run manifest written to $manifestPath"

Write-Log "================================================================"
Write-Log "AccountGovernance Audit complete — $([Math]::Round(($auditEnd - $auditStart).TotalMinutes, 1)) minutes"
Write-Log "Output: $RunOutputPath"
Write-Log "================================================================"

}
finally {
    Remove-Variable -Name GovernanceOrchestratorActive -Scope Global -ErrorAction SilentlyContinue
}
