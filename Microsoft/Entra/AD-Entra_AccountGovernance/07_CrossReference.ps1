# ==============================================================================
# 07_CrossReference.ps1
# Purpose : Cross-reference AD export against Entra buckets to identify
#           AD-only accounts and surface sync anomalies
# Run on  : Any machine with access to the NDJSON output files
# Requires: 00_Config.ps1, and outputs from 03_ExportEntraUsers.ps1 and
#           06_ExportADUsers.ps1
# ==============================================================================

. "$PSScriptRoot\00_Config.ps1"

# --- Module imports -----------------------------------------------------------
$loggingModulePath = Join-Path $PSScriptRoot '..\..\Common\Modules\Shared\Logging.psm1'
Import-Module $loggingModulePath -Force -ErrorAction Stop

# --- Run output directory -----------------------------------------------------
if (-not (Get-Variable -Name RunOutputPath -ErrorAction SilentlyContinue)) {
    # Standalone: use the most recent timestamped run directory
    $latestRun = Get-ChildItem -Path $OutputPath -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
    if ($null -eq $latestRun) {
        throw "No timestamped run directories found in '$OutputPath'. Run scripts 03 and 04 first."
    }
    $RunOutputPath = $latestRun.FullName
    Write-Warning "No RunOutputPath set; using most recent run: $RunOutputPath"
}
Set-LogFilePath -Path (Join-Path $RunOutputPath 'AccountGovernance.log')
Write-Log "=== 07_CrossReference started ==="

# --- Input file validation ----------------------------------------------------
$requiredInputFiles = @(
    @{ Path = Join-Path $RunOutputPath 'Entra_SyncedUsers.ndjson';     Label = 'Entra synced users' }
    @{ Path = Join-Path $RunOutputPath 'Entra_PreviouslySynced.ndjson'; Label = 'Entra previously synced' }
)

# Require at least one forest AD file
$forestAdFiles = @($Forests | ForEach-Object {
    Join-Path $RunOutputPath "AD_AllUsers_${_}.ndjson"
} | Where-Object { Test-Path $_ })

if ($forestAdFiles.Count -eq 0) {
    $expectedFiles = $Forests | ForEach-Object { "AD_AllUsers_${_}.ndjson" }
    throw "No AD user export files found in '$RunOutputPath'. Expected: $($expectedFiles -join ', '). Run script 06 first."
}

$missingFiles = $requiredInputFiles | Where-Object { -not (Test-Path $_.Path) }
if ($missingFiles.Count -gt 0) {
    $missingFiles | ForEach-Object { Write-Log "MISSING: $($_.Label) — expected at $($_.Path)" }
    throw "Required Entra input files are missing. Run script 03 first."
}

# --- Load Entra data ----------------------------------------------------------
Write-Log "Loading Entra synced users..."
$entraSynced = Get-Content (Join-Path $RunOutputPath 'Entra_SyncedUsers.ndjson') |
    ForEach-Object { $_ | ConvertFrom-Json }

Write-Log "Loading Entra previously synced users..."
$prevSynced = Get-Content (Join-Path $RunOutputPath 'Entra_PreviouslySynced.ndjson') |
    ForEach-Object { $_ | ConvertFrom-Json }

# --- Load AD data (union across all configured forests) -----------------------
Write-Log "Loading AD users ($($forestAdFiles.Count) forest file(s))..."
$adUsers = @()
foreach ($forestFile in $forestAdFiles) {
    $forestName = [System.IO.Path]::GetFileNameWithoutExtension($forestFile) -replace '^AD_AllUsers_', ''
    $forestUsers = Get-Content $forestFile | ForEach-Object { $_ | ConvertFrom-Json }
    Write-Log "  Forest '$forestName': $($forestUsers.Count) users"
    $adUsers += $forestUsers
}
Write-Log "  Total AD users loaded: $($adUsers.Count)"

# Build lookup of ImmutableIds present in Entra
$entraImmutableIds = @{}
$entraSynced | ForEach-Object {
    if ($_.OnPremisesImmutableId) {
        $entraImmutableIds[$_.OnPremisesImmutableId] = $true
    }
}

# --- Bucket 4: AD-only accounts -----------------------------------------------
# Accounts in AD whose ImmutableId does not appear in any Entra synced bucket
Write-Log "Identifying AD-only accounts..."

$adOnly = $adUsers | Where-Object {
    -not $entraImmutableIds.ContainsKey($_.ImmutableId)
}

Write-Log "  AD-only accounts: $($adOnly.Count)"

$adOnly | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 } |
    Out-File (Join-Path $RunOutputPath 'AD_OnlyAccounts.ndjson') -Encoding UTF8
Write-Log "  Written -> AD_OnlyAccounts.ndjson"

# --- Accounts with provisioning errors ----------------------------------------
# OnPremisesProvisioningErrors is a JSON array (not a string) — check array length
$withErrors = $entraSynced | Where-Object { @($_.OnPremisesProvisioningErrors).Count -gt 0 }
Write-Log "  Accounts with provisioning errors: $($withErrors.Count)"

$withErrors | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 } |
    Out-File (Join-Path $RunOutputPath 'Entra_ProvisioningErrors.ndjson') -Encoding UTF8
Write-Log "  Written -> Entra_ProvisioningErrors.ndjson"

# --- Summary ------------------------------------------------------------------
Write-Log "=== 07_CrossReference complete ==="
Write-Log "  AD total accounts         : $($adUsers.Count)"
Write-Log "  Entra synced              : $($entraSynced.Count)"
Write-Log "  Entra previously synced   : $($prevSynced.Count)"
Write-Log "  AD-only (no Entra object) : $($adOnly.Count)"
Write-Log "  Accounts with sync errors : $($withErrors.Count)"
