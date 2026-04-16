# ==============================================================================
# 05_CrossReference.ps1
# Purpose : Cross-reference AD export against Entra buckets to identify
#           AD-only accounts and surface sync anomalies
# Run on  : Any machine with access to the NDJSON output files
# Requires: 00_Config.ps1, and outputs from 03_ExportEntraUsers.ps1 and
#           04_ExportADUsers.ps1
# Status  : TODO - not yet completed
# ==============================================================================

. "$PSScriptRoot\00_Config.ps1"

# --- Load exported data -------------------------------------------------------
Write-Host "Loading Entra synced users..." -ForegroundColor Cyan
$entraSynced = Get-Content "${OutputPath}Entra_SyncedUsers.ndjson" |
    ForEach-Object { $_ | ConvertFrom-Json }

Write-Host "Loading AD users..." -ForegroundColor Cyan
$adUsers = Get-Content "${OutputPath}AD_AllUsers.ndjson" |
    ForEach-Object { $_ | ConvertFrom-Json }

# Build lookup of ImmutableIds present in Entra
$entraImmutableIds = @{}
$entraSynced | ForEach-Object {
    if ($_.OnPremisesImmutableId) {
        $entraImmutableIds[$_.OnPremisesImmutableId] = $true
    }
}

# --- Bucket 4: AD-only accounts -----------------------------------------------
# Accounts in AD whose ImmutableId does not appear in any Entra synced bucket
Write-Host "Identifying AD-only accounts..." -ForegroundColor Cyan

$adOnly = $adUsers | Where-Object {
    -not $entraImmutableIds.ContainsKey($_.ImmutableId)
}

Write-Host "  AD-only accounts: $($adOnly.Count)"

$adOnly | ForEach-Object { $_ | ConvertTo-Json -Compress } |
    Out-File "${OutputPath}AD_OnlyAccounts.ndjson" -Encoding UTF8

Write-Host "  Written -> ${OutputPath}AD_OnlyAccounts.ndjson" -ForegroundColor Green

# --- Accounts with provisioning errors ----------------------------------------
Write-Host "`nLoading previously synced users..." -ForegroundColor Cyan
$prevSynced = Get-Content "${OutputPath}Entra_PreviouslySynced.ndjson" |
    ForEach-Object { $_ | ConvertFrom-Json }

$withErrors = $entraSynced | Where-Object { $_.OnPremisesProvisioningErrors -ne "" -and $_.OnPremisesProvisioningErrors -ne $null }
Write-Host "  Accounts with provisioning errors: $($withErrors.Count)"

$withErrors | ForEach-Object { $_ | ConvertTo-Json -Compress } |
    Out-File "${OutputPath}Entra_ProvisioningErrors.ndjson" -Encoding UTF8

Write-Host "  Written -> ${OutputPath}Entra_ProvisioningErrors.ndjson" -ForegroundColor Green

# --- Summary ------------------------------------------------------------------
Write-Host "`n=== CROSS-REFERENCE SUMMARY ===" -ForegroundColor Yellow
Write-Host "AD total accounts         : $($adUsers.Count)"
Write-Host "Entra synced              : $($entraSynced.Count)"
Write-Host "Entra previously synced   : $($prevSynced.Count)"
Write-Host "AD-only (no Entra object) : $($adOnly.Count)"
Write-Host "Accounts with sync errors : $($withErrors.Count)"
