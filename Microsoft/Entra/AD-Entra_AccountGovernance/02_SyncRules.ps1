# ==============================================================================
# 02_SyncRules.ps1
# Purpose : Export and inspect Entra Connect sync rules
# Run on  : Entra Connect server (requires ADSync module)
# Output  : <OutputPath>\SyncRules_*.txt
# Requires: 00_Config.ps1 (shared configuration)
# ==============================================================================

. "$PSScriptRoot\00_Config.ps1"

# --- All inbound rules --------------------------------------------------------
Write-Host "Exporting inbound sync rules..." -ForegroundColor Cyan

Get-ADSyncRule | Where-Object {$_.Direction -eq "Inbound"} |
    Select-Object Name, ConnectorName, ScopeFilterGroups |
    Format-List | Out-File "${OutputPath}SyncRules_Inbound.txt" -Encoding UTF8

Write-Host "  Written -> ${OutputPath}SyncRules_Inbound.txt" -ForegroundColor Green

# --- Detail on key rules ------------------------------------------------------
# Rule names are configured in $KeySyncRuleNames (00_Config.ps1)
Write-Host "Exporting detail on key rules..." -ForegroundColor Cyan

Get-ADSyncRule | Where-Object {
    $_.Name -in $KeySyncRuleNames
} | Format-List * | Out-File "${OutputPath}SyncRules_Detail.txt" -Encoding UTF8

Write-Host "  Written -> ${OutputPath}SyncRules_Detail.txt" -ForegroundColor Green

# --- Disconnector rule attribute flow -----------------------------------------
Write-Host "Exporting Disconnector attribute flow..." -ForegroundColor Cyan

$rule = Get-ADSyncRule | Where-Object {$_.Name -eq "In from AD - User Dirsync Disconnector"}

$rule.AttributeFlowMappings | ForEach-Object {
    [PSCustomObject]@{
        Destination  = $_.Destination
        FlowType     = $_.FlowType
        Expression   = $_.Expression
        ValueMerge   = $_.ValueMergeType
    }
} | Format-List * | Out-String | Out-File "${OutputPath}SyncRules_DisconnectorFlow.txt" -Encoding UTF8

Write-Host "  Written -> ${OutputPath}SyncRules_DisconnectorFlow.txt" -ForegroundColor Green

# --- Disconnector scope condition (nested object) -----------------------------
# Note: In some environments this rule has an empty ScopeFilter and fires on
# precedence only. An empty output file is expected behaviour, not an error.
# See ENVIRONMENT.md and README.md for a reference example.
Write-Host "Exporting Disconnector scope conditions..." -ForegroundColor Cyan

$scopeOutput = $rule.ScopeFilter | ForEach-Object {
    $_.ScopeConditionGroups | ForEach-Object {
        $_.ScopeConditions | Format-List *
    }
} | Out-String

$scopeOutput | Out-File "${OutputPath}SyncRules_DisconnectorScope.txt" -Encoding UTF8
Write-Host "  Written -> ${OutputPath}SyncRules_DisconnectorScope.txt" -ForegroundColor Green

# --- OU / connector scope -----------------------------------------------------
Write-Host "Exporting connector partition info..." -ForegroundColor Cyan

$connector = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -eq $ADConnectorTypeName}
$connector.Partitions | Out-String |
    Out-File "${OutputPath}SyncRules_ConnectorPartitions.txt" -Encoding UTF8

Write-Host "  Written -> ${OutputPath}SyncRules_ConnectorPartitions.txt" -ForegroundColor Green
Write-Host "`nAll sync rule exports complete." -ForegroundColor Green
