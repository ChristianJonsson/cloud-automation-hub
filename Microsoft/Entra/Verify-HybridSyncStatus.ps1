<#
.SYNOPSIS
Verifies sync state for users in a hybrid Entra ID and Active Directory environment.

.DESCRIPTION
Generates report-only outputs for three analysis modes:
- Audit: Inventory of synced, out-of-sync, cloud-only, and unknown users.
- Troubleshoot: Focused diagnostics for problematic sync states.
- Health: Sync freshness and aggregate health metrics.

.NOTES
This script does not write changes to Entra user objects.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Audit', 'Troubleshoot', 'Health')]
    [string]$Mode,

    [ValidateSet('Auto', 'EntraConnect', 'EntraCloudSync')]
    [string]$SyncSource = 'Auto',

    [ValidateRange(1, 3650)]
    [int]$OutOfSyncDaysThreshold = 7,

    [ValidateSet('All', 'EnabledOnly', 'DisabledOnly')]
    [string]$IncludeAccountStatus = 'All',

    [string[]]$UpnDomains,

    [string[]]$ExtensionAttribute1Values,

    [switch]$UseCachedGraphResults,

    [string]$OutputFolderPath = (Join-Path $PSScriptRoot 'Reports\HybridSyncVerification'),

    [switch]$IncludeGuests,

    [Alias('h')]
    [switch]$Help
)

if ($Help) {
    @"
Usage:
    .\Verify-HybridSyncStatus.ps1 -Mode Audit|Troubleshoot|Health [-SyncSource Auto|EntraConnect|EntraCloudSync] [-OutOfSyncDaysThreshold <int>] [-IncludeAccountStatus All|EnabledOnly|DisabledOnly] [-UpnDomains <string[]>] [-ExtensionAttribute1Values <string[]>] [-UseCachedGraphResults] [-OutputFolderPath <path>] [-IncludeGuests] [-Help|-h]

Examples:
    .\Verify-HybridSyncStatus.ps1 -Mode Audit
    .\Verify-HybridSyncStatus.ps1 -Mode Troubleshoot -OutOfSyncDaysThreshold 14
    .\Verify-HybridSyncStatus.ps1 -Mode Health -UpnDomains contoso.com,fabrikam.com
    .\Verify-HybridSyncStatus.ps1 -Mode Audit -ExtensionAttribute1Values HQ,FieldOps

Notes:
    - This script is report-only and does not update users.
    - IncludeGuests is off by default, so guest-like users are excluded unless explicitly included.
    - Health mode writes both detailed and aggregate summary CSV outputs.
"@ | Write-Host
    return
}

if ([string]::IsNullOrWhiteSpace($Mode)) {
    Write-Error "Parameter -Mode is required unless -Help is specified." -ErrorAction Stop
}

$commonSharedModuleRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'Common\Modules\Shared'
$entraSharedModuleRoot = Join-Path $PSScriptRoot 'Modules\Shared'

Import-Module (Join-Path $commonSharedModuleRoot 'Logging.psm1') -Force
Import-Module (Join-Path $entraSharedModuleRoot 'GraphConnection.psm1') -Force
Import-Module (Join-Path $entraSharedModuleRoot 'GraphData.psm1') -Force
Import-Module (Join-Path $entraSharedModuleRoot 'SyncStatus.psm1') -Force

Set-LogFilePath -Path (Join-Path $PSScriptRoot 'Logs\SyncVerification.log')

function New-DirectoryIfMissing {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-NormalizedStringSet {
    param([string[]]$Values)

    return @(
        @($Values) |
            ForEach-Object { "$_".Trim().ToLowerInvariant() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Get-UpnDomain {
    param([string]$UserPrincipalName)

    $upn = "$UserPrincipalName"
    if ($upn -notmatch '@') {
        return ''
    }

    return ($upn.Split('@')[-1]).ToLowerInvariant()
}

function Test-IsGuestLikeUser {
    param([object]$User)

    if ("$($User.UserType)" -eq 'Guest') {
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace("$($User.UserPrincipalName)") -and "$($User.UserPrincipalName)" -match '#EXT#') {
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace("$($User.ExternalUserState)")) {
        return $true
    }

    if ("$($User.CreationType)" -eq 'Invitation') {
        return $true
    }

    return $false
}

function Test-UserMatchesAccountStatusFilter {
    param(
        [object]$User,
        [ValidateSet('All', 'EnabledOnly', 'DisabledOnly')]
        [string]$IncludeAccountStatus
    )

    switch ($IncludeAccountStatus) {
        'All' { return $true }
        'EnabledOnly' { return ($User.AccountEnabled -eq $true) }
        'DisabledOnly' { return ($User.AccountEnabled -eq $false) }
    }

    return $true
}

function Test-UserMatchesFilters {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [string[]]$NormalizedUpnDomains,

        [string[]]$NormalizedExtensionAttribute1Values,

        [ValidateSet('All', 'EnabledOnly', 'DisabledOnly')]
        [string]$IncludeAccountStatus,

        [bool]$IncludeGuests
    )

    if (-not $IncludeGuests -and (Test-IsGuestLikeUser -User $User)) {
        return [pscustomobject]@{
            IsMatch = $false
            FilterMatchedBy = 'ExcludedGuestLike'
        }
    }

    if (-not (Test-UserMatchesAccountStatusFilter -User $User -IncludeAccountStatus $IncludeAccountStatus)) {
        return [pscustomobject]@{
            IsMatch = $false
            FilterMatchedBy = 'AccountStatusMismatch'
        }
    }

    $matchedBy = @()

    $domainMatch = $true
    if (@($NormalizedUpnDomains).Count -gt 0) {
        $domain = Get-UpnDomain -UserPrincipalName $User.UserPrincipalName
        $domainMatch = ($NormalizedUpnDomains -contains $domain)
        if ($domainMatch) {
            $matchedBy += 'UPNDomain'
        }
    }

    $extensionMatch = $true
    if (@($NormalizedExtensionAttribute1Values).Count -gt 0) {
        $extensionAttribute1 = "$(Get-ExtensionAttributeValue -OnPremisesExtensionAttributes $User.OnPremisesExtensionAttributes -Index 1)".Trim().ToLowerInvariant()
        $extensionMatch = ($NormalizedExtensionAttribute1Values -contains $extensionAttribute1)
        if ($extensionMatch) {
            $matchedBy += 'ExtensionAttribute1'
        }
    }

    $isMatch = $domainMatch -and $extensionMatch

    return [pscustomobject]@{
        IsMatch = $isMatch
        FilterMatchedBy = if ($isMatch) {
            if ($matchedBy.Count -eq 0) { 'AllUsers' } else { $matchedBy -join '+' }
        }
        else {
            'FilterMismatch'
        }
    }
}

function Show-ClassificationSummary {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Records,

        [Parameter(Mandatory = $true)]
        [string]$Title
    )

    $recordArray = @($Records)
    $total = $recordArray.Count

    Write-Host ''
    Write-Host $Title -ForegroundColor Cyan

    if ($total -eq 0) {
        Write-Host 'No records to summarize.' -ForegroundColor Yellow
        return
    }

    $summary = @(
        $recordArray |
            Group-Object -Property Classification |
            Sort-Object Name |
            ForEach-Object {
                [pscustomobject]@{
                    Classification = $_.Name
                    Count = $_.Count
                    Percent = [math]::Round(($_.Count / $total) * 100, 2)
                }
            }
    )

    $summary | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "Total evaluated: $total"
}

Write-Host '=====================================' -ForegroundColor Cyan
Write-Host '  Verifying Hybrid Sync Status' -ForegroundColor Cyan
Write-Host '=====================================' -ForegroundColor Cyan
Write-Host ''

Write-Log("Starting hybrid sync verification. Mode=$Mode, SyncSource=$SyncSource, ThresholdDays=$OutOfSyncDaysThreshold")

New-DirectoryIfMissing -Path $OutputFolderPath

try {
    Connect-MgGraphWithRequirements -GraphModuleNames @('Microsoft.Graph.Users', 'Microsoft.Graph.Identity.DirectoryManagement') -RequiredScopes @('User.Read.All', 'Organization.Read.All')
}
catch {
    $graphSetupError = "Stopping script because Graph prerequisites failed: $($_.Exception.Message)"
    Write-Log($graphSetupError)
    Write-Error $graphSetupError -ErrorAction Stop
}

$mgContext = Get-MgContext
$tenantId = if ($null -ne $mgContext -and -not [string]::IsNullOrWhiteSpace("$($mgContext.TenantId)")) { "$($mgContext.TenantId)" } else { 'UnknownTenant' }

$properties = @(
    'id','userType','displayName','userPrincipalName','createdDateTime',
    'creationType','externalUserState','accountEnabled',
    'ServiceProvisioningErrors','onPremisesSyncEnabled',
    'onPremisesDistinguishedName','onPremisesDomainName',
    'onPremisesSamAccountName','onPremisesSecurityIdentifier',
    'onPremisesImmutableId','onPremisesLastSyncDateTime',
    'onPremisesUserPrincipalName',
    'onPremisesExtensionAttributes'
)

$requiredCachedUserProperties = @(
    'Id','UserType','DisplayName','UserPrincipalName','CreatedDateTime',
    'CreationType','ExternalUserState','AccountEnabled',
    'ServiceProvisioningErrors','OnPremisesSyncEnabled',
    'OnPremisesDistinguishedName','OnPremisesDomainName',
    'OnPremisesSamAccountName','OnPremisesSecurityIdentifier',
    'OnPremisesImmutableId','OnPremisesLastSyncDateTime',
    'OnPremisesUserPrincipalName',
    'OnPremisesExtensionAttributes'
)

$usersResult = Get-UsersFromGraphOrCache -UseCachedGraphResults:$UseCachedGraphResults -Properties $properties -RequiredCachedUserProperties $requiredCachedUserProperties
$users = @($usersResult.Users)
$Global:users = $users

Write-Log("Total users loaded for evaluation: $($users.Count)")

$normalizedDomains = Get-NormalizedStringSet -Values $UpnDomains
$normalizedExtensionAttribute1Values = Get-NormalizedStringSet -Values $ExtensionAttribute1Values

$runTimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
$runTimestampFileSafe = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')

$evaluations = @()
$records = @()

foreach ($user in $users) {
    $filterResult = Test-UserMatchesFilters -User $user `
                                            -NormalizedUpnDomains $normalizedDomains `
                                            -NormalizedExtensionAttribute1Values $normalizedExtensionAttribute1Values `
                                            -IncludeAccountStatus $IncludeAccountStatus `
                                            -IncludeGuests $IncludeGuests.IsPresent

    if (-not $filterResult.IsMatch) {
        continue
    }

    $evaluation = Get-SyncStatusEvaluation -User $user -OutOfSyncDaysThreshold $OutOfSyncDaysThreshold -SyncSourceOverride $SyncSource
    $evaluations += $evaluation

    $record = New-SyncStatusCsvRecord -RunTimestampUtc $runTimestampUtc `
                                      -Mode $Mode `
                                      -TenantId $tenantId `
                                      -User $user `
                                      -Evaluation $evaluation `
                                      -OutOfSyncDaysThreshold $OutOfSyncDaysThreshold `
                                      -FilterMatchedBy $filterResult.FilterMatchedBy `
                                      -IncludedByGuestSwitch $IncludeGuests.IsPresent

    $records += $record
}

$recordsToExport = switch ($Mode) {
    'Audit' { @($records) }
    'Troubleshoot' { @($records | Where-Object { $_.Classification -in @('OutOfSync', 'SyncedWithErrors', 'Unknown') }) }
    'Health' { @($records) }
}

if ($recordsToExport.Count -eq 0) {
    Write-Log('No records matched the selected mode and filters. No CSV file was generated.')
    Write-Host 'No records matched the selected mode and filters.' -ForegroundColor Yellow
    return
}

$detailCsvPath = Join-Path $OutputFolderPath ("$Mode-$runTimestampFileSafe.csv")
$recordsToExport | Export-Csv -Path $detailCsvPath -NoTypeInformation -Encoding UTF8
Write-Log("Detailed CSV exported: $detailCsvPath")

Show-ClassificationSummary -Records $recordsToExport -Title "Mode summary: $Mode"

if ($Mode -eq 'Health') {
    $healthSummary = New-HealthSummaryRecord -RunTimestampUtc $runTimestampUtc -TenantId $tenantId -Evaluations $evaluations -OutOfSyncDaysThreshold $OutOfSyncDaysThreshold
    $healthSummaryCsvPath = Join-Path $OutputFolderPath ("Health-Summary-$runTimestampFileSafe.csv")
    @($healthSummary) | Export-Csv -Path $healthSummaryCsvPath -NoTypeInformation -Encoding UTF8
    Write-Log("Health summary CSV exported: $healthSummaryCsvPath")

    Write-Host 'Health summary:' -ForegroundColor Cyan
    @($healthSummary) | Format-Table -AutoSize | Out-String | Write-Host
}

Write-Host ''
Write-Host "Done. Output file: $detailCsvPath" -ForegroundColor Green
