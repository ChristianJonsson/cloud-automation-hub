function Get-NonEmptyString {
    param([object]$Value)

    $stringValue = "$Value".Trim()
    if ([string]::IsNullOrWhiteSpace($stringValue)) {
        return $null
    }

    return $stringValue
}

function Get-ExtensionAttributeValue {
    param(
        [object]$OnPremisesExtensionAttributes,
        [ValidateRange(1, 15)]
        [int]$Index
    )

    if ($null -eq $OnPremisesExtensionAttributes) {
        return $null
    }

    $propertyName = "ExtensionAttribute$Index"
    return $OnPremisesExtensionAttributes.$propertyName
}

function Test-HasAnyOnPremisesExtensionAttributeValue {
    param([object]$OnPremisesExtensionAttributes)

    if ($null -eq $OnPremisesExtensionAttributes) {
        return $false
    }

    foreach ($index in 1..15) {
        $value = Get-ExtensionAttributeValue -OnPremisesExtensionAttributes $OnPremisesExtensionAttributes -Index $index
        if (-not [string]::IsNullOrWhiteSpace("$value")) {
            return $true
        }
    }

    return $false
}

function Get-ServiceProvisioningErrorsInfo {
    param([object]$ServiceProvisioningErrors)

    $errors = @($ServiceProvisioningErrors)
    if ($errors.Count -eq 0) {
        return [pscustomobject]@{
            HasErrors = $false
            Summary = ''
            RawJson = ''
        }
    }

    $summaryParts = foreach ($errorItem in $errors) {
        $category = Get-NonEmptyString -Value $errorItem.Category
        $isResolved = Get-NonEmptyString -Value $errorItem.IsResolved
        $createdDateTime = Get-NonEmptyString -Value $errorItem.CreatedDateTime
        $detail = Get-NonEmptyString -Value $errorItem.ServiceInstance

        @($category, $isResolved, $createdDateTime, $detail) -join '|'
    }

    return [pscustomobject]@{
        HasErrors = $true
        Summary = ($summaryParts -join '; ')
        RawJson = ($errors | ConvertTo-Json -Depth 8 -Compress)
    }
}

function Get-SyncSignalSummary {
    param([object]$User)

    $signals = @()

    if ($User.OnPremisesSyncEnabled -eq $true) {
        $signals += 'OnPremisesSyncEnabled=true'
    }

    if (-not [string]::IsNullOrWhiteSpace("$($User.OnPremisesImmutableId)")) {
        $signals += 'OnPremisesImmutableId present'
    }

    if (-not [string]::IsNullOrWhiteSpace("$($User.OnPremisesSecurityIdentifier)")) {
        $signals += 'OnPremisesSecurityIdentifier present'
    }

    if (-not [string]::IsNullOrWhiteSpace("$($User.OnPremisesDistinguishedName)")) {
        $signals += 'OnPremisesDistinguishedName present'
    }

    return [pscustomobject]@{
        IsSyncedSignalPresent = ($signals.Count -gt 0)
        SyncSignalsSummary = ($signals -join '; ')
    }
}

function Get-SyncSourceInference {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Auto', 'EntraConnect', 'EntraCloudSync')]
        [string]$SyncSourceOverride,

        [Parameter(Mandatory = $true)]
        [bool]$IsSyncedSignalPresent
    )

    if ($SyncSourceOverride -ne 'Auto') {
        return [pscustomobject]@{
            SyncSource = $SyncSourceOverride
            SyncSourceConfidence = 'Explicit'
        }
    }

    if (-not $IsSyncedSignalPresent) {
        return [pscustomobject]@{
            SyncSource = 'Unknown'
            SyncSourceConfidence = 'Unknown'
        }
    }

    $hasOnPremisesExtensionAttributeValues = Test-HasAnyOnPremisesExtensionAttributeValue -OnPremisesExtensionAttributes $User.OnPremisesExtensionAttributes
    if ($hasOnPremisesExtensionAttributeValues) {
        return [pscustomobject]@{
            SyncSource = 'EntraConnect'
            SyncSourceConfidence = 'InferredHigh'
        }
    }

    return [pscustomobject]@{
        SyncSource = 'EntraCloudSync'
        SyncSourceConfidence = 'InferredLow'
    }
}

function Get-SyncAgeDays {
    param([object]$OnPremisesLastSyncDateTime)

    if ($null -eq $OnPremisesLastSyncDateTime) {
        return $null
    }

    $syncTimestamp = $null
    if ($OnPremisesLastSyncDateTime -is [datetime]) {
        $syncTimestamp = $OnPremisesLastSyncDateTime
    }
    else {
        $parsed = [datetime]::MinValue
        if ([datetime]::TryParse("$OnPremisesLastSyncDateTime", [ref]$parsed)) {
            $syncTimestamp = $parsed
        }
    }

    if ($null -eq $syncTimestamp) {
        return $null
    }

    $utcNow = (Get-Date).ToUniversalTime()
    $syncUtc = $syncTimestamp.ToUniversalTime()

    if ($syncUtc -gt $utcNow) {
        return 0
    }

    return [math]::Floor(($utcNow - $syncUtc).TotalDays)
}

function Get-SyncStatusEvaluation {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 3650)]
        [int]$OutOfSyncDaysThreshold,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Auto', 'EntraConnect', 'EntraCloudSync')]
        [string]$SyncSourceOverride
    )

    $signalInfo = Get-SyncSignalSummary -User $User
    $errorInfo = Get-ServiceProvisioningErrorsInfo -ServiceProvisioningErrors $User.ServiceProvisioningErrors
    $syncAgeDays = Get-SyncAgeDays -OnPremisesLastSyncDateTime $User.OnPremisesLastSyncDateTime

    $isOutOfSync = $false
    if ($signalInfo.IsSyncedSignalPresent) {
        $isOutOfSync = ($null -eq $syncAgeDays) -or ($syncAgeDays -gt $OutOfSyncDaysThreshold)
    }

    $classification = 'Unknown'
    $reason = 'User could not be evaluated with available properties.'

    if ($signalInfo.IsSyncedSignalPresent -and $errorInfo.HasErrors) {
        $classification = 'SyncedWithErrors'
        $reason = 'Synced identity signals are present and service provisioning errors were detected.'
    }
    elseif ($signalInfo.IsSyncedSignalPresent -and $isOutOfSync) {
        $classification = 'OutOfSync'
        $reason = 'Synced identity signals are present, but sync timestamp is missing or older than threshold.'
    }
    elseif ($signalInfo.IsSyncedSignalPresent) {
        $classification = 'Synced'
        $reason = 'Synced identity signals are present and sync timestamp is within threshold.'
    }
    elseif (-not $signalInfo.IsSyncedSignalPresent) {
        $classification = 'CloudOnly'
        $reason = 'No synced identity signals detected.'
    }

    $sourceInfo = Get-SyncSourceInference -User $User -SyncSourceOverride $SyncSourceOverride -IsSyncedSignalPresent $signalInfo.IsSyncedSignalPresent

    return [pscustomobject]@{
        Classification = $classification
        Reason = $reason
        IsSyncedSignalPresent = $signalInfo.IsSyncedSignalPresent
        SyncSignalsSummary = $signalInfo.SyncSignalsSummary
        HasServiceProvisioningErrors = $errorInfo.HasErrors
        ServiceProvisioningErrorsSummary = $errorInfo.Summary
        RawServiceProvisioningErrorsJson = $errorInfo.RawJson
        SyncAgeDays = $syncAgeDays
        IsOutOfSync = $isOutOfSync
        IsRecentSync = ($signalInfo.IsSyncedSignalPresent -and $null -ne $syncAgeDays -and $syncAgeDays -le $OutOfSyncDaysThreshold)
        SyncSource = $sourceInfo.SyncSource
        SyncSourceConfidence = $sourceInfo.SyncSourceConfidence
    }
}

function Get-SyncAgeBand {
    param([object]$SyncAgeDays)

    if ($null -eq $SyncAgeDays) {
        return 'NoTimestamp'
    }

    $days = [int]$SyncAgeDays
    if ($days -le 1) { return '0-1d' }
    if ($days -le 7) { return '2-7d' }
    if ($days -le 30) { return '8-30d' }
    return '31d+'
}

function Get-TroubleshootDiagnostic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Classification,

        [Parameter(Mandatory = $true)]
        [bool]$HasServiceProvisioningErrors,

        [Parameter(Mandatory = $true)]
        [bool]$IsOutOfSync
    )

    if ($HasServiceProvisioningErrors -or $Classification -eq 'SyncedWithErrors') {
        return [pscustomobject]@{
            DiagnosticCategory = 'ProvisioningErrors'
            SuggestedAction = 'Review ServiceProvisioningErrors details and investigate provisioning connectors and attribute flows.'
        }
    }

    if ($IsOutOfSync -or $Classification -eq 'OutOfSync') {
        return [pscustomobject]@{
            DiagnosticCategory = 'StaleOrMissingSyncTimestamp'
            SuggestedAction = 'Verify Entra sync cycle health and connector agent status, then confirm user object sync scope.'
        }
    }

    if ($Classification -eq 'Unknown') {
        return [pscustomobject]@{
            DiagnosticCategory = 'InsufficientSignals'
            SuggestedAction = 'Validate required user properties are available and re-run with full Graph properties set.'
        }
    }

    return [pscustomobject]@{
        DiagnosticCategory = 'None'
        SuggestedAction = 'No action required for this record in troubleshoot mode.'
    }
}

function Get-HealthBucket {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Classification,

        [Parameter(Mandatory = $true)]
        [bool]$IsRecentSync
    )

    if ($Classification -eq 'Synced' -and $IsRecentSync) {
        return 'Healthy'
    }

    if ($Classification -in @('OutOfSync', 'SyncedWithErrors')) {
        return 'NeedsAttention'
    }

    if ($Classification -eq 'CloudOnly') {
        return 'CloudOnly'
    }

    if ($Classification -eq 'Synced') {
        return 'Healthy'
    }

    return 'Unknown'
}

function New-SyncStatusCsvRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunTimestampUtc,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Audit', 'Troubleshoot', 'Health')]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [object]$Evaluation,

        [Parameter(Mandatory = $true)]
        [int]$OutOfSyncDaysThreshold,

        [Parameter(Mandatory = $true)]
        [string]$FilterMatchedBy,

        [Parameter(Mandatory = $true)]
        [bool]$IncludedByGuestSwitch
    )

    $record = [ordered]@{
        RunTimestampUtc = $RunTimestampUtc
        Mode = $Mode
        TenantId = $TenantId
        UserId = $User.Id
        UserPrincipalName = $User.UserPrincipalName
        DisplayName = $User.DisplayName
        AccountEnabled = $User.AccountEnabled
        UserType = $User.UserType
        Classification = $Evaluation.Classification
        SyncSource = $Evaluation.SyncSource
        SyncSourceConfidence = $Evaluation.SyncSourceConfidence
        IsSyncedSignalPresent = $Evaluation.IsSyncedSignalPresent
        OnPremisesSyncEnabled = $User.OnPremisesSyncEnabled
        OnPremisesLastSyncDateTime = $User.OnPremisesLastSyncDateTime
        SyncAgeDays = $Evaluation.SyncAgeDays
        OutOfSyncDaysThreshold = $OutOfSyncDaysThreshold
        HasServiceProvisioningErrors = $Evaluation.HasServiceProvisioningErrors
        ServiceProvisioningErrorsSummary = $Evaluation.ServiceProvisioningErrorsSummary
        OnPremisesImmutableId = $User.OnPremisesImmutableId
        OnPremisesSecurityIdentifier = $User.OnPremisesSecurityIdentifier
        OnPremisesDistinguishedName = $User.OnPremisesDistinguishedName
        OnPremisesSamAccountName = $User.OnPremisesSamAccountName
        OnPremisesDomainName = $User.OnPremisesDomainName
        OnPremisesUserPrincipalName = $User.OnPremisesUserPrincipalName
        CreatedDateTime = $User.CreatedDateTime
        ExtensionAttribute1 = (Get-ExtensionAttributeValue -OnPremisesExtensionAttributes $User.OnPremisesExtensionAttributes -Index 1)
        FilterMatchedBy = $FilterMatchedBy
        Reason = $Evaluation.Reason
    }

    switch ($Mode) {
        'Audit' {
            $record['ClassificationBucket'] = $Evaluation.Classification
            $record['IncludedByGuestSwitch'] = $IncludedByGuestSwitch
        }
        'Troubleshoot' {
            $troubleshootInfo = Get-TroubleshootDiagnostic -Classification $Evaluation.Classification `
                                                           -HasServiceProvisioningErrors $Evaluation.HasServiceProvisioningErrors `
                                                           -IsOutOfSync $Evaluation.IsOutOfSync
            $record['DiagnosticCategory'] = $troubleshootInfo.DiagnosticCategory
            $record['SuggestedAction'] = $troubleshootInfo.SuggestedAction
            $record['RawServiceProvisioningErrorsJson'] = $Evaluation.RawServiceProvisioningErrorsJson
            $record['SyncSignalsSummary'] = $Evaluation.SyncSignalsSummary
        }
        'Health' {
            $record['HealthBucket'] = Get-HealthBucket -Classification $Evaluation.Classification -IsRecentSync $Evaluation.IsRecentSync
            $record['IsRecentSync'] = $Evaluation.IsRecentSync
            $record['SyncAgeBand'] = Get-SyncAgeBand -SyncAgeDays $Evaluation.SyncAgeDays
        }
    }

    return [pscustomobject]$record
}

function New-HealthSummaryRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RunTimestampUtc,

        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [object[]]$Evaluations,

        [Parameter(Mandatory = $true)]
        [int]$OutOfSyncDaysThreshold
    )

    $evaluationArray = @($Evaluations)
    $total = $evaluationArray.Count

    $totalSynced = @($evaluationArray | Where-Object { $_.Classification -eq 'Synced' }).Count
    $totalOutOfSync = @($evaluationArray | Where-Object { $_.Classification -eq 'OutOfSync' }).Count
    $totalSyncedWithErrors = @($evaluationArray | Where-Object { $_.Classification -eq 'SyncedWithErrors' }).Count
    $totalCloudOnly = @($evaluationArray | Where-Object { $_.Classification -eq 'CloudOnly' }).Count
    $totalUnknown = @($evaluationArray | Where-Object { $_.Classification -eq 'Unknown' }).Count

    $syncedPopulation = $totalSynced + $totalOutOfSync + $totalSyncedWithErrors
    $recentSynced = @($evaluationArray | Where-Object {
        ($_.Classification -in @('Synced', 'OutOfSync', 'SyncedWithErrors')) -and $_.IsRecentSync
    }).Count

    $percentSynced = if ($total -eq 0) { 0 } else { [math]::Round(($syncedPopulation / $total) * 100, 2) }
    $percentOutOfSyncOfSynced = if ($syncedPopulation -eq 0) { 0 } else { [math]::Round(($totalOutOfSync / $syncedPopulation) * 100, 2) }
    $percentRecentSyncOfSynced = if ($syncedPopulation -eq 0) { 0 } else { [math]::Round(($recentSynced / $syncedPopulation) * 100, 2) }

    return [pscustomobject]@{
        RunTimestampUtc = $RunTimestampUtc
        TenantId = $TenantId
        TotalEvaluatedUsers = $total
        TotalSynced = $totalSynced
        TotalOutOfSync = $totalOutOfSync
        TotalSyncedWithErrors = $totalSyncedWithErrors
        TotalCloudOnly = $totalCloudOnly
        TotalUnknown = $totalUnknown
        PercentSynced = $percentSynced
        PercentOutOfSyncOfSynced = $percentOutOfSyncOfSynced
        PercentRecentSyncOfSynced = $percentRecentSyncOfSynced
        ThresholdDays = $OutOfSyncDaysThreshold
    }
}

Export-ModuleMember -Function Get-ExtensionAttributeValue, Get-SyncStatusEvaluation, New-SyncStatusCsvRecord, New-HealthSummaryRecord