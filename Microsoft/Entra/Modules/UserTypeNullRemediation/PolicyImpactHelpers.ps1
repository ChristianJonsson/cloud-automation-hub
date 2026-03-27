# Shared internal helpers for the PolicyImpact module family.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.

function Test-GraphProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AreaName,

        [Parameter(Mandatory = $true)]
        [string[]]$RequiredScopes,

        [Parameter(Mandatory = $true)]
        [bool]$IsCritical,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ProbeScript
    )

    try {
        & $ProbeScript
        return [pscustomobject]@{
            Area = $AreaName
            RequiredScopes = ($RequiredScopes -join '; ')
            IsCritical = $IsCritical
            Status = 'Available'
            Message = 'Probe succeeded.'
        }
    }
    catch {
        return [pscustomobject]@{
            Area = $AreaName
            RequiredScopes = ($RequiredScopes -join '; ')
            IsCritical = $IsCritical
            Status = 'Unavailable'
            Message = $_.Exception.Message
        }
    }
}

function Write-PolicyImpactLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )

    if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Message "${Level}: $Message" -NoConsole
    }
}

function Get-ObjectValue {
    param(
        [object]$InputObject,
        [string]$PropertyName
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject.PSObject.Properties.Name -contains $PropertyName) {
        return $InputObject.$PropertyName
    }

    if ($InputObject.PSObject.Properties.Name -contains 'AdditionalProperties') {
        $ap = $InputObject.AdditionalProperties
        $dictionary = $ap -as [System.Collections.IDictionary]
        if ($null -ne $dictionary) {
            if (@($dictionary.Keys) -contains $PropertyName) {
                return $dictionary[$PropertyName]
            }
        }
    }

    return $null
}

function Convert-ToStringArray {
    param([object]$InputValue)

    if ($null -eq $InputValue) {
        return @()
    }

    if ($InputValue -is [string]) {
        if ([string]::IsNullOrWhiteSpace($InputValue)) {
            return @()
        }

        return @($InputValue)
    }

    if ($InputValue -is [System.Collections.IEnumerable]) {
        $items = @()
        foreach ($item in $InputValue) {
            if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace("$item")) {
                $items += "$item"
            }
        }

        return @($items)
    }

    return @("$InputValue")
}

function Get-UniqueStringArray {
    param([string[]]$InputArray = @())

    return @($InputArray | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
}

function Get-PolicyConditionList {
    param(
        [object]$ConditionObject,
        [string]$PropertyName
    )

    return Get-UniqueStringArray -InputArray (Convert-ToStringArray -InputValue (Get-ObjectValue -InputObject $ConditionObject -PropertyName $PropertyName))
}

function Convert-ImpactDirectionToReportLabel {
    param([string]$Direction)

    switch -Regex ($Direction) {
        '^WouldStartApplying$' { return 'StartsApplying' }
        '^WouldStopApplying$' { return 'StopsApplying' }
        '^WouldJoin$' { return 'GainsAccess' }
        '^WouldLeave$' { return 'LosesAccess' }
        '^WouldGain$' { return 'GainsAccess' }
        '^WouldLose$' { return 'LosesAccess' }
        '^NoChange$' { return 'NoMaterialChange' }
        '^RequiresManualReview$' { return 'ManualReview' }
        '^ManualReview$' { return 'ManualReview' }
        default {
            if ([string]::IsNullOrWhiteSpace($Direction)) {
                return 'NoMaterialChange'
            }

            return "$Direction"
        }
    }
}

function Invoke-PolicyAreaGraphWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Operation,

        [Parameter(Mandatory = $true)]
        [string]$OperationName,

        [ValidateRange(1, 5)]
        [int]$MaxAttempts = 3,

        [ValidateRange(1, 30)]
        [int]$InitialDelaySeconds = 2,

        [ValidateRange(1, 60)]
        [int]$MaxDelaySeconds = 16
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $Operation
        }
        catch {
            $errorMessage = "$($_.Exception.Message)".ToLowerInvariant()
            $isTransient = (
                $errorMessage.Contains('too many requests') -or
                $errorMessage.Contains('429') -or
                $errorMessage.Contains('timed out') -or
                $errorMessage.Contains('temporarily unavailable') -or
                $errorMessage.Contains('service unavailable') -or
                $errorMessage.Contains('internal server error') -or
                $errorMessage.Contains('bad gateway') -or
                $errorMessage.Contains('gateway timeout')
            )

            if (-not $isTransient -or $attempt -ge $MaxAttempts) {
                throw
            }

            $delaySeconds = [Math]::Min($MaxDelaySeconds, $InitialDelaySeconds * [int][Math]::Pow(2, $attempt - 1))
            Write-PolicyImpactLog -Level 'WARNING' -Message "Transient Graph error during '$OperationName' (attempt $attempt of $MaxAttempts): $($_.Exception.Message). Retrying in $delaySeconds s."
            Start-Sleep -Seconds $delaySeconds
        }
    }

    throw "Unexpected retry loop exit for '$OperationName'."
}

function Convert-StateToPolicyStateLabel {
    param([bool]$State)

    if ($State) {
        return 'Applies'
    }

    return 'DoesNotApply'
}
