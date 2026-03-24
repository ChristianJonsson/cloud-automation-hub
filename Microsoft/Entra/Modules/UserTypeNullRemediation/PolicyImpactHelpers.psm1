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
        if ($ap -is [System.Collections.IDictionary] -and $ap.Contains($PropertyName)) {
            return $ap[$PropertyName]
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
