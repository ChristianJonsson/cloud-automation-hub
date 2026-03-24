# Per-user evaluator: ConditionalAccess policy area.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.
# Requires $UserGroupIds (from GroupAndAppAssignments) to evaluate group-based conditions.

function Invoke-ConditionalAccessUserImpact {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ProposedUserType,

        [Parameter(Mandatory = $true)]
        [object]$PolicyContext,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$UserGroupIds,

        [Parameter(Mandatory = $true)]
        [hashtable]$UserAreaStatus
    )

    $caMatches = @()

    if ($UserAreaStatus['ConditionalAccess'] -ne 'Available') {
        return [pscustomobject]@{ Matches = $caMatches; MatchCount = 0 }
    }

    foreach ($policy in @($PolicyContext.ConditionalAccessPolicies)) {
        $conditions = Get-ObjectValue -InputObject $policy -PropertyName 'Conditions'
        $usersCondition = Get-ObjectValue -InputObject $conditions -PropertyName 'Users'
        if ($null -eq $usersCondition) {
            continue
        }

        $includeUsers = Get-PolicyConditionList -ConditionObject $usersCondition -PropertyName 'IncludeUsers'
        $excludeUsers = Get-PolicyConditionList -ConditionObject $usersCondition -PropertyName 'ExcludeUsers'
        $includeGroups = Get-PolicyConditionList -ConditionObject $usersCondition -PropertyName 'IncludeGroups'
        $excludeGroups = Get-PolicyConditionList -ConditionObject $usersCondition -PropertyName 'ExcludeGroups'

        $isIncluded = ($includeUsers -contains 'All') -or ($includeUsers -contains $User.Id) -or (@($includeGroups | Where-Object { $_ -in $UserGroupIds }).Count -gt 0)
        $isExcluded = ($excludeUsers -contains $User.Id) -or (@($excludeGroups | Where-Object { $_ -in $UserGroupIds }).Count -gt 0)

        if ($isIncluded -and -not $isExcluded) {
            $caMatches += $policy
        }
    }

    $matchDetails = @(
        $caMatches |
            ForEach-Object {
                [pscustomobject]@{
                    Id = "$(Get-ObjectValue -InputObject $_ -PropertyName 'Id')"
                    DisplayName = "$(Get-ObjectValue -InputObject $_ -PropertyName 'DisplayName')"
                }
            } |
            ForEach-Object {
                if ([string]::IsNullOrWhiteSpace($_.DisplayName)) {
                    $_.DisplayName = "[UnnamedPolicy:$($_.Id)]"
                }
                $_
            }
    )

    return [pscustomobject]@{
        Matches = $caMatches
        MatchCount = $caMatches.Count
        MatchDetails = $matchDetails
    }
}
