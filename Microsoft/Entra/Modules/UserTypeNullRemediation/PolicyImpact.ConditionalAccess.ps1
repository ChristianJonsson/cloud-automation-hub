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
    $matchDetails = @()

    if ($UserAreaStatus['ConditionalAccess'] -ne 'Available') {
        return [pscustomobject]@{ Matches = $caMatches; MatchCount = 0; MatchDetails = @() }
    }

    $currentIsGuest = ("$($User.UserType)" -eq 'Guest')
    $proposedUserTypeResolved = if ([string]::IsNullOrWhiteSpace($ProposedUserType)) { "$($User.UserType)" } else { "$ProposedUserType" }
    $postChangeIsGuest = ($proposedUserTypeResolved -eq 'Guest')

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
        $includeGuestExternal = Get-PolicyConditionList -ConditionObject $usersCondition -PropertyName 'IncludeGuestsOrExternalUsers'
        $excludeGuestExternal = Get-PolicyConditionList -ConditionObject $usersCondition -PropertyName 'ExcludeGuestsOrExternalUsers'

        $currentGuestIncluded = ($currentIsGuest -and $includeGuestExternal.Count -gt 0)
        $postGuestIncluded = ($postChangeIsGuest -and $includeGuestExternal.Count -gt 0)
        $currentGuestExcluded = ($currentIsGuest -and $excludeGuestExternal.Count -gt 0)
        $postGuestExcluded = ($postChangeIsGuest -and $excludeGuestExternal.Count -gt 0)

        $isCurrentlyIncluded =
            ($includeUsers -contains 'All') -or
            ($includeUsers -contains $User.Id) -or
            (@($includeGroups | Where-Object { $_ -in $UserGroupIds }).Count -gt 0) -or
            $currentGuestIncluded

        $isPostChangeIncluded =
            ($includeUsers -contains 'All') -or
            ($includeUsers -contains $User.Id) -or
            (@($includeGroups | Where-Object { $_ -in $UserGroupIds }).Count -gt 0) -or
            $postGuestIncluded

        $isCurrentlyExcluded =
            ($excludeUsers -contains $User.Id) -or
            (@($excludeGroups | Where-Object { $_ -in $UserGroupIds }).Count -gt 0) -or
            $currentGuestExcluded

        $isPostChangeExcluded =
            ($excludeUsers -contains $User.Id) -or
            (@($excludeGroups | Where-Object { $_ -in $UserGroupIds }).Count -gt 0) -or
            $postGuestExcluded

        $currentlyApplies = ($isCurrentlyIncluded -and -not $isCurrentlyExcluded)
        $postChangeApplies = ($isPostChangeIncluded -and -not $isPostChangeExcluded)

        $direction = if (-not $currentlyApplies -and $postChangeApplies) {
            'WouldStartApplying'
        }
        elseif ($currentlyApplies -and -not $postChangeApplies) {
            'WouldStopApplying'
        }
        else {
            'NoChange'
        }

        if ($currentlyApplies -or $postChangeApplies) {
            $caMatches += $policy

            $policyId = "$(Get-ObjectValue -InputObject $policy -PropertyName 'Id')"
            $policyName = "$(Get-ObjectValue -InputObject $policy -PropertyName 'DisplayName')"
            if ([string]::IsNullOrWhiteSpace($policyName)) {
                $policyName = "[UnnamedPolicy:$policyId]"
            }

            $matchDetails += [pscustomobject]@{
                Id = $policyId
                DisplayName = $policyName
                CurrentState = Convert-StateToPolicyStateLabel -State $currentlyApplies
                PostChangeState = Convert-StateToPolicyStateLabel -State $postChangeApplies
                ImpactDirection = Convert-ImpactDirectionToReportLabel -Direction $direction
                Confidence = 'High'
                EvidenceSource = 'ConditionalAccessPolicy.Users'
            }
        }
    }

    return [pscustomobject]@{
        Matches = $caMatches
        MatchCount = @($matchDetails | Where-Object { $_.ImpactDirection -ne 'NoMaterialChange' }).Count
        MatchDetails = $matchDetails
    }
}
