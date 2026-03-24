# Per-user evaluator: DynamicGroups policy area.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.

function Invoke-DynamicGroupsUserImpact {
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

    $dynamicRuleMatches = @()

    if ($UserAreaStatus['DynamicGroups'] -ne 'Available') {
        return [pscustomobject]@{ RuleMatches = $dynamicRuleMatches; RuleMatchCount = 0 }
    }

    foreach ($group in @($PolicyContext.DynamicGroups)) {
        $membershipRule = "$(Get-ObjectValue -InputObject $group -PropertyName 'MembershipRule')"
        if ([string]::IsNullOrWhiteSpace($membershipRule)) {
            continue
        }

        $refersToUserType = $membershipRule -match '(?i)user\.userType|userType'
        $refersToProposedType = -not [string]::IsNullOrWhiteSpace($ProposedUserType) -and
                                $membershipRule -match [regex]::Escape($ProposedUserType)

        if (-not $refersToUserType -and -not $refersToProposedType) {
            continue
        }

        # Evaluate current membership for this specific user via the Graph evaluate endpoint.
        $isCurrentMember = $false
        $evaluateSuccess = $false
        try {
            $evalResult = Invoke-MgGraphRequest -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/groups/$($group.Id)/evaluateDynamicMembership" `
                -Body @{ memberId = $User.Id } `
                -ErrorAction Stop
            $isCurrentMember = [bool]$evalResult.membershipRuleEvaluationResult
            $evaluateSuccess = $true
        }
        catch {
            Write-PolicyImpactLog -Level 'WARNING' -Message "Dynamic membership evaluation requires manual review for user $($User.UserPrincipalName) ($($User.Id)) in group $($group.DisplayName) ($($group.Id)): $($_.Exception.Message)"
        }

        if (-not $evaluateSuccess) {
            $dynamicRuleMatches += [pscustomobject]@{
                Group           = $group
                ImpactDirection = 'RequiresManualReview'
                IsCurrentMember = $false
            }
            continue
        }

        # Estimate post-change membership using simple rule pattern extraction.
        $estimatedPostChangeMember = $isCurrentMember
        if ($membershipRule -match '(?i)user\.userType\s*-eq\s*"([^"]+)"') {
            $estimatedPostChangeMember = ($Matches[1] -eq $ProposedUserType)
        }
        elseif ($membershipRule -match '(?i)user\.userType\s*-ne\s*"([^"]+)"') {
            $estimatedPostChangeMember = ($Matches[1] -ne $ProposedUserType)
        }
        elseif ($refersToProposedType) {
            $estimatedPostChangeMember = $true
        }

        $impactDirection = if (-not $isCurrentMember -and $estimatedPostChangeMember) {
            'WouldJoin'
        }
        elseif ($isCurrentMember -and -not $estimatedPostChangeMember) {
            'WouldLeave'
        }
        elseif ($isCurrentMember -and $estimatedPostChangeMember) {
            'NoChange'
        }
        else {
            'RequiresManualReview'
        }

        # Only report groups where a meaningful impact is expected.
        if ($impactDirection -ne 'NoChange') {
            $dynamicRuleMatches += [pscustomobject]@{
                Group           = $group
                ImpactDirection = $impactDirection
                IsCurrentMember = $isCurrentMember
            }
        }
    }

    return [pscustomobject]@{ RuleMatches = $dynamicRuleMatches; RuleMatchCount = $dynamicRuleMatches.Count }
}
