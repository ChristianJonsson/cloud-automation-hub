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
        return [pscustomobject]@{
            RuleMatches = $dynamicRuleMatches
            RuleMatchCount = 0
            RuleDetails = @()
        }
    }

    foreach ($group in @($PolicyContext.DynamicGroups)) {
        $membershipRule = "$(Get-ObjectValue -InputObject $group -PropertyName 'MembershipRule')"
        if ([string]::IsNullOrWhiteSpace($membershipRule)) {
            continue
        }

        $usedMembershipListFallback = $false

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
            Write-PolicyImpactLog -Level 'WARNING' -Message "Dynamic membership evaluation failed for user $($User.UserPrincipalName) ($($User.Id)) in group $($group.DisplayName) ($($group.Id)); falling back to group membership list for current membership: $($_.Exception.Message)"
        }

        if (-not $evaluateSuccess) {
            $groupId = "$(Get-ObjectValue -InputObject $group -PropertyName 'Id')"
            $isCurrentMember = $groupId -in $UserGroupIds
            $evaluateSuccess = $true
            $usedMembershipListFallback = $true
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
            'GainsAccess'
        }
        elseif ($isCurrentMember -and -not $estimatedPostChangeMember) {
            'LosesAccess'
        }
        elseif ($isCurrentMember -and $estimatedPostChangeMember) {
            'NoMaterialChange'
        }
        else {
            'ManualReview'
        }

        # Only report groups where a meaningful impact is expected.
        if ($impactDirection -ne 'NoMaterialChange') {
            $dynamicRuleMatches += [pscustomobject]@{
                Group           = $group
                ImpactDirection = $impactDirection
                IsCurrentMember = $isCurrentMember
                IsPostChangeMember = $estimatedPostChangeMember
                UsedMembershipListFallback = $usedMembershipListFallback
            }
        }
    }

    $ruleDetails = @(
        $dynamicRuleMatches |
            ForEach-Object {
                [pscustomobject]@{
                    GroupId = "$(Get-ObjectValue -InputObject $_.Group -PropertyName 'Id')"
                    GroupName = "$(Get-ObjectValue -InputObject $_.Group -PropertyName 'DisplayName')"
                    ImpactDirection = "$($_.ImpactDirection)"
                    CurrentState = if ([bool]$_.IsCurrentMember) { 'Applies' } else { 'DoesNotApply' }
                    PostChangeState = if ([bool]$_.IsPostChangeMember) { 'Applies' } else { 'DoesNotApply' }
                    Confidence = if ($_.ImpactDirection -eq 'ManualReview') { 'Low' } else { 'Medium' }
                    EvidenceSource = if ([bool]$_.UsedMembershipListFallback) { 'DynamicGroupMembershipList' } else { 'DynamicGroupMembershipRule' }
                    IsCurrentMember = [bool]$_.IsCurrentMember
                    IsPostChangeMember = [bool]$_.IsPostChangeMember
                }
            } |
            ForEach-Object {
                if ([string]::IsNullOrWhiteSpace($_.GroupName)) {
                    $_.GroupName = "[UnnamedGroup:$($_.GroupId)]"
                }
                $_
            }
    )

    return [pscustomobject]@{
        RuleMatches = $dynamicRuleMatches
        RuleMatchCount = $dynamicRuleMatches.Count
        RuleDetails = $ruleDetails
    }
}
