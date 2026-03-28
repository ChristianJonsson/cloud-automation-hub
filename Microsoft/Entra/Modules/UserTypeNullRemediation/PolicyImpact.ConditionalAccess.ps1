# Per-user evaluator: ConditionalAccess policy area.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.
# Requires $UserGroupIds (from GroupAndAppAssignments) to evaluate group-based conditions.

function Get-GuestOrExternalTypeString {
    param([object]$GuestOrExternalObj)

    if ($null -eq $GuestOrExternalObj) {
        return ''
    }

    $value = Get-ObjectValue -InputObject $GuestOrExternalObj -PropertyName 'GuestOrExternalUserTypes'
    return if ($null -ne $value) { "$value" } else { '' }
}

function Test-UserMatchesGuestOrExternalTypes {
    <#
    .SYNOPSIS
        Returns $true if the given UserType matches one of the GuestOrExternalUserTypes values.
    .DESCRIPTION
        Maps Entra UserType ('Guest', 'Member') to the corresponding conditionalAccessGuestOrExternalUserTypes
        enum values used in Conditional Access policy conditions. The GuestOrExternalUserTypes field is a
        comma-separated string (e.g. "b2bCollaborationGuest,b2bCollaborationMember").

        Mappings:
          Guest  -> b2bCollaborationGuest, internalGuest
          Member -> b2bCollaborationMember
    #>
    param(
        [string]$UserType,
        [string]$GuestOrExternalUserTypes
    )

    if ([string]::IsNullOrWhiteSpace($UserType) -or [string]::IsNullOrWhiteSpace($GuestOrExternalUserTypes)) {
        return $false
    }

    $types = @($GuestOrExternalUserTypes -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })

    switch ($UserType) {
        'Guest'  { return ($types -contains 'b2bcollaborationguest' -or $types -contains 'internalguest') }
        'Member' { return ($types -contains 'b2bcollaborationmember') }
        default  { return $false }
    }
}

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

    $currentUserTypeResolved = if ([string]::IsNullOrWhiteSpace("$($User.UserType)")) { '' } else { "$($User.UserType)" }
    $proposedUserTypeResolved = if ([string]::IsNullOrWhiteSpace($ProposedUserType)) { $currentUserTypeResolved } else { "$ProposedUserType" }

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

        $includeGuestTypes = Get-GuestOrExternalTypeString -GuestOrExternalObj (Get-ObjectValue -InputObject $usersCondition -PropertyName 'IncludeGuestsOrExternalUsers')
        $excludeGuestTypes = Get-GuestOrExternalTypeString -GuestOrExternalObj (Get-ObjectValue -InputObject $usersCondition -PropertyName 'ExcludeGuestsOrExternalUsers')

        $currentGuestIncluded = Test-UserMatchesGuestOrExternalTypes -UserType $currentUserTypeResolved -GuestOrExternalUserTypes $includeGuestTypes
        $postGuestIncluded    = Test-UserMatchesGuestOrExternalTypes -UserType $proposedUserTypeResolved -GuestOrExternalUserTypes $includeGuestTypes
        $currentGuestExcluded = Test-UserMatchesGuestOrExternalTypes -UserType $currentUserTypeResolved -GuestOrExternalUserTypes $excludeGuestTypes
        $postGuestExcluded    = Test-UserMatchesGuestOrExternalTypes -UserType $proposedUserTypeResolved -GuestOrExternalUserTypes $excludeGuestTypes

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

            $policyState = "$(Get-ObjectValue -InputObject $policy -PropertyName 'State')"

            $matchDetails += [pscustomobject]@{
                Id = $policyId
                DisplayName = $policyName
                CurrentState = Convert-StateToPolicyStateLabel -State $currentlyApplies
                PostChangeState = Convert-StateToPolicyStateLabel -State $postChangeApplies
                ImpactDirection = Convert-ImpactDirectionToReportLabel -Direction $direction
                PolicyState = $policyState
                IncludeGuestOrExternalUserTypes = $includeGuestTypes
                ExcludeGuestOrExternalUserTypes = $excludeGuestTypes
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
