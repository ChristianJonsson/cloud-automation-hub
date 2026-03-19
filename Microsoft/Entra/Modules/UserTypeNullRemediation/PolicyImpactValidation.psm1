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

function Get-PolicyImpactScopeMatrix {
    [CmdletBinding()]
    param()

    return @(
        [pscustomobject]@{ Area = 'ConditionalAccess'; RequiredScopes = @('Policy.Read.All'); IsCritical = $true },
        [pscustomobject]@{ Area = 'DynamicGroups'; RequiredScopes = @('Directory.Read.All'); IsCritical = $true },
        [pscustomobject]@{ Area = 'GroupAndAppAssignments'; RequiredScopes = @('Directory.Read.All'); IsCritical = $true },
        [pscustomobject]@{ Area = 'EntitlementManagement'; RequiredScopes = @('EntitlementManagement.Read.All'); IsCritical = $true },
        [pscustomobject]@{ Area = 'DirectoryRoleAssignments'; RequiredScopes = @('RoleManagement.Read.Directory'); IsCritical = $true },
        [pscustomobject]@{ Area = 'LicensingHeuristics'; RequiredScopes = @('Organization.Read.All'); IsCritical = $false },
        [pscustomobject]@{ Area = 'TeamsExchangeHeuristics'; RequiredScopes = @('Team.ReadBasic.All', 'Mail.ReadBasic.All'); IsCritical = $false }
    )
}

function Test-PolicyImpactPrerequisites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$IsPreviewMode,

        [ValidateSet('Strict', 'Balanced', 'Permissive')]
        [string]$StrictnessMode = 'Balanced'
    )

    $results = @()

    $results += Test-GraphProbe -AreaName 'ConditionalAccess' -RequiredScopes @('Policy.Read.All') -IsCritical $true -ProbeScript {
        if (-not (Get-Command -Name Get-MgIdentityConditionalAccessPolicy -ErrorAction SilentlyContinue)) {
            throw "Command 'Get-MgIdentityConditionalAccessPolicy' not found. Install/import Microsoft.Graph.Identity.SignIns."
        }

        Get-MgIdentityConditionalAccessPolicy -Top 1 -ErrorAction Stop | Out-Null
    }

    $results += Test-GraphProbe -AreaName 'DynamicGroups' -RequiredScopes @('Directory.Read.All') -IsCritical $true -ProbeScript {
        if (-not (Get-Command -Name Get-MgGroup -ErrorAction SilentlyContinue)) {
            throw "Command 'Get-MgGroup' not found. Install/import Microsoft.Graph.Groups."
        }

        Get-MgGroup -Top 1 -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -Property Id -ErrorAction Stop | Out-Null
    }

    $results += Test-GraphProbe -AreaName 'GroupAndAppAssignments' -RequiredScopes @('Directory.Read.All') -IsCritical $true -ProbeScript {
        if (-not (Get-Command -Name Get-MgUser -ErrorAction SilentlyContinue)) {
            throw "Command 'Get-MgUser' not found. Install/import Microsoft.Graph.Users."
        }

        $probeUser = Get-MgUser -Top 1 -Property Id -ErrorAction Stop
        if ($probeUser) {
            Get-MgUserMemberOf -UserId $probeUser.Id -Top 1 -ErrorAction Stop | Out-Null
            Get-MgUserAppRoleAssignment -UserId $probeUser.Id -Top 1 -ErrorAction Stop | Out-Null
        }
    }

    $results += Test-GraphProbe -AreaName 'EntitlementManagement' -RequiredScopes @('EntitlementManagement.Read.All') -IsCritical $true -ProbeScript {
        if (-not (Get-Command -Name Get-MgEntitlementManagementAccessPackage -ErrorAction SilentlyContinue)) {
            throw "Command 'Get-MgEntitlementManagementAccessPackage' not found. Install/import Microsoft.Graph.Identity.Governance."
        }

        Get-MgEntitlementManagementAccessPackage -Top 1 -ErrorAction Stop | Out-Null
    }

    $results += Test-GraphProbe -AreaName 'DirectoryRoleAssignments' -RequiredScopes @('RoleManagement.Read.Directory') -IsCritical $true -ProbeScript {
        if (-not (Get-Command -Name Get-MgRoleManagementDirectoryRoleAssignment -ErrorAction SilentlyContinue)) {
            throw "Command 'Get-MgRoleManagementDirectoryRoleAssignment' not found. Install/import Microsoft.Graph.Identity.Governance."
        }

        Get-MgRoleManagementDirectoryRoleAssignment -Top 1 -ErrorAction Stop | Out-Null
    }

    $results += Test-GraphProbe -AreaName 'LicensingHeuristics' -RequiredScopes @('Organization.Read.All') -IsCritical $false -ProbeScript {
        if (-not (Get-Command -Name Get-MgSubscribedSku -ErrorAction SilentlyContinue)) {
            throw "Command 'Get-MgSubscribedSku' not found. Install/import Microsoft.Graph.Identity.DirectoryManagement."
        }

        Get-MgSubscribedSku -ErrorAction Stop | Select-Object -First 1 | Out-Null
    }

    # Teams/Exchange checks are advisory only in v1.
    $results += [pscustomobject]@{
        Area = 'TeamsExchangeHeuristics'
        RequiredScopes = 'Team.ReadBasic.All; Mail.ReadBasic.All'
        IsCritical = $false
        Status = 'AdvisoryOnly'
        Message = 'No direct probe in v1. Review Teams/Exchange access impact manually when applicable.'
    }

    $criticalFailures = @($results | Where-Object { $_.IsCritical -and $_.Status -ne 'Available' })
    $criticalBlockingFindings = @($criticalFailures)

    # Permissive mode allows write execution when only entitlement visibility is missing.
    if (-not $IsPreviewMode -and $StrictnessMode -eq 'Permissive') {
        $criticalBlockingFindings = @($criticalBlockingFindings | Where-Object { $_.Area -ne 'EntitlementManagement' })
    }

    $criticalNonBlockingFindings = @($criticalFailures | Where-Object { $_.Area -notin @($criticalBlockingFindings | ForEach-Object { $_.Area }) })
    $advisories = @($results | Where-Object { -not $_.IsCritical -and $_.Status -ne 'Available' })

    $advisoryBlockingFindings = @()
    if (-not $IsPreviewMode -and $StrictnessMode -eq 'Strict') {
        $advisoryBlockingFindings = @($advisories | Where-Object { $_.Status -eq 'Unavailable' })
    }

    $canProceed = $IsPreviewMode -or (($criticalBlockingFindings.Count -eq 0) -and ($advisoryBlockingFindings.Count -eq 0))

    $blockingAreas = @()
    $blockingAreas += @($criticalBlockingFindings | ForEach-Object { $_.Area })
    $blockingAreas += @($advisoryBlockingFindings | ForEach-Object { $_.Area })
    $blockingAreas = Get-UniqueStringArray -InputArray $blockingAreas

    $blockingMessage = ''
    if ($blockingAreas.Count -gt 0) {
        $blockingMessage = "Blocking policy-impact prerequisite failures ($StrictnessMode): $($blockingAreas -join ', ')."
    }

    $summary = Format-PolicyPreflightSummary -Result $results -IsPreviewMode:$IsPreviewMode -StrictnessMode $StrictnessMode

    return [pscustomobject]@{
        Results = $results
        CriticalFailures = $criticalFailures
        CriticalBlockingFindings = $criticalBlockingFindings
        CriticalNonBlockingFindings = $criticalNonBlockingFindings
        AdvisoryFindings = $advisories
        AdvisoryBlockingFindings = $advisoryBlockingFindings
        CanProceed = $canProceed
        BlockingMessage = $blockingMessage
        StrictnessMode = $StrictnessMode
        Summary = $summary
    }
}

function Format-PolicyPreflightSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Result,

        [Parameter(Mandatory = $true)]
        [bool]$IsPreviewMode,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Strict', 'Balanced', 'Permissive')]
        [string]$StrictnessMode
    )

    $critical = @($Result | Where-Object { $_.IsCritical })
    $advisory = @($Result | Where-Object { -not $_.IsCritical })
    $criticalFailed = @($critical | Where-Object { $_.Status -ne 'Available' })
    $criticalFailedForDecision = @($criticalFailed)
    if (-not $IsPreviewMode -and $StrictnessMode -eq 'Permissive') {
        $criticalFailedForDecision = @($criticalFailedForDecision | Where-Object { $_.Area -ne 'EntitlementManagement' })
    }
    $advisoryFailed = @($advisory | Where-Object { $_.Status -eq 'Unavailable' })

    $decision = 'PASS'
    if (-not $IsPreviewMode) {
        if ($criticalFailedForDecision.Count -gt 0) {
            $decision = 'BLOCK'
        }
        elseif ($StrictnessMode -eq 'Strict' -and $advisoryFailed.Count -gt 0) {
            $decision = 'BLOCK'
        }
    }

    $failedAreas = @($criticalFailed + $advisoryFailed | ForEach-Object { $_.Area })
    $failedAreaText = if ($failedAreas.Count -gt 0) {
        ($failedAreas | Sort-Object -Unique) -join ', '
    }
    else {
        'None'
    }

    $runMode = if ($IsPreviewMode) { 'Preview' } else { 'Write' }

    return "PolicyPreflight Mode=$runMode Strictness=$StrictnessMode Critical=$($critical.Count - $criticalFailed.Count)/$($critical.Count) Advisory=$($advisory.Count - $advisoryFailed.Count)/$($advisory.Count) Decision=$decision FailedAreas=$failedAreaText"
}

function Initialize-PolicyImpactContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$PrerequisiteResult
    )

    $areaStatus = @{}
    foreach ($result in @($PrerequisiteResult.Results)) {
        $areaStatus[$result.Area] = $result.Status
    }

    $conditionalAccessPolicies = @()
    $dynamicGroups = @()
    $directoryRoleAssignments = @()

    if ($areaStatus['ConditionalAccess'] -eq 'Available') {
        try {
            $conditionalAccessPolicies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
        }
        catch {
            $areaStatus['ConditionalAccess'] = 'Unavailable'
        }
    }

    if ($areaStatus['DynamicGroups'] -eq 'Available') {
        try {
            $dynamicGroups = @(Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -Property Id,DisplayName,MembershipRule -All -ErrorAction Stop)
        }
        catch {
            $areaStatus['DynamicGroups'] = 'Unavailable'
        }
    }

    if ($areaStatus['DirectoryRoleAssignments'] -eq 'Available') {
        try {
            $directoryRoleAssignments = @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop)
        }
        catch {
            $areaStatus['DirectoryRoleAssignments'] = 'Unavailable'
        }
    }

    return [pscustomobject]@{
        PrerequisiteResult = $PrerequisiteResult
        AreaStatus = $areaStatus
        ConditionalAccessPolicies = $conditionalAccessPolicies
        DynamicGroups = $dynamicGroups
        DirectoryRoleAssignments = $directoryRoleAssignments
    }
}

function Get-UserPolicyImpact {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [string]$ProposedUserType = '',

        [Parameter(Mandatory = $true)]
        [object]$PolicyContext
    )

    $groupMemberships = @()
    $appRoleAssignments = @()
    $entitlementAssignments = @()

    if ($PolicyContext.AreaStatus['GroupAndAppAssignments'] -eq 'Available') {
        try {
            $groupMemberships = @(Get-MgUserMemberOf -UserId $User.Id -All -ErrorAction Stop)
            $appRoleAssignments = @(Get-MgUserAppRoleAssignment -UserId $User.Id -All -ErrorAction Stop)
        }
        catch {
            $PolicyContext.AreaStatus['GroupAndAppAssignments'] = 'Unavailable'
        }
    }

    if ($PolicyContext.AreaStatus['EntitlementManagement'] -eq 'Available') {
        try {
            $entitlementAssignments = @(Get-MgEntitlementManagementAssignment -Filter "targetId eq '$($User.Id)'" -All -ErrorAction Stop)
        }
        catch {
            $PolicyContext.AreaStatus['EntitlementManagement'] = 'Unavailable'
        }
    }

    $memberGroupIds = @($groupMemberships | ForEach-Object { if ($_.Id) { "$($_.Id)" } })
    $memberGroupIds = Get-UniqueStringArray -InputArray $memberGroupIds

    $caMatches = @()
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

        $isIncluded = ($includeUsers -contains 'All') -or ($includeUsers -contains $User.Id) -or (@($includeGroups | Where-Object { $_ -in $memberGroupIds }).Count -gt 0)
        $isExcluded = ($excludeUsers -contains $User.Id) -or (@($excludeGroups | Where-Object { $_ -in $memberGroupIds }).Count -gt 0)

        if ($isIncluded -and -not $isExcluded) {
            $caMatches += $policy
        }
    }

    $dynamicRuleMatches = @()
    foreach ($group in @($PolicyContext.DynamicGroups)) {
        $membershipRule = "$(Get-ObjectValue -InputObject $group -PropertyName 'MembershipRule')"
        if ([string]::IsNullOrWhiteSpace($membershipRule)) {
            continue
        }

        if ($membershipRule -match '(?i)user\.userType|userType') {
            $dynamicRuleMatches += $group
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($ProposedUserType) -and $membershipRule -match [regex]::Escape($ProposedUserType)) {
            $dynamicRuleMatches += $group
        }
    }

    $directoryRoleMatches = @($PolicyContext.DirectoryRoleAssignments | Where-Object { "$($_.PrincipalId)" -eq "$($User.Id)" })

    $coverageLevel = 'Full'
    $coverageFailures = @($PolicyContext.AreaStatus.GetEnumerator() | Where-Object { $_.Value -ne 'Available' -and $_.Value -ne 'AdvisoryOnly' })
    if ($coverageFailures.Count -gt 0) {
        $coverageLevel = 'Partial'
    }

    $riskLevel = 'None'
    if ($directoryRoleMatches.Count -gt 0 -or $caMatches.Count -gt 0) {
        $riskLevel = 'High'
    }
    elseif ($entitlementAssignments.Count -gt 0 -or $appRoleAssignments.Count -gt 0) {
        $riskLevel = 'Medium'
    }
    elseif ($dynamicRuleMatches.Count -gt 0 -or $groupMemberships.Count -gt 0) {
        $riskLevel = 'Low'
    }

    $blockingFlags = @()
    if ($caMatches.Count -gt 0) { $blockingFlags += 'ConditionalAccessMatch' }
    if ($directoryRoleMatches.Count -gt 0) { $blockingFlags += 'DirectoryRoleAssignment' }
    if ($entitlementAssignments.Count -gt 0) { $blockingFlags += 'EntitlementAssignment' }

    $summary = "CA=$($caMatches.Count); DynamicRules=$($dynamicRuleMatches.Count); GroupMemberships=$($groupMemberships.Count); AppRoles=$($appRoleAssignments.Count); Entitlements=$($entitlementAssignments.Count); DirectoryRoles=$($directoryRoleMatches.Count); Risk=$riskLevel; Coverage=$coverageLevel"

    return [pscustomobject]@{
        CoverageLevel = $coverageLevel
        RiskLevel = $riskLevel
        ConditionalAccessCount = $caMatches.Count
        DynamicGroupRuleCount = $dynamicRuleMatches.Count
        GroupMembershipCount = $groupMemberships.Count
        AppRoleAssignmentCount = $appRoleAssignments.Count
        DirectoryRoleAssignmentCount = $directoryRoleMatches.Count
        EntitlementAssignmentCount = $entitlementAssignments.Count
        BlockingFlags = ($blockingFlags -join '; ')
        Summary = $summary
    }
}

Export-ModuleMember -Function Get-PolicyImpactScopeMatrix, Test-PolicyImpactPrerequisites, Format-PolicyPreflightSummary, Initialize-PolicyImpactContext, Get-UserPolicyImpact
