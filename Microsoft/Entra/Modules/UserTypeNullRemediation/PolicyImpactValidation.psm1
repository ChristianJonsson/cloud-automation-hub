# Dot-source shared helpers and per-area evaluators.
. "$PSScriptRoot\PolicyImpactHelpers.ps1"
. "$PSScriptRoot\PolicyImpact.GroupAndAppAssignments.ps1"
. "$PSScriptRoot\PolicyImpact.EntitlementManagement.ps1"
. "$PSScriptRoot\PolicyImpact.ConditionalAccess.ps1"
. "$PSScriptRoot\PolicyImpact.DynamicGroups.ps1"
. "$PSScriptRoot\PolicyImpact.DirectoryRoleAssignments.ps1"
. "$PSScriptRoot\PolicyImpact.LicensingHeuristics.ps1"
. "$PSScriptRoot\PolicyImpact.TeamsExchangeHeuristics.ps1"

function Get-PolicyImpactScopeMatrix {
    [CmdletBinding()]
    param()

    return @(
        [pscustomobject]@{ Area = 'ConditionalAccess'; RequiredScopes = @('Policy.Read.All'); IsCritical = $true },
        [pscustomobject]@{ Area = 'DynamicGroups'; RequiredScopes = @('Directory.Read.All'); IsCritical = $true },
        [pscustomobject]@{ Area = 'GroupAndAppAssignments'; RequiredScopes = @('Directory.Read.All'); IsCritical = $true },
        [pscustomobject]@{ Area = 'EntitlementManagement'; RequiredScopes = @('EntitlementManagement.Read.All'); IsCritical = $true },
        [pscustomobject]@{ Area = 'DirectoryRoleAssignments'; RequiredScopes = @('RoleManagement.Read.Directory'); IsCritical = $true },
        [pscustomobject]@{ Area = 'LicensingHeuristics'; RequiredScopes = @('Organization.Read.All'); IsCritical = $false }
        # [pscustomobject]@{ Area = 'TeamsExchangeHeuristics'; RequiredScopes = @('Team.ReadBasic.All', 'Mail.ReadBasic.All'); IsCritical = $false }
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

    # $results += Test-GraphProbe -AreaName 'TeamsExchangeHeuristics' -RequiredScopes @('Team.ReadBasic.All', 'Mail.ReadBasic.All') -IsCritical $false -ProbeScript {
    #     $probeResult = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users?`$top=1&`$select=id" -ErrorAction Stop
    #     $firstUser = @($probeResult.value)[0]
    #     if ($firstUser) {
    #         Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($firstUser.id)/joinedTeams?`$top=1&`$select=id" -ErrorAction Stop | Out-Null
    #         Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($firstUser.id)/mailFolders?`$top=1&`$select=id" -ErrorAction Stop | Out-Null
    #     }
    # }

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
            Write-PolicyImpactLog -Level 'WARNING' -Message "Failed to load Conditional Access policies into policy context: $($_.Exception.Message)"
        }
    }

    if ($areaStatus['DynamicGroups'] -eq 'Available') {
        try {
            $dynamicGroups = @(Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')" -Property Id,DisplayName,MembershipRule -All -ErrorAction Stop)
        }
        catch {
            $areaStatus['DynamicGroups'] = 'Unavailable'
            Write-PolicyImpactLog -Level 'WARNING' -Message "Failed to load dynamic groups into policy context: $($_.Exception.Message)"
        }
    }

    if ($areaStatus['DirectoryRoleAssignments'] -eq 'Available') {
        try {
            $directoryRoleAssignments = @(Get-MgRoleManagementDirectoryRoleAssignment -All -ErrorAction Stop)
        }
        catch {
            $areaStatus['DirectoryRoleAssignments'] = 'Unavailable'
            Write-PolicyImpactLog -Level 'WARNING' -Message "Failed to load directory role assignments into policy context: $($_.Exception.Message)"
        }
    }

    $areaStatusStr = @($areaStatus.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
    Write-PolicyImpactLog -Message "Initialized policy context: CAPolicies=$($conditionalAccessPolicies.Count); DynamicGroups=$($dynamicGroups.Count); DirectoryRoleAssignments=$($directoryRoleAssignments.Count); AreaStatus=$areaStatusStr"

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

    $userAreaStatus = @{}
    foreach ($entry in $PolicyContext.AreaStatus.GetEnumerator()) {
        $userAreaStatus[$entry.Key] = $entry.Value
    }

    # GroupAndAppAssignments must run first — group IDs are passed to ConditionalAccess and DynamicGroups.
    $groupData       = Invoke-GroupAndAppAssignmentsUserImpact   -User $User -UserAreaStatus $userAreaStatus
    $entitlementData = Invoke-EntitlementManagementUserImpact    -User $User -UserAreaStatus $userAreaStatus
    $teamsData       = Invoke-TeamsExchangeHeuristicsUserImpact  -User $User -UserAreaStatus $userAreaStatus

    $memberGroupIds  = @(Get-UniqueStringArray -InputArray @($groupData.GroupMemberships | ForEach-Object { if ($_.Id) { "$($_.Id)" } }))
    if ($null -eq $memberGroupIds) { $memberGroupIds = @() }

    $caData          = Invoke-ConditionalAccessUserImpact        -User $User -ProposedUserType $ProposedUserType -PolicyContext $PolicyContext -UserGroupIds $memberGroupIds -UserAreaStatus $userAreaStatus
    $dynamicData     = Invoke-DynamicGroupsUserImpact            -User $User -ProposedUserType $ProposedUserType -PolicyContext $PolicyContext -UserGroupIds $memberGroupIds -UserAreaStatus $userAreaStatus
    $roleData        = Invoke-DirectoryRoleAssignmentsUserImpact -User $User -PolicyContext $PolicyContext -UserAreaStatus $userAreaStatus

    $coverageLevel = 'Full'
    $coverageFailures = @($userAreaStatus.GetEnumerator() | Where-Object { $_.Value -ne 'Available' -and $_.Value -ne 'AdvisoryOnly' })
    if ($coverageFailures.Count -gt 0) {
        $coverageLevel = 'Partial'
    }

    $riskLevel = 'None'
    if ($roleData.MatchCount -gt 0 -or $caData.MatchCount -gt 0) {
        $riskLevel = 'High'
    }
    elseif ($entitlementData.AssignmentCount -gt 0 -or $groupData.AppRoleCount -gt 0) {
        $riskLevel = 'Medium'
    }
    elseif ($dynamicData.RuleMatchCount -gt 0 -or $groupData.GroupMembershipCount -gt 0) {
        $riskLevel = 'Low'
    }
    elseif ($teamsData.TeamsCount -gt 0) {
        $riskLevel = 'Low'
    }

    $blockingFlags = @()
    if ($caData.MatchCount -gt 0) { $blockingFlags += 'ConditionalAccessMatch' }
    if ($roleData.MatchCount -gt 0) { $blockingFlags += 'DirectoryRoleAssignment' }
    if ($entitlementData.AssignmentCount -gt 0) { $blockingFlags += 'EntitlementAssignment' }

    $coverageFailureAreas = @($coverageFailures | ForEach-Object { $_.Key } | Sort-Object -Unique)
    $coverageFailureText = if ($coverageFailureAreas.Count -gt 0) { $coverageFailureAreas -join ',' } else { 'None' }

    $summary = "CA=$($caData.MatchCount); DynamicRules=$($dynamicData.RuleMatchCount); GroupMemberships=$($groupData.GroupMembershipCount); AppRoles=$($groupData.AppRoleCount); Entitlements=$($entitlementData.AssignmentCount); DirectoryRoles=$($roleData.MatchCount); Teams=$($teamsData.TeamsCount); Mailbox=$($teamsData.HasMailbox); Risk=$riskLevel; Coverage=$coverageLevel; CoverageFailures=$coverageFailureText"

    Write-PolicyImpactLog -Message "Policy impact evaluated for $($User.UserPrincipalName) ($($User.Id)): $summary"

    return [pscustomobject]@{
        CoverageLevel                = $coverageLevel
        RiskLevel                    = $riskLevel
        ConditionalAccessCount       = $caData.MatchCount
        DynamicGroupRuleCount        = $dynamicData.RuleMatchCount
        GroupMembershipCount         = $groupData.GroupMembershipCount
        AppRoleAssignmentCount       = $groupData.AppRoleCount
        DirectoryRoleAssignmentCount = $roleData.MatchCount
        EntitlementAssignmentCount   = $entitlementData.AssignmentCount
        TeamsCount                   = $teamsData.TeamsCount
        HasMailbox                   = $teamsData.HasMailbox
        BlockingFlags                = ($blockingFlags -join '; ')
        CoverageFailureAreas         = ($coverageFailureAreas -join '; ')
        Summary                      = $summary
    }
}

Export-ModuleMember -Function Get-PolicyImpactScopeMatrix, Test-PolicyImpactPrerequisites, Format-PolicyPreflightSummary, Initialize-PolicyImpactContext, Get-UserPolicyImpact
