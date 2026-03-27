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
    $directoryRoleDefinitionNameMap = @{}
    $accessPackageNameMap = @{}

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

            if (Get-Command -Name Get-MgRoleManagementDirectoryRoleDefinition -ErrorAction SilentlyContinue) {
                $roleDefinitions = @(Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop)
                foreach ($roleDefinition in $roleDefinitions) {
                    $roleDefinitionId = "$(Get-ObjectValue -InputObject $roleDefinition -PropertyName 'Id')"
                    if ([string]::IsNullOrWhiteSpace($roleDefinitionId)) {
                        continue
                    }

                    $roleDisplayName = "$(Get-ObjectValue -InputObject $roleDefinition -PropertyName 'DisplayName')"
                    if ([string]::IsNullOrWhiteSpace($roleDisplayName)) {
                        $roleDisplayName = "[RoleDefinition:$roleDefinitionId]"
                    }

                    $directoryRoleDefinitionNameMap[$roleDefinitionId] = $roleDisplayName
                }
            }
        }
        catch {
            $areaStatus['DirectoryRoleAssignments'] = 'Unavailable'
            Write-PolicyImpactLog -Level 'WARNING' -Message "Failed to load directory role assignments into policy context: $($_.Exception.Message)"
        }
    }

    if ($areaStatus['EntitlementManagement'] -eq 'Available') {
        try {
            if (Get-Command -Name Get-MgEntitlementManagementAccessPackage -ErrorAction SilentlyContinue) {
                $accessPackages = @(Get-MgEntitlementManagementAccessPackage -All -ErrorAction Stop)
                foreach ($accessPackage in $accessPackages) {
                    $accessPackageId = "$(Get-ObjectValue -InputObject $accessPackage -PropertyName 'Id')"
                    if ([string]::IsNullOrWhiteSpace($accessPackageId)) {
                        continue
                    }

                    $accessPackageName = "$(Get-ObjectValue -InputObject $accessPackage -PropertyName 'DisplayName')"
                    if ([string]::IsNullOrWhiteSpace($accessPackageName)) {
                        $accessPackageName = "[AccessPackage:$accessPackageId]"
                    }

                    $accessPackageNameMap[$accessPackageId] = $accessPackageName
                }
            }
        }
        catch {
            Write-PolicyImpactLog -Level 'WARNING' -Message "Failed to load entitlement access package names into policy context: $($_.Exception.Message)"
        }
    }

    $subscribedSkuMap = @{}
    if ($areaStatus['LicensingHeuristics'] -eq 'Available') {
        try {
            if (Get-Command -Name Get-MgSubscribedSku -ErrorAction SilentlyContinue) {
                $subscribedSkus = @(Get-MgSubscribedSku -All -ErrorAction Stop)
                foreach ($sku in $subscribedSkus) {
                    $skuId = "$(Get-ObjectValue -InputObject $sku -PropertyName 'SkuId')"
                    if ([string]::IsNullOrWhiteSpace($skuId)) { continue }
                    $skuPartNumber = "$(Get-ObjectValue -InputObject $sku -PropertyName 'SkuPartNumber')"
                    $subscribedSkuMap[$skuId] = if ([string]::IsNullOrWhiteSpace($skuPartNumber)) { "[Sku:$skuId]" } else { $skuPartNumber }
                }
            }
        }
        catch {
            Write-PolicyImpactLog -Level 'WARNING' -Message "Failed to load subscribed SKU names into policy context: $($_.Exception.Message)"
        }
    }

    $areaStatusStr = @($areaStatus.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '
    Write-PolicyImpactLog -Message "Initialized policy context: CAPolicies=$($conditionalAccessPolicies.Count); DynamicGroups=$($dynamicGroups.Count); DirectoryRoleAssignments=$($directoryRoleAssignments.Count); RoleDefinitions=$($directoryRoleDefinitionNameMap.Count); AccessPackages=$($accessPackageNameMap.Count); SubscribedSkus=$($subscribedSkuMap.Count); AreaStatus=$areaStatusStr"

    return [pscustomobject]@{
        PrerequisiteResult = $PrerequisiteResult
        AreaStatus = $areaStatus
        ConditionalAccessPolicies = $conditionalAccessPolicies
        DynamicGroups = $dynamicGroups
        DirectoryRoleAssignments = $directoryRoleAssignments
        DirectoryRoleDefinitionNameMap = $directoryRoleDefinitionNameMap
        AccessPackageNameMap = $accessPackageNameMap
        SubscribedSkuMap = $subscribedSkuMap
    }
}

function Convert-PolicyImpactDetailToJson {
    param([object[]]$Details = @())

    $detailArray = @($Details)
    if ($detailArray.Count -eq 0) {
        return '[]'
    }

    # Use -InputObject (not pipeline) to preserve the array wrapper when there is exactly one element.
    # Piping a single object through ConvertTo-Json outputs a plain object {} rather than an array [{}].
    return (ConvertTo-Json -InputObject $detailArray -Depth 8 -Compress)
}

function Join-UniqueDetailText {
    param([string[]]$Values = @())

    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($items.Count -eq 0) {
        return ''
    }

    return ($items -join '; ')
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
    $entitlementData = Invoke-EntitlementManagementUserImpact    -User $User -PolicyContext $PolicyContext -UserAreaStatus $userAreaStatus
    $teamsData       = Invoke-TeamsExchangeHeuristicsUserImpact  -User $User -UserAreaStatus $userAreaStatus
    $licensingData   = Invoke-LicensingHeuristicsUserImpact      -User $User -ProposedUserType $ProposedUserType -UserAreaStatus $userAreaStatus -PolicyContext $PolicyContext

    if ($licensingData.ImpactDirection -eq 'GainsAccess') {
        Write-PolicyImpactLog -Level 'INFO' -Message "Licensing note for $($User.UserPrincipalName) ($($User.Id)): user currently has no assigned licenses and is proposed as Member. No specific license name is available — a license will need to be assigned manually after the userType change. See LicensingImpactNames='[NeedsLicenseAssignment]' in the export."
    }

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
    elseif ($entitlementData.AssignmentCount -gt 0 -or $groupData.AppRoleCount -gt 0 -or $licensingData.ImpactCount -gt 0) {
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

    $conditionalAccessPolicyNames = Join-UniqueDetailText -Values @($caData.MatchDetails | ForEach-Object { $_.DisplayName })
    $conditionalAccessDirections = Join-UniqueDetailText -Values @($caData.MatchDetails | ForEach-Object { $_.ImpactDirection })
    $conditionalAccessPolicyTransitions = Join-UniqueDetailText -Values @($caData.MatchDetails | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_.ImpactDirection)) {
            $_.DisplayName
        }
        else {
            "$($_.DisplayName) [$($_.ImpactDirection)]"
        }
    })
    $dynamicGroupNames = Join-UniqueDetailText -Values @($dynamicData.RuleDetails | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_.ImpactDirection)) { $_.GroupName } else { "$($_.GroupName) [$($_.ImpactDirection)]" }
    })
    $dynamicGroupDirections = Join-UniqueDetailText -Values @($dynamicData.RuleDetails | ForEach-Object { $_.ImpactDirection })
    $groupMembershipNames = Join-UniqueDetailText -Values @($groupData.GroupMembershipDetails | ForEach-Object { $_.GroupName })
    $appRoleAssignmentNames = Join-UniqueDetailText -Values @($groupData.AppRoleDetails | ForEach-Object { $_.ResourceDisplayName })
    $directoryRoleNames = Join-UniqueDetailText -Values @($roleData.MatchDetails | ForEach-Object { $_.RoleName })
    $entitlementPackageNames = Join-UniqueDetailText -Values @($entitlementData.AssignmentDetails | ForEach-Object { $_.AccessPackageName })
    $licensingImpactDirections = Join-UniqueDetailText -Values @($licensingData.ImpactDetails | ForEach-Object { $_.ImpactDirection })
    $licensingImpactNames = Join-UniqueDetailText -Values @($licensingData.ImpactDetails | ForEach-Object { $_.SkuName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $licensingAssignedNames = "$($licensingData.AssignedLicenseNames)"

    $conditionalAccessPolicyDetailsJson = Convert-PolicyImpactDetailToJson -Details @($caData.MatchDetails)
    $dynamicGroupImpactDetailsJson = Convert-PolicyImpactDetailToJson -Details @($dynamicData.RuleDetails)
    $groupMembershipDetailsJson = Convert-PolicyImpactDetailToJson -Details @($groupData.GroupMembershipDetails)
    $appRoleAssignmentDetailsJson = Convert-PolicyImpactDetailToJson -Details @($groupData.AppRoleDetails)
    $directoryRoleDetailsJson = Convert-PolicyImpactDetailToJson -Details @($roleData.MatchDetails)
    $entitlementPackageDetailsJson = Convert-PolicyImpactDetailToJson -Details @($entitlementData.AssignmentDetails)
    $licensingImpactDetailsJson = Convert-PolicyImpactDetailToJson -Details @($licensingData.ImpactDetails)

    $summary = "CA=$($caData.MatchCount); DynamicRules=$($dynamicData.RuleMatchCount); GroupMemberships=$($groupData.GroupMembershipCount); AppRoles=$($groupData.AppRoleCount); Entitlements=$($entitlementData.AssignmentCount); LicensingImpacts=$($licensingData.ImpactCount); DirectoryRoles=$($roleData.MatchCount); Teams=$($teamsData.TeamsCount); Mailbox=$($teamsData.HasMailbox); Risk=$riskLevel; BlockingFlags=$($blockingFlags -join '; '); Coverage=$coverageLevel; CoverageFailures=$coverageFailureText"

    Write-PolicyImpactLog -Message "Policy impact evaluated for $($User.UserPrincipalName) ($($User.Id)): $summary"

    return [pscustomobject]@{
        CoverageLevel                = $coverageLevel
        RiskLevel                    = $riskLevel
        ConditionalAccessCount       = $caData.MatchCount
        ConditionalAccessPolicyNames = $conditionalAccessPolicyNames
        ConditionalAccessDirections  = $conditionalAccessDirections
        ConditionalAccessPolicyTransitions = $conditionalAccessPolicyTransitions
        ConditionalAccessPolicyDetailsJson = $conditionalAccessPolicyDetailsJson
        DynamicGroupRuleCount        = $dynamicData.RuleMatchCount
        DynamicGroupNames            = $dynamicGroupNames
        DynamicGroupImpactDirections = $dynamicGroupDirections
        DynamicGroupImpactDetailsJson = $dynamicGroupImpactDetailsJson
        GroupMembershipCount         = $groupData.GroupMembershipCount
        GroupMembershipNames         = $groupMembershipNames
        GroupMembershipDetailsJson   = $groupMembershipDetailsJson
        AppRoleAssignmentCount       = $groupData.AppRoleCount
        AppRoleAssignmentNames       = $appRoleAssignmentNames
        AppRoleAssignmentDetailsJson = $appRoleAssignmentDetailsJson
        DirectoryRoleAssignmentCount = $roleData.MatchCount
        DirectoryRoleNames           = $directoryRoleNames
        DirectoryRoleDetailsJson     = $directoryRoleDetailsJson
        EntitlementAssignmentCount   = $entitlementData.AssignmentCount
        EntitlementPackageNames      = $entitlementPackageNames
        EntitlementPackageDetailsJson = $entitlementPackageDetailsJson
        LicensingImpactCount         = $licensingData.ImpactCount
        LicensingImpactDirections    = $licensingImpactDirections
        LicensingImpactNames         = $licensingImpactNames
        LicensingAssignedNames       = $licensingAssignedNames
        LicensingImpactDetailsJson   = $licensingImpactDetailsJson
        TeamsCount                   = $teamsData.TeamsCount
        HasMailbox                   = $teamsData.HasMailbox
        BlockingFlags                = ($blockingFlags -join '; ')
        CoverageFailureAreas         = ($coverageFailureAreas -join '; ')
        Summary                      = $summary
    }
}

Export-ModuleMember -Function Get-PolicyImpactScopeMatrix, Test-PolicyImpactPrerequisites, Format-PolicyPreflightSummary, Initialize-PolicyImpactContext, Get-UserPolicyImpact
