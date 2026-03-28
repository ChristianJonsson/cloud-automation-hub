# Per-user evaluator: LicensingHeuristics policy area.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.
# Computes per-user licensing impact direction and licensing details (including assigned license information).

function Invoke-LicensingHeuristicsUserImpact {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ProposedUserType,

        [Parameter(Mandatory = $true)]
        [hashtable]$UserAreaStatus,

        [Parameter(Mandatory = $true)]
        [object]$PolicyContext
    )

    $assignedLicenses = @($User.AssignedLicenses)
    $licenseCount = $assignedLicenses.Count
    $currentType = "$($User.UserType)"
    $resolvedProposedType = if ([string]::IsNullOrWhiteSpace($ProposedUserType)) { $currentType } else { "$ProposedUserType" }

    # currentType is null/empty for all users targeted by this script (UserType = null).
    # Include that case alongside the explicit Member/Guest transitions so the heuristic
    # fires correctly for the primary use case.
    $isCurrentTypeUnset = [string]::IsNullOrWhiteSpace($currentType)

    $direction = 'NoMaterialChange'
    if ($licenseCount -gt 0 -and ($currentType -eq 'Member' -or $isCurrentTypeUnset) -and $resolvedProposedType -eq 'Guest') {
        # Has licenses and is being assigned Guest — likely to lose member-tier licensing benefits.
        $direction = 'LosesAccess'
    }
    elseif ($licenseCount -eq 0 -and ($currentType -eq 'Guest' -or $isCurrentTypeUnset) -and $resolvedProposedType -eq 'Member') {
        # No licenses and is being assigned Member — will likely need licensing to use member-tier services.
        $direction = 'GainsAccess'
    }

    # Build assignment path map (Direct vs. GroupBased) from LicenseAssignmentStates.
    # GroupBased licenses are controlled by group membership, not direct assignment, so a userType
    # change alone will not remove them unless the group membership also changes.
    $assignmentPathBySkuId = @{}
    foreach ($state in @($User.LicenseAssignmentStates)) {
        $stateSkuId = "$(Get-ObjectValue -InputObject $state -PropertyName 'SkuId')"
        if ([string]::IsNullOrWhiteSpace($stateSkuId)) { continue }
        $assignedByGroup = Get-ObjectValue -InputObject $state -PropertyName 'AssignedByGroup'
        $path = if ($null -eq $assignedByGroup -or [string]::IsNullOrWhiteSpace("$assignedByGroup")) { 'Direct' } else { 'GroupBased' }
        if ($assignmentPathBySkuId.ContainsKey($stateSkuId)) {
            # Same SKU can be assigned both directly and via group — mark as Mixed.
            if ($assignmentPathBySkuId[$stateSkuId] -ne $path) {
                $assignmentPathBySkuId[$stateSkuId] = 'Mixed'
            }
        }
        else {
            $assignmentPathBySkuId[$stateSkuId] = $path
        }
    }

    # Build SKU name lookup from context so detail records carry human-readable names.
    $skuNameMap = @{}
    if ($null -ne $PolicyContext -and $null -ne $PolicyContext.SubscribedSkuMap) {
        foreach ($entry in $PolicyContext.SubscribedSkuMap.GetEnumerator()) {
            $skuNameMap["$($entry.Key)"] = "$($entry.Value)"
        }
    }

    $details = @()
    if ($direction -ne 'NoMaterialChange') {
        if ($assignedLicenses.Count -gt 0) {
            # LosesAccess path: enumerate each affected SKU so the caller knows exactly which licenses are at risk.
            foreach ($license in $assignedLicenses) {
                $skuId = "$(Get-ObjectValue -InputObject $license -PropertyName 'SkuId')"
                if ([string]::IsNullOrWhiteSpace($skuId)) {
                    $skuId = "$(Get-ObjectValue -InputObject $license -PropertyName 'skuId')"
                }
                $skuName = if ($skuNameMap.ContainsKey($skuId)) { $skuNameMap[$skuId] } else { "[Sku:$skuId]" }

                $assignmentPath = if ($assignmentPathBySkuId.ContainsKey($skuId)) { $assignmentPathBySkuId[$skuId] } else { 'Unknown' }
                $details += [pscustomobject]@{
                    SkuId            = $skuId
                    SkuName          = $skuName
                    AssignmentPath   = $assignmentPath
                    CurrentState     = 'Licensed'
                    PostChangeState  = 'PotentiallyNotLicensed'
                    ImpactDirection  = $direction
                    Confidence       = 'Low'
                    EvidenceSource   = 'AssignedLicensesHeuristic'
                    AssignedLicenseCount = $licenseCount
                }
            }
        }
        else {
            # GainsAccess path: no current licenses to enumerate.
            # Use a named placeholder so LicensingImpactNames is never blank and a reviewer
            # understands a manual license assignment is required rather than suspecting a data gap.
            $details += [pscustomobject]@{
                SkuId            = ''
                SkuName          = '[NeedsLicenseAssignment]'
                AssignmentPath   = 'NotApplicable'
                CurrentState     = 'NotLicensed'
                PostChangeState  = 'PotentiallyLicensed'
                ImpactDirection  = $direction
                Confidence       = 'Low'
                EvidenceSource   = 'AssignedLicensesHeuristic'
                AssignedLicenseCount = $licenseCount
            }
        }
    }

    # Always enumerate current license names regardless of impact direction so the
    # caller has visibility into what licenses the user holds even for NoMaterialChange.
    $assignedLicenseNames = ''
    if ($assignedLicenses.Count -gt 0) {
        $licenseNames = @(
            $assignedLicenses | ForEach-Object {
                $skuId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'SkuId')"
                if ([string]::IsNullOrWhiteSpace($skuId)) {
                    $skuId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'skuId')"
                }
                if ($skuNameMap.ContainsKey($skuId)) { $skuNameMap[$skuId] } else { "[Sku:$skuId]" }
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        $assignedLicenseNames = $licenseNames -join '; '
    }

    return [pscustomobject]@{
        ImpactCount          = $details.Count
        ImpactDirection      = $direction
        ImpactDetails        = $details
        AssignedLicenseNames = $assignedLicenseNames
    }
}
