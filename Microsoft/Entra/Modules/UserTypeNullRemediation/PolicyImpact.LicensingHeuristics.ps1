# Per-user evaluator: LicensingHeuristics policy area.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.
# Probe-only area: no per-user licensing data is computed in the current implementation.

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

                $details += [pscustomobject]@{
                    SkuId            = $skuId
                    SkuName          = $skuName
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
            # GainsAccess path: no current licenses to enumerate — emit a single summary record.
            $details += [pscustomobject]@{
                SkuId            = ''
                SkuName          = ''
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
