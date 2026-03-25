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
        [hashtable]$UserAreaStatus
    )

    $licenseCount = @($User.AssignedLicenses).Count
    $currentType = "$($User.UserType)"
    $resolvedProposedType = if ([string]::IsNullOrWhiteSpace($ProposedUserType)) { $currentType } else { "$ProposedUserType" }

    $direction = 'NoMaterialChange'
    if ($licenseCount -gt 0 -and $currentType -eq 'Member' -and $resolvedProposedType -eq 'Guest') {
        $direction = 'LosesAccess'
    }
    elseif ($licenseCount -eq 0 -and $currentType -eq 'Guest' -and $resolvedProposedType -eq 'Member') {
        $direction = 'GainsAccess'
    }

    $details = @()
    if ($direction -ne 'NoMaterialChange') {
        $details += [pscustomobject]@{
            CurrentState = if ($licenseCount -gt 0) { 'Licensed' } else { 'NotLicensed' }
            PostChangeState = if ($direction -eq 'LosesAccess') { 'PotentiallyNotLicensed' } elseif ($direction -eq 'GainsAccess') { 'PotentiallyLicensed' } else { 'Unchanged' }
            ImpactDirection = $direction
            Confidence = 'Low'
            EvidenceSource = 'AssignedLicensesHeuristic'
            AssignedLicenseCount = $licenseCount
        }
    }

    return [pscustomobject]@{
        ImpactCount = $details.Count
        ImpactDirection = $direction
        ImpactDetails = $details
    }
}
