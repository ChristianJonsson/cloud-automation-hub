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
