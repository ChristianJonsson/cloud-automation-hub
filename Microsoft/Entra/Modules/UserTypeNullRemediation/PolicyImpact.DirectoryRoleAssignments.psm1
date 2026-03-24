# Per-user evaluator: DirectoryRoleAssignments policy area.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.
# Uses tenant-wide role assignments loaded into PolicyContext by Initialize-PolicyImpactContext.

function Invoke-DirectoryRoleAssignmentsUserImpact {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [object]$PolicyContext,

        [Parameter(Mandatory = $true)]
        [hashtable]$UserAreaStatus
    )

    $directoryRoleMatches = @()

    if ($UserAreaStatus['DirectoryRoleAssignments'] -eq 'Available') {
        $directoryRoleMatches = @($PolicyContext.DirectoryRoleAssignments | Where-Object { "$($_.PrincipalId)" -eq "$($User.Id)" })
    }

    return [pscustomobject]@{
        Matches    = $directoryRoleMatches
        MatchCount = $directoryRoleMatches.Count
    }
}
