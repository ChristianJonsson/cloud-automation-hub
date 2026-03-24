# Per-user evaluator: TeamsExchangeHeuristics policy area.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.
#
# DISABLED. The scope matrix entry and prerequisite probe are commented out in
# PolicyImpactValidation.psm1. Per-user Teams and mailbox probes are not executed.
# Team.ReadBasic.All and Mail.ReadBasic.All are not requested.
#
# To re-enable:
#   1. Uncomment the TeamsExchangeHeuristics entry in Get-PolicyImpactScopeMatrix.
#   2. Uncomment the Test-GraphProbe block for TeamsExchangeHeuristics in Test-PolicyImpactPrerequisites.
#   3. Replace the stub body below with the live probe logic (see git history).

function Invoke-TeamsExchangeHeuristicsUserImpact {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [hashtable]$UserAreaStatus
    )

    return [pscustomobject]@{
        TeamsCount = 0
        HasMailbox = $false
    }
}
