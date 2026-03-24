# Per-user evaluator: EntitlementManagement policy area.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.

function Invoke-EntitlementManagementUserImpact {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [hashtable]$UserAreaStatus
    )

    $entitlementAssignments = @()

    if ($UserAreaStatus['EntitlementManagement'] -eq 'Available') {
        try {
            $entitlementAssignments = @(Get-MgEntitlementManagementAssignment -Filter "targetId eq '$($User.Id)'" -All -ErrorAction Stop)
        }
        catch {
            $UserAreaStatus['EntitlementManagement'] = 'Unavailable'
            Write-PolicyImpactLog -Level 'ERROR' -Message "Entitlement evaluation failed for $($User.UserPrincipalName) ($($User.Id)): $($_.Exception.Message)"
        }
    }

    return [pscustomobject]@{
        Assignments     = $entitlementAssignments
        AssignmentCount = $entitlementAssignments.Count
    }
}
