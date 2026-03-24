# Per-user evaluator: GroupAndAppAssignments policy area.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.
# Must run before ConditionalAccess and DynamicGroups; group IDs are passed downstream.

function Invoke-GroupAndAppAssignmentsUserImpact {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [hashtable]$UserAreaStatus
    )

    $groupMemberships = @()
    $appRoleAssignments = @()

    if ($UserAreaStatus['GroupAndAppAssignments'] -eq 'Available') {
        try {
            $groupMemberships = @(Get-MgUserMemberOf -UserId $User.Id -All -ErrorAction Stop)
            $appRoleAssignments = @(Get-MgUserAppRoleAssignment -UserId $User.Id -All -ErrorAction Stop)
        }
        catch {
            $UserAreaStatus['GroupAndAppAssignments'] = 'Unavailable'
            Write-PolicyImpactLog -Level 'ERROR' -Message "Group/app assignment evaluation failed for $($User.UserPrincipalName) ($($User.Id)): $($_.Exception.Message)"
        }
    }

    return [pscustomobject]@{
        GroupMemberships     = $groupMemberships
        GroupMembershipCount = $groupMemberships.Count
        AppRoleAssignments   = $appRoleAssignments
        AppRoleCount         = $appRoleAssignments.Count
    }
}
