# Per-user evaluator: EntitlementManagement policy area.
# Dot-sourced by PolicyImpactValidation.psm1 — not imported directly.

function Invoke-EntitlementManagementUserImpact {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [object]$PolicyContext,

        [Parameter(Mandatory = $true)]
        [hashtable]$UserAreaStatus
    )

    $entitlementAssignments = @()

    if ($UserAreaStatus['EntitlementManagement'] -eq 'Available') {
        try {
            $entitlementAssignments = @(Get-MgEntitlementManagementAssignment -Filter "targetId eq '$($User.Id)'" -All -ErrorAction Stop)
        }
        catch {
            try {
                $entitlementAssignments = @(Get-MgEntitlementManagementAssignment -Filter "target/objectId eq '$($User.Id)'" -All -ErrorAction Stop)
            }
            catch {
                $UserAreaStatus['EntitlementManagement'] = 'Unavailable'
                Write-PolicyImpactLog -Level 'ERROR' -Message "Entitlement evaluation failed for $($User.UserPrincipalName) ($($User.Id)): $($_.Exception.Message)"
            }
        }
    }

    $accessPackageNameById = @{}
    if ($null -ne $PolicyContext -and $null -ne $PolicyContext.AccessPackageNameMap) {
        foreach ($entry in $PolicyContext.AccessPackageNameMap.GetEnumerator()) {
            $accessPackageNameById["$($entry.Key)"] = "$($entry.Value)"
        }
    }

    $assignmentDetails = @(
        $entitlementAssignments |
            ForEach-Object {
                $accessPackageId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'AccessPackageId')"
                if ([string]::IsNullOrWhiteSpace($accessPackageId)) {
                    $accessPackageId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'accessPackageId')"
                }

                $packageName = if ($accessPackageNameById.ContainsKey($accessPackageId)) {
                    $accessPackageNameById[$accessPackageId]
                }
                else {
                    "[AccessPackage:$accessPackageId]"
                }

                [pscustomobject]@{
                    AssignmentId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'Id')"
                    AccessPackageId = $accessPackageId
                    AccessPackageName = $packageName
                }
            }
    )

    return [pscustomobject]@{
        Assignments     = $entitlementAssignments
        AssignmentCount = $entitlementAssignments.Count
        AssignmentDetails = $assignmentDetails
    }
}
