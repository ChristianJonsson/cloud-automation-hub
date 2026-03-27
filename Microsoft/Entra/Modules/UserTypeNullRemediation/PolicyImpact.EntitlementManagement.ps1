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
            $entitlementAssignments = @(
                Invoke-PolicyAreaGraphWithRetry -OperationName "Get-MgEntitlementManagementAssignment ($($User.Id))" -Operation {
                    Get-MgEntitlementManagementAssignment `
                        -Filter "target/objectid eq '$($User.Id)'" `
                        -ExpandProperty @('target', 'accessPackage') `
                        -All `
                        -ErrorAction Stop
                }
            )
        }
        catch {
            $UserAreaStatus['EntitlementManagement'] = 'Unavailable'
            Write-PolicyImpactLog -Level 'ERROR' -Message "Entitlement evaluation failed for $($User.UserPrincipalName) ($($User.Id)): $($_.Exception.Message)"
        }
    }

    $entitlementAssignments = @(
        $entitlementAssignments |
            Where-Object {
                $assignmentState = "$(Get-ObjectValue -InputObject $_ -PropertyName 'State')"
                -not [string]::Equals($assignmentState, 'Expired', [System.StringComparison]::OrdinalIgnoreCase)
            }
    )

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
                if ([string]::IsNullOrWhiteSpace($accessPackageId)) {
                    $accessPackage = Get-ObjectValue -InputObject $_ -PropertyName 'AccessPackage'
                    $accessPackageId = "$(Get-ObjectValue -InputObject $accessPackage -PropertyName 'Id')"
                }

                $expandedAccessPackage = Get-ObjectValue -InputObject $_ -PropertyName 'AccessPackage'
                $expandedAccessPackageName = "$(Get-ObjectValue -InputObject $expandedAccessPackage -PropertyName 'DisplayName')"

                $packageName = if (-not [string]::IsNullOrWhiteSpace($expandedAccessPackageName)) {
                    $expandedAccessPackageName
                }
                elseif ($accessPackageNameById.Keys -contains $accessPackageId) {
                    $accessPackageNameById[$accessPackageId]
                }
                else {
                    "[AccessPackage:$accessPackageId]"
                }

                [pscustomobject]@{
                    AssignmentId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'Id')"
                    AccessPackageId = $accessPackageId
                    AccessPackageName = $packageName
                    State = "$(Get-ObjectValue -InputObject $_ -PropertyName 'State')"
                    Status = "$(Get-ObjectValue -InputObject $_ -PropertyName 'Status')"
                }
            }
    )

    return [pscustomobject]@{
        Assignments     = $entitlementAssignments
        AssignmentCount = $entitlementAssignments.Count
        AssignmentDetails = $assignmentDetails
    }
}
