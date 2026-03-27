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
            $groupMemberships = @(
                Invoke-PolicyAreaGraphWithRetry -OperationName "Get-MgUserMemberOf ($($User.Id))" -Operation {
                    Get-MgUserMemberOf -UserId $User.Id -All -ErrorAction Stop
                }
            )
            $appRoleAssignments = @(
                Invoke-PolicyAreaGraphWithRetry -OperationName "Get-MgUserAppRoleAssignment ($($User.Id))" -Operation {
                    Get-MgUserAppRoleAssignment -UserId $User.Id -All -ErrorAction Stop
                }
            )
        }
        catch {
            $UserAreaStatus['GroupAndAppAssignments'] = 'Unavailable'
            Write-PolicyImpactLog -Level 'ERROR' -Message "Group/app assignment evaluation failed for $($User.UserPrincipalName) ($($User.Id)): $($_.Exception.Message)"
        }
    }

    $groupMembershipDetails = @(
        $groupMemberships |
            ForEach-Object {
                $groupId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'Id')"
                $groupName = "$(Get-ObjectValue -InputObject $_ -PropertyName 'DisplayName')"
                if ([string]::IsNullOrWhiteSpace($groupName)) {
                    $groupName = "$(Get-ObjectValue -InputObject $_ -PropertyName 'displayName')"
                }

                [pscustomobject]@{
                    GroupId = $groupId
                    GroupName = if ([string]::IsNullOrWhiteSpace($groupName)) { "[UnnamedGroup:$groupId]" } else { $groupName }
                }
            }
    )

    $appRoleDetails = @(
        $appRoleAssignments |
            ForEach-Object {
                $resourceName = "$(Get-ObjectValue -InputObject $_ -PropertyName 'ResourceDisplayName')"
                if ([string]::IsNullOrWhiteSpace($resourceName)) {
                    $resourceName = "$(Get-ObjectValue -InputObject $_ -PropertyName 'resourceDisplayName')"
                }

                $appId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'AppId')"
                if ([string]::IsNullOrWhiteSpace($appId)) {
                    $appId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'appId')"
                }

                [pscustomobject]@{
                    AppId = $appId
                    ResourceDisplayName = if ([string]::IsNullOrWhiteSpace($resourceName)) { "[UnnamedApp:$appId]" } else { $resourceName }
                }
            }
    )

    return [pscustomobject]@{
        GroupMemberships     = $groupMemberships
        GroupMembershipCount = $groupMemberships.Count
        GroupMembershipDetails = $groupMembershipDetails
        AppRoleAssignments   = $appRoleAssignments
        AppRoleCount         = $appRoleAssignments.Count
        AppRoleDetails       = $appRoleDetails
    }
}
