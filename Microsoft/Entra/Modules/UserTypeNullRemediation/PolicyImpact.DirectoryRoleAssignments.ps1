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

    $roleNameById = @{}
    if ($null -ne $PolicyContext -and $null -ne $PolicyContext.DirectoryRoleDefinitionNameMap) {
        foreach ($entry in $PolicyContext.DirectoryRoleDefinitionNameMap.GetEnumerator()) {
            $roleNameById["$($entry.Key)"] = "$($entry.Value)"
        }
    }

    $matchDetails = @(
        $directoryRoleMatches |
            ForEach-Object {
                $roleDefinitionId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'RoleDefinitionId')"
                if ([string]::IsNullOrWhiteSpace($roleDefinitionId)) {
                    $roleDefinitionId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'roleDefinitionId')"
                }

                $roleName = if ($roleNameById.ContainsKey($roleDefinitionId)) {
                    $roleNameById[$roleDefinitionId]
                }
                else {
                    "[RoleDefinition:$roleDefinitionId]"
                }

                [pscustomobject]@{
                    RoleDefinitionId = $roleDefinitionId
                    RoleName = $roleName
                    AssignmentId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'Id')"
                    AssignmentType = 'Active'
                }
            }
    )

    # PIM eligible role schedules — users with eligible-but-not-activated assignments.
    # Sourced from PolicyContext.EligibleRoleSchedules loaded at context init.
    $eligibleRoleMatches = @()
    if ($UserAreaStatus['DirectoryRoleAssignments'] -eq 'Available' -and
        $null -ne $PolicyContext -and
        $null -ne $PolicyContext.EligibleRoleSchedules) {
        $eligibleRoleMatches = @(
            $PolicyContext.EligibleRoleSchedules |
                Where-Object { "$($_.PrincipalId)" -eq "$($User.Id)" }
        )
    }

    $eligibleMatchDetails = @(
        $eligibleRoleMatches |
            ForEach-Object {
                $roleDefinitionId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'RoleDefinitionId')"
                if ([string]::IsNullOrWhiteSpace($roleDefinitionId)) {
                    $roleDefinitionId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'roleDefinitionId')"
                }

                $roleName = if ($roleNameById.ContainsKey($roleDefinitionId)) {
                    $roleNameById[$roleDefinitionId]
                }
                else {
                    "[RoleDefinition:$roleDefinitionId]"
                }

                [pscustomobject]@{
                    RoleDefinitionId = $roleDefinitionId
                    RoleName = $roleName
                    ScheduleId = "$(Get-ObjectValue -InputObject $_ -PropertyName 'Id')"
                    AssignmentType = 'Eligible'
                }
            }
    )

    return [pscustomobject]@{
        Matches             = $directoryRoleMatches
        MatchCount          = $directoryRoleMatches.Count
        MatchDetails        = $matchDetails
        EligibleCount       = $eligibleRoleMatches.Count
        EligibleMatchDetails = $eligibleMatchDetails
    }
}
