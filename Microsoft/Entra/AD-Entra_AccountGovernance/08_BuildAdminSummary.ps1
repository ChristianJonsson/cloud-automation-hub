# ==============================================================================
# 08_BuildAdminSummary.ps1
# Purpose : Derive effective admins and an aggregate admin summary from the
#           role and group exports. Pure transformation — no Graph calls.
# Run on  : Any machine with access to the NDJSON output files
# Output  : <RunOutputPath>\Entra_EffectiveAdmins_<RunFileSuffix>.ndjson
#           <RunOutputPath>\Entra_NonUserRoleHolders_<RunFileSuffix>.ndjson
#           <RunOutputPath>\Entra_AdminSummary_<RunFileSuffix>.json
# Requires: 00_Config.ps1 and outputs from 03_ExportEntraUsers.ps1,
#           04_ExportEntraRoles.ps1, 05_ExportEntraGroups.ps1
#
# Testability:
#   The join logic is exposed as Build-AdminSummary so Pester tests can call
#   it directly with fixture arrays. Setting the global sentinel
#   $BuildAdminSummary_TestMode before dot-sourcing skips the I/O wrapper.
# ==============================================================================

if (-not (Get-Variable -Name BuildAdminSummary_TestMode -Scope Global -ErrorAction SilentlyContinue)) {
    . "$PSScriptRoot\00_Config.ps1"

    $loggingModulePath = Join-Path $PSScriptRoot '..\..\Common\Modules\Shared\Logging.psm1'
    Import-Module $loggingModulePath -Force -ErrorAction Stop
}

# --- Helpers (script-level so Pester can test them in isolation) -------------

function Resolve-EffectiveStaleness {
    param(
        $LastSignInDateTime,
        [datetime]$Now,
        [int]$ThresholdDays
    )

    if ([string]::IsNullOrWhiteSpace("$LastSignInDateTime")) { return $true }
    try {
        $signIn = [datetime]$LastSignInDateTime
        return ($Now - $signIn).TotalDays -gt $ThresholdDays
    }
    catch {
        return $true
    }
}

function Get-TransitiveUserMembers {
    param(
        [Parameter(Mandatory)] [string]$RootGroupId,
        [Parameter(Mandatory)] [hashtable]$MembersByGroupId,
        [hashtable]$Visited = @{}
    )

    if ($Visited.ContainsKey($RootGroupId)) { return @() }
    $Visited[$RootGroupId] = $true

    $result = New-Object System.Collections.Generic.List[object]
    if (-not $MembersByGroupId.ContainsKey($RootGroupId)) { return $result.ToArray() }

    foreach ($member in $MembersByGroupId[$RootGroupId]) {
        switch ($member.MemberType) {
            'User' {
                $result.Add($member)
            }
            'Group' {
                $nested = Get-TransitiveUserMembers -RootGroupId $member.MemberId `
                                                   -MembersByGroupId $MembersByGroupId `
                                                   -Visited $Visited
                foreach ($n in $nested) { $result.Add($n) }
            }
            default { } # ServicePrincipal/Device/etc are not users; skip when expanding for admin attribution
        }
    }
    return $result.ToArray()
}

function New-EffectiveAdminRow {
    param(
        $User,
        [string]$PrincipalId,
        [string]$PrincipalDisplayName,
        [string]$PrincipalUpn,
        [string]$RoleId,
        [string]$RoleName,
        [string]$AssignmentPath,
        [string]$AssignmentType,
        [string]$Scope,
        [datetime]$Now,
        [int]$ThresholdDays
    )

    $userId      = if ($null -ne $User -and $User.Id) { $User.Id } else { $PrincipalId }
    $upn         = if ($null -ne $User -and $User.PSObject.Properties['UserPrincipalName'] -and $User.UserPrincipalName) { $User.UserPrincipalName } else { $PrincipalUpn }
    $displayName = if ($null -ne $User -and $User.PSObject.Properties['DisplayName'] -and $User.DisplayName)         { $User.DisplayName }       else { $PrincipalDisplayName }
    $userType    = if ($null -ne $User -and $User.PSObject.Properties['UserType'])              { $User.UserType }              else { $null }
    $synced      = if ($null -ne $User -and $User.PSObject.Properties['OnPremisesSyncEnabled']) { [bool]$User.OnPremisesSyncEnabled } else { $false }
    $enabled     = if ($null -ne $User -and $User.PSObject.Properties['AccountEnabled'])        { $User.AccountEnabled }        else { $null }
    $lastSignIn  = if ($null -ne $User -and $User.PSObject.Properties['LastSignInDateTime'])    { $User.LastSignInDateTime }    else { $null }
    $isStale     = Resolve-EffectiveStaleness -LastSignInDateTime $lastSignIn -Now $Now -ThresholdDays $ThresholdDays

    [PSCustomObject][ordered]@{
        UserId                = $userId
        UserPrincipalName     = $upn
        DisplayName           = $displayName
        UserType              = $userType
        OnPremisesSyncEnabled = $synced
        AccountEnabled        = $enabled
        LastSignInDateTime    = $lastSignIn
        RoleId                = $RoleId
        RoleName              = $RoleName
        AssignmentPath        = $AssignmentPath
        AssignmentType        = $AssignmentType
        Scope                 = $Scope
        IsStale               = $isStale
    }
}

function Build-AdminSummary {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [array]$Users,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [array]$Roles,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [array]$RoleAssignments,
        [AllowEmptyCollection()] [array]$RoleEligibilities = @(),
        [Parameter(Mandatory)] [AllowEmptyCollection()] [array]$Groups,
        [AllowEmptyCollection()] [array]$GroupMembers = @(),
        [int]$StaleAdminThresholdDays = 90,
        [datetime]$Now = (Get-Date)
    )

    $usersById  = @{}
    foreach ($u in $Users)  { if ($u.Id) { $usersById[$u.Id]  = $u } }

    $rolesById  = @{}
    foreach ($r in $Roles)  { if ($r.Id) { $rolesById[$r.Id]  = $r } }

    $groupsById = @{}
    foreach ($g in $Groups) { if ($g.Id) { $groupsById[$g.Id] = $g } }

    $membersByGroupId = @{}
    foreach ($m in $GroupMembers) {
        if (-not $membersByGroupId.ContainsKey($m.GroupId)) {
            $membersByGroupId[$m.GroupId] = New-Object System.Collections.Generic.List[object]
        }
        $membersByGroupId[$m.GroupId].Add($m)
    }

    $effectiveAdmins    = New-Object System.Collections.Generic.List[object]
    $nonUserRoleHolders = New-Object System.Collections.Generic.List[object]

    $allAssignments = @($RoleAssignments) + @($RoleEligibilities)

    foreach ($a in $allAssignments) {
        $role     = $rolesById[$a.RoleDefinitionId]
        $roleName = if ($role) { $role.DisplayName } else { $a.RoleDefinitionId }

        switch ($a.PrincipalType) {
            'User' {
                $row = New-EffectiveAdminRow -User $usersById[$a.PrincipalId] `
                                             -PrincipalId $a.PrincipalId `
                                             -PrincipalDisplayName $a.PrincipalDisplayName `
                                             -PrincipalUpn $a.PrincipalUserPrincipalName `
                                             -RoleId $a.RoleDefinitionId `
                                             -RoleName $roleName `
                                             -AssignmentPath 'Direct' `
                                             -AssignmentType $a.AssignmentType `
                                             -Scope $a.DirectoryScopeId `
                                             -Now $Now `
                                             -ThresholdDays $StaleAdminThresholdDays
                $effectiveAdmins.Add($row)
            }
            'Group' {
                $group     = $groupsById[$a.PrincipalId]
                $groupName = if ($group) { $group.DisplayName } else { $a.PrincipalDisplayName }
                $userMembers = Get-TransitiveUserMembers -RootGroupId $a.PrincipalId -MembersByGroupId $membersByGroupId

                foreach ($member in $userMembers) {
                    $row = New-EffectiveAdminRow -User $usersById[$member.MemberId] `
                                                 -PrincipalId $member.MemberId `
                                                 -PrincipalDisplayName $member.MemberDisplayName `
                                                 -PrincipalUpn $member.MemberUserPrincipalName `
                                                 -RoleId $a.RoleDefinitionId `
                                                 -RoleName $roleName `
                                                 -AssignmentPath "ViaGroup:$groupName" `
                                                 -AssignmentType $a.AssignmentType `
                                                 -Scope $a.DirectoryScopeId `
                                                 -Now $Now `
                                                 -ThresholdDays $StaleAdminThresholdDays
                    $effectiveAdmins.Add($row)
                }
            }
            default {
                $nonUserRoleHolders.Add([PSCustomObject][ordered]@{
                    PrincipalId          = $a.PrincipalId
                    PrincipalType        = $a.PrincipalType
                    PrincipalDisplayName = $a.PrincipalDisplayName
                    RoleId               = $a.RoleDefinitionId
                    RoleName             = $roleName
                    AssignmentType       = $a.AssignmentType
                    Scope                = $a.DirectoryScopeId
                })
            }
        }
    }

    $effectiveArr   = $effectiveAdmins.ToArray()
    $nonUserArr     = $nonUserRoleHolders.ToArray()

    $uniqueAdminIds = @($effectiveArr | ForEach-Object { $_.UserId } | Select-Object -Unique)
    $staleUserIds   = @($effectiveArr | Where-Object { $_.IsStale }              | ForEach-Object { $_.UserId } | Select-Object -Unique)
    $syncedUserIds  = @($effectiveArr | Where-Object { $_.OnPremisesSyncEnabled } | ForEach-Object { $_.UserId } | Select-Object -Unique)
    $cloudUserIds   = @($effectiveArr | Where-Object { -not $_.OnPremisesSyncEnabled } | ForEach-Object { $_.UserId } | Select-Object -Unique)
    $guestUserIds   = @($effectiveArr | Where-Object { $_.UserType -eq 'Guest' } | ForEach-Object { $_.UserId } | Select-Object -Unique)

    $byRole = [ordered]@{}
    foreach ($row in $effectiveArr) {
        if (-not $byRole.Contains($row.RoleName)) { $byRole[$row.RoleName] = 0 }
        $byRole[$row.RoleName] = $byRole[$row.RoleName] + 1
    }

    $summary = [ordered]@{
        GeneratedAt             = $Now.ToString('yyyy-MM-dd HH:mm:ss')
        StaleAdminThresholdDays = $StaleAdminThresholdDays
        Totals = [ordered]@{
            EffectiveAdminRows  = $effectiveArr.Count
            UniqueAdminUsers    = $uniqueAdminIds.Count
            NonUserRoleHolders  = $nonUserArr.Count
            ActiveAssignments   = @($effectiveArr | Where-Object { $_.AssignmentType -eq 'Active' }).Count
            EligibleAssignments = @($effectiveArr | Where-Object { $_.AssignmentType -eq 'Eligible' }).Count
            DirectAssignments   = @($effectiveArr | Where-Object { $_.AssignmentPath -eq 'Direct' }).Count
            ViaGroupAssignments = @($effectiveArr | Where-Object { $_.AssignmentPath -like 'ViaGroup:*' }).Count
            StaleAdminUsers     = $staleUserIds.Count
            SyncedAdminUsers    = $syncedUserIds.Count
            CloudOnlyAdminUsers = $cloudUserIds.Count
            GuestAdminUsers     = $guestUserIds.Count
        }
        AdminsByRole = $byRole
    }

    return @{
        EffectiveAdmins    = $effectiveArr
        NonUserRoleHolders = $nonUserArr
        Summary            = $summary
    }
}

# --- Main I/O wrapper (skipped under $BuildAdminSummary_TestMode) ------------

if (-not (Get-Variable -Name BuildAdminSummary_TestMode -Scope Global -ErrorAction SilentlyContinue)) {

    if (-not (Get-Variable -Name RunOutputPath -ErrorAction SilentlyContinue)) {
        $latestRun = Get-ChildItem -Path $OutputPath -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($null -eq $latestRun) {
            throw "No timestamped run directories found in '$OutputPath'. Run scripts 03-05 first."
        }
        $RunOutputPath = $latestRun.FullName
        Write-Warning "No RunOutputPath set; using most recent run: $RunOutputPath"
    }
    if (-not (Get-Variable -Name RunFileSuffix -ErrorAction SilentlyContinue) -or [string]::IsNullOrEmpty($RunFileSuffix)) {
        $RunFileSuffix = ConvertTo-RunFileSuffix -DirectoryName (Split-Path $RunOutputPath -Leaf)
        if ([string]::IsNullOrEmpty($RunFileSuffix)) {
            $sample = Get-ChildItem -Path $RunOutputPath -Filter '*.ndjson' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($sample -and $sample.Name -match '_(\d{8}_\d{4})\.ndjson$') { $RunFileSuffix = $matches[1] }
            else { throw "Could not determine RunFileSuffix for '$RunOutputPath'." }
        }
    }
    Set-LogFilePath -Path (Join-Path $RunOutputPath 'AccountGovernance.log')
    Write-Log '=== 08_BuildAdminSummary started ==='

    $allUsersFile          = "Entra_AllUsers_$RunFileSuffix.ndjson"
    $roleDefinitionsFile   = "Entra_RoleDefinitions_$RunFileSuffix.ndjson"
    $roleAssignmentsFile   = "Entra_RoleAssignments_$RunFileSuffix.ndjson"
    $roleEligibilitiesFile = "Entra_RoleEligibilities_$RunFileSuffix.ndjson"
    $groupsFile            = "Entra_Groups_$RunFileSuffix.ndjson"
    $groupMembersFile      = "Entra_GroupMembers_$RunFileSuffix.ndjson"

    $requiredInputs = @($allUsersFile, $roleDefinitionsFile, $roleAssignmentsFile, $groupsFile, $groupMembersFile)
    foreach ($f in $requiredInputs) {
        $p = Join-Path $RunOutputPath $f
        if (-not (Test-Path $p)) {
            throw "Required input '$f' not found in '$RunOutputPath'. Run scripts 03/04/05 first."
        }
    }

    function Read-NdjsonFile {
        param([string]$Path)
        if (-not (Test-Path $Path)) { return @() }
        return @(
            Get-Content $Path |
                Where-Object { $_ -match '\S' } |
                ForEach-Object { $_ | ConvertFrom-Json }
        )
    }

    Write-Log 'Loading inputs...'
    $allUsers          = Read-NdjsonFile (Join-Path $RunOutputPath $allUsersFile)
    $roleDefinitions   = Read-NdjsonFile (Join-Path $RunOutputPath $roleDefinitionsFile)
    $roleAssignments   = Read-NdjsonFile (Join-Path $RunOutputPath $roleAssignmentsFile)
    $roleEligibilities = Read-NdjsonFile (Join-Path $RunOutputPath $roleEligibilitiesFile)
    $groups            = Read-NdjsonFile (Join-Path $RunOutputPath $groupsFile)
    $groupMembers      = Read-NdjsonFile (Join-Path $RunOutputPath $groupMembersFile)
    Write-Log "  Users: $($allUsers.Count)"
    Write-Log "  Role definitions: $($roleDefinitions.Count)"
    Write-Log "  Role assignments: $($roleAssignments.Count)"
    Write-Log "  Role eligibilities: $($roleEligibilities.Count)"
    Write-Log "  Groups: $($groups.Count)"
    Write-Log "  Group member rows: $($groupMembers.Count)"

    Write-Log 'Building admin summary...'
    $buildResult = Build-AdminSummary `
        -Users $allUsers `
        -Roles $roleDefinitions `
        -RoleAssignments $roleAssignments `
        -RoleEligibilities $roleEligibilities `
        -Groups $groups `
        -GroupMembers $groupMembers `
        -StaleAdminThresholdDays $StaleAdminThresholdDays

    $effectiveAdmins    = $buildResult.EffectiveAdmins
    $nonUserRoleHolders = $buildResult.NonUserRoleHolders

    $effectiveAdminsFile    = "Entra_EffectiveAdmins_$RunFileSuffix.ndjson"
    $nonUserRoleHoldersFile = "Entra_NonUserRoleHolders_$RunFileSuffix.ndjson"
    $adminSummaryFile       = "Entra_AdminSummary_$RunFileSuffix.json"
    $effectivePath = Join-Path $RunOutputPath $effectiveAdminsFile
    $nonUserPath   = Join-Path $RunOutputPath $nonUserRoleHoldersFile
    $summaryPath   = Join-Path $RunOutputPath $adminSummaryFile

    if ($effectiveAdmins.Count -gt 0) {
        $effectiveAdmins | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 } |
            Out-File $effectivePath -Encoding UTF8
    } else {
        '' | Out-File $effectivePath -Encoding UTF8
        Clear-Content $effectivePath
    }
    Write-Log "  Written -> $effectiveAdminsFile ($($effectiveAdmins.Count) rows)"

    if ($nonUserRoleHolders.Count -gt 0) {
        $nonUserRoleHolders | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 } |
            Out-File $nonUserPath -Encoding UTF8
    } else {
        '' | Out-File $nonUserPath -Encoding UTF8
        Clear-Content $nonUserPath
    }
    Write-Log "  Written -> $nonUserRoleHoldersFile ($($nonUserRoleHolders.Count) rows)"

    $buildResult.Summary | ConvertTo-Json -Depth 5 | Out-File $summaryPath -Encoding UTF8
    Write-Log "  Written -> $adminSummaryFile"

    Write-Log '=== 08_BuildAdminSummary complete ==='
    $totals = $buildResult.Summary.Totals
    Write-Log ("  Effective admin rows: {0}  (unique users: {1})" -f $totals.EffectiveAdminRows, $totals.UniqueAdminUsers)
    Write-Log ("  Active / Eligible   : {0} / {1}" -f $totals.ActiveAssignments, $totals.EligibleAssignments)
    Write-Log ("  Direct / ViaGroup   : {0} / {1}" -f $totals.DirectAssignments, $totals.ViaGroupAssignments)
    Write-Log ("  Synced / Cloud-only : {0} / {1}" -f $totals.SyncedAdminUsers, $totals.CloudOnlyAdminUsers)
    Write-Log ("  Guest admins        : {0}" -f $totals.GuestAdminUsers)
    Write-Log ("  Stale admins        : {0} (threshold {1} days)" -f $totals.StaleAdminUsers, $StaleAdminThresholdDays)
    Write-Log ("  Non-user holders    : {0}" -f $totals.NonUserRoleHolders)
}
