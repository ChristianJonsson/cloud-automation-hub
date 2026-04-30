# Pester 5 tests for the Build-AdminSummary join logic in 08_BuildAdminSummary.ps1.
# Run from the repo root or from this folder:
#   Invoke-Pester .\Microsoft\Entra\AD-Entra_AccountGovernance\Tests\

BeforeAll {
    # Sentinel suppresses the script's I/O wrapper so dot-sourcing only loads
    # the function definitions.
    $Global:BuildAdminSummary_TestMode = $true
    . "$PSScriptRoot\..\08_BuildAdminSummary.ps1"

    $script:fixturesPath = Join-Path $PSScriptRoot 'Fixtures'

    function Read-Fixture {
        param([string]$FileName)
        $path = Join-Path $script:fixturesPath $FileName
        if (-not (Test-Path $path)) { return @() }
        return @(
            Get-Content $path |
                Where-Object { $_ -match '\S' } |
                ForEach-Object { $_ | ConvertFrom-Json }
        )
    }

    $script:users          = Read-Fixture 'Users.ndjson'
    $script:roles          = Read-Fixture 'Roles.ndjson'
    $script:assignments    = Read-Fixture 'RoleAssignments.ndjson'
    $script:eligibilities  = Read-Fixture 'RoleEligibilities.ndjson'
    $script:groups         = Read-Fixture 'Groups.ndjson'
    $script:groupMembers   = Read-Fixture 'GroupMembers.ndjson'

    $script:fixedNow = [datetime]'2026-04-28T12:00:00Z'

    $script:result = Build-AdminSummary `
        -Users $script:users `
        -Roles $script:roles `
        -RoleAssignments $script:assignments `
        -RoleEligibilities $script:eligibilities `
        -Groups $script:groups `
        -GroupMembers $script:groupMembers `
        -StaleAdminThresholdDays 90 `
        -Now $script:fixedNow
}

AfterAll {
    Remove-Variable -Name BuildAdminSummary_TestMode -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Build-AdminSummary' {

    Context 'Direct user assignments' {
        It 'emits AssignmentPath = Direct for alice with Global Administrator' {
            $row = $script:result.EffectiveAdmins |
                Where-Object { $_.UserId -eq 'u-alice' -and $_.RoleName -eq 'Global Administrator' -and $_.AssignmentPath -eq 'Direct' }
            $row | Should -Not -BeNullOrEmpty
            $row.AssignmentType | Should -Be 'Active'
            $row.Scope          | Should -Be '/'
        }

        It 'flags bob as stale (last sign-in older than threshold)' {
            $row = $script:result.EffectiveAdmins |
                Where-Object { $_.UserId -eq 'u-bob' -and $_.AssignmentPath -eq 'Direct' }
            $row.IsStale | Should -BeTrue
        }

        It 'flags alice as not stale (recent sign-in)' {
            $row = $script:result.EffectiveAdmins |
                Where-Object { $_.UserId -eq 'u-alice' -and $_.AssignmentPath -eq 'Direct' }
            $row.IsStale | Should -BeFalse
        }
    }

    Context 'Via-group resolution (transitive)' {
        It 'emits ViaGroup:GA-PAG for dave (direct member of role-assignable group)' {
            $row = $script:result.EffectiveAdmins |
                Where-Object { $_.UserId -eq 'u-dave' }
            $row.AssignmentPath | Should -Be 'ViaGroup:GA-PAG'
            $row.RoleName       | Should -Be 'Global Administrator'
        }

        It 'expands nested groups (eve reachable via g-pag -> g-nested -> u-eve)' {
            $row = $script:result.EffectiveAdmins |
                Where-Object { $_.UserId -eq 'u-eve' }
            $row.AssignmentPath | Should -Be 'ViaGroup:GA-PAG'
        }

        It 'preserves both Direct and ViaGroup paths for the same user (alice)' {
            $aliceRows = $script:result.EffectiveAdmins | Where-Object { $_.UserId -eq 'u-alice' }
            $aliceRows.Count                                            | Should -Be 2
            ($aliceRows | Where-Object { $_.AssignmentPath -eq 'Direct' }).Count           | Should -Be 1
            ($aliceRows | Where-Object { $_.AssignmentPath -eq 'ViaGroup:GA-PAG' }).Count  | Should -Be 1
        }
    }

    Context 'Service principals and other non-user role holders' {
        It 'routes ServicePrincipal assignments to NonUserRoleHolders, not EffectiveAdmins' {
            $script:result.EffectiveAdmins    | Where-Object { $_.UserId -eq 'sp-1' } | Should -BeNullOrEmpty
            $script:result.NonUserRoleHolders | Where-Object { $_.PrincipalId -eq 'sp-1' } | Should -Not -BeNullOrEmpty
        }

        It 'preserves PrincipalType on non-user rows' {
            $row = $script:result.NonUserRoleHolders | Where-Object { $_.PrincipalId -eq 'sp-1' }
            $row.PrincipalType | Should -Be 'ServicePrincipal'
            $row.RoleName      | Should -Be 'Custom Helpdesk'
        }
    }

    Context 'PIM eligibility' {
        It 'emits AssignmentType = Eligible for carol with User Administrator' {
            $row = $script:result.EffectiveAdmins |
                Where-Object { $_.UserId -eq 'u-carol' }
            $row.AssignmentType | Should -Be 'Eligible'
            $row.RoleName       | Should -Be 'User Administrator'
        }

        It 'preserves UserType = Guest from the user record' {
            $row = $script:result.EffectiveAdmins | Where-Object { $_.UserId -eq 'u-carol' }
            $row.UserType | Should -Be 'Guest'
        }
    }

    Context 'Aggregate summary counts' {
        It 'reports the correct number of effective admin rows and unique users' {
            $script:result.Summary.Totals.EffectiveAdminRows | Should -Be 6
            $script:result.Summary.Totals.UniqueAdminUsers   | Should -Be 5
        }

        It 'splits Active vs Eligible correctly' {
            $script:result.Summary.Totals.ActiveAssignments   | Should -Be 5
            $script:result.Summary.Totals.EligibleAssignments | Should -Be 1
        }

        It 'splits Direct vs ViaGroup correctly' {
            $script:result.Summary.Totals.DirectAssignments   | Should -Be 3
            $script:result.Summary.Totals.ViaGroupAssignments | Should -Be 3
        }

        It 'splits synced vs cloud-only admin users correctly' {
            $script:result.Summary.Totals.SyncedAdminUsers    | Should -Be 1
            $script:result.Summary.Totals.CloudOnlyAdminUsers | Should -Be 4
        }

        It 'counts guest admin users' {
            $script:result.Summary.Totals.GuestAdminUsers | Should -Be 1
        }

        It 'counts unique stale admin users (bob + carol) given a 90-day threshold' {
            $script:result.Summary.Totals.StaleAdminUsers | Should -Be 2
        }

        It 'counts non-user role holders' {
            $script:result.Summary.Totals.NonUserRoleHolders | Should -Be 1
        }

        It 'breaks down counts by role name' {
            $script:result.Summary.AdminsByRole['Global Administrator'] | Should -Be 4
            $script:result.Summary.AdminsByRole['User Administrator']   | Should -Be 2
        }
    }

    Context 'Empty inputs' {
        It 'produces empty arrays without throwing when there are no assignments' {
            $empty = Build-AdminSummary `
                -Users @() -Roles @() -RoleAssignments @() `
                -RoleEligibilities @() -Groups @() -GroupMembers @() `
                -StaleAdminThresholdDays 90 -Now $script:fixedNow
            $empty.EffectiveAdmins.Count    | Should -Be 0
            $empty.NonUserRoleHolders.Count | Should -Be 0
            $empty.Summary.Totals.EffectiveAdminRows | Should -Be 0
        }
    }
}

Describe 'Get-TransitiveUserMembers' {
    It 'walks nested groups and returns users only' {
        $membersByGroup = @{
            'g-pag'    = @(
                [PSCustomObject]@{ MemberId = 'u-1';      MemberType = 'User';  MemberDisplayName = 'One' },
                [PSCustomObject]@{ MemberId = 'g-nested'; MemberType = 'Group'; MemberDisplayName = 'Nested' }
            )
            'g-nested' = @(
                [PSCustomObject]@{ MemberId = 'u-2'; MemberType = 'User';            MemberDisplayName = 'Two' },
                [PSCustomObject]@{ MemberId = 'sp-1'; MemberType = 'ServicePrincipal'; MemberDisplayName = 'SP' }
            )
        }
        $result = Get-TransitiveUserMembers -RootGroupId 'g-pag' -MembersByGroupId $membersByGroup
        $userIds = @($result | ForEach-Object { $_.MemberId } | Sort-Object)
        $userIds | Should -Be @('u-1', 'u-2')
    }

    It 'breaks cycles without infinite recursion' {
        $membersByGroup = @{
            'g-a' = @([PSCustomObject]@{ MemberId = 'g-b'; MemberType = 'Group';  MemberDisplayName = 'B' })
            'g-b' = @(
                [PSCustomObject]@{ MemberId = 'g-a'; MemberType = 'Group';  MemberDisplayName = 'A' },
                [PSCustomObject]@{ MemberId = 'u-x'; MemberType = 'User';   MemberDisplayName = 'X' }
            )
        }
        $result = Get-TransitiveUserMembers -RootGroupId 'g-a' -MembersByGroupId $membersByGroup
        @($result).Count                | Should -Be 1
        @($result)[0].MemberId          | Should -Be 'u-x'
    }
}

Describe 'Resolve-EffectiveStaleness' {
    It 'returns true for null/empty sign-in' {
        Resolve-EffectiveStaleness -LastSignInDateTime $null -Now ([datetime]'2026-04-28') -ThresholdDays 90 | Should -BeTrue
        Resolve-EffectiveStaleness -LastSignInDateTime ''    -Now ([datetime]'2026-04-28') -ThresholdDays 90 | Should -BeTrue
    }

    It 'returns true when last sign-in is older than threshold' {
        Resolve-EffectiveStaleness -LastSignInDateTime '2025-01-01T00:00:00Z' -Now ([datetime]'2026-04-28') -ThresholdDays 90 | Should -BeTrue
    }

    It 'returns false when last sign-in is within threshold' {
        Resolve-EffectiveStaleness -LastSignInDateTime '2026-04-01T00:00:00Z' -Now ([datetime]'2026-04-28') -ThresholdDays 90 | Should -BeFalse
    }
}
