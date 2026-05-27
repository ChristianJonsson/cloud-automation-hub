# Pester 5 tests for the Conditional Access policy-impact evaluator.
# Run from the repo root or this folder:
#   Invoke-Pester .\Microsoft\Entra\Modules\UserTypeNullRemediation\Tests\
#
# These guard two fixes:
#   * Get-GuestOrExternalTypeString must return the GuestOrExternalUserTypes
#     string (a 'return if (...)' bug previously made it always return empty,
#     silently disabling all guest-scoped CA impact analysis).
#   * Invoke-ConditionalAccessUserImpact.MatchCount must exclude disabled
#     policies so they do not inflate the risk signal.

BeforeAll {
    $moduleRoot = Split-Path $PSScriptRoot -Parent
    . (Join-Path $moduleRoot 'PolicyImpactHelpers.ps1')
    . (Join-Path $moduleRoot 'PolicyImpact.ConditionalAccess.ps1')

    # Builds a CA policy object shaped like the Graph SDK output the evaluator reads.
    function New-CaPolicy {
        param(
            [string]$Id,
            [string]$DisplayName,
            [string]$State = 'enabled',
            [string[]]$IncludeUsers = @(),
            [string[]]$ExcludeUsers = @(),
            [string[]]$IncludeGroups = @(),
            [string[]]$ExcludeGroups = @(),
            [string]$IncludeGuestTypes = $null,
            [string]$ExcludeGuestTypes = $null
        )
        $usersCondition = [pscustomobject]@{
            IncludeUsers  = $IncludeUsers
            ExcludeUsers  = $ExcludeUsers
            IncludeGroups = $IncludeGroups
            ExcludeGroups = $ExcludeGroups
            IncludeGuestsOrExternalUsers = if ($IncludeGuestTypes) { [pscustomobject]@{ GuestOrExternalUserTypes = $IncludeGuestTypes } } else { $null }
            ExcludeGuestsOrExternalUsers = if ($ExcludeGuestTypes) { [pscustomobject]@{ GuestOrExternalUserTypes = $ExcludeGuestTypes } } else { $null }
        }
        [pscustomobject]@{
            Id          = $Id
            DisplayName = $DisplayName
            State       = $State
            Conditions  = [pscustomobject]@{ Users = $usersCondition }
        }
    }

    $script:available = @{ ConditionalAccess = 'Available' }
}

Describe 'Get-GuestOrExternalTypeString' {
    It 'returns the GuestOrExternalUserTypes string when present (regression: must not return empty)' {
        $obj = [pscustomobject]@{ GuestOrExternalUserTypes = 'b2bCollaborationGuest,internalGuest' }
        Get-GuestOrExternalTypeString -GuestOrExternalObj $obj | Should -Be 'b2bCollaborationGuest,internalGuest'
    }

    It 'returns empty string for a null object' {
        Get-GuestOrExternalTypeString -GuestOrExternalObj $null | Should -Be ''
    }

    It 'returns empty string when the property is absent' {
        Get-GuestOrExternalTypeString -GuestOrExternalObj ([pscustomobject]@{ Other = 'x' }) | Should -Be ''
    }
}

Describe 'Test-UserMatchesGuestOrExternalTypes' {
    It 'matches Guest against b2bCollaborationGuest' {
        Test-UserMatchesGuestOrExternalTypes -UserType 'Guest' -GuestOrExternalUserTypes 'b2bCollaborationGuest' | Should -BeTrue
    }
    It 'matches Guest against internalGuest' {
        Test-UserMatchesGuestOrExternalTypes -UserType 'Guest' -GuestOrExternalUserTypes 'internalGuest,b2bCollaborationMember' | Should -BeTrue
    }
    It 'matches Member against b2bCollaborationMember' {
        Test-UserMatchesGuestOrExternalTypes -UserType 'Member' -GuestOrExternalUserTypes 'b2bCollaborationMember' | Should -BeTrue
    }
    It 'does not match Member against guest-only types' {
        Test-UserMatchesGuestOrExternalTypes -UserType 'Member' -GuestOrExternalUserTypes 'b2bCollaborationGuest' | Should -BeFalse
    }
    It 'returns false for empty inputs' {
        Test-UserMatchesGuestOrExternalTypes -UserType '' -GuestOrExternalUserTypes 'b2bCollaborationGuest' | Should -BeFalse
        Test-UserMatchesGuestOrExternalTypes -UserType 'Guest' -GuestOrExternalUserTypes '' | Should -BeFalse
    }
}

Describe 'Invoke-ConditionalAccessUserImpact' {
    It 'detects a guest-scoped policy that would stop applying (regression for the empty guest-type bug)' {
        $user = [pscustomobject]@{ Id = 'u1'; UserType = 'Guest' }
        $ctx  = [pscustomobject]@{
            ConditionalAccessPolicies = @(
                New-CaPolicy -Id 'p1' -DisplayName 'Guest MFA' -IncludeGuestTypes 'b2bCollaborationGuest'
            )
        }
        $result = Invoke-ConditionalAccessUserImpact -User $user -ProposedUserType 'Member' -PolicyContext $ctx -UserGroupIds @() -UserAreaStatus $script:available
        $result.MatchCount | Should -Be 1
        $result.MatchDetails[0].ImpactDirection | Should -Be 'StopsApplying'
    }

    It 'excludes disabled policies from MatchCount but keeps them in MatchDetails' {
        $user = [pscustomobject]@{ Id = 'u1'; UserType = 'Guest' }
        $ctx  = [pscustomobject]@{
            ConditionalAccessPolicies = @(
                New-CaPolicy -Id 'p1' -DisplayName 'Enabled Guest MFA'  -State 'enabled'  -IncludeGuestTypes 'b2bCollaborationGuest'
                New-CaPolicy -Id 'p2' -DisplayName 'Disabled Guest MFA' -State 'disabled' -IncludeGuestTypes 'b2bCollaborationGuest'
            )
        }
        $result = Invoke-ConditionalAccessUserImpact -User $user -ProposedUserType 'Member' -PolicyContext $ctx -UserGroupIds @() -UserAreaStatus $script:available
        $result.MatchCount | Should -Be 1
        @($result.MatchDetails).Count | Should -Be 2
    }

    It 'returns zero matches when the area is not Available' {
        $user = [pscustomobject]@{ Id = 'u1'; UserType = 'Guest' }
        $ctx  = [pscustomobject]@{ ConditionalAccessPolicies = @(New-CaPolicy -Id 'p1' -DisplayName 'x' -IncludeGuestTypes 'b2bCollaborationGuest') }
        $result = Invoke-ConditionalAccessUserImpact -User $user -ProposedUserType 'Member' -PolicyContext $ctx -UserGroupIds @() -UserAreaStatus @{ ConditionalAccess = 'Unavailable' }
        $result.MatchCount | Should -Be 0
    }
}
