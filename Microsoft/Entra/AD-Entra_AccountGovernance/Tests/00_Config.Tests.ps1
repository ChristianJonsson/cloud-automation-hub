# Pester 5 tests for the pure helper functions in 00_Config.ps1.
# Run from the repo root or this folder:
#   Invoke-Pester .\Microsoft\Entra\AD-Entra_AccountGovernance\Tests\

BeforeAll {
    # Dot-sourcing 00_Config defines the helpers (and creates the gitignored
    # Output\ directory as a side effect, which is harmless for the test run).
    . "$PSScriptRoot\..\00_Config.ps1"
}

Describe 'ConvertTo-SafeFileNameToken' {
    It 'leaves a normal forest name (including dots) unchanged' {
        ConvertTo-SafeFileNameToken -Token 'corp.local' | Should -Be 'corp.local'
    }

    It 'replaces path separators and other illegal characters with underscores' {
        # Build a token from genuinely illegal filename characters so the test is
        # platform-accurate rather than assuming a specific set.
        $illegal = [System.IO.Path]::GetInvalidFileNameChars() | Select-Object -First 1
        $result = ConvertTo-SafeFileNameToken -Token "a$($illegal)b"
        $result | Should -Be 'a_b'
    }

    It 'produces a name with no remaining illegal characters' {
        $token = 'we:ird\name/with*chars?'
        $result = ConvertTo-SafeFileNameToken -Token $token
        $invalid = [System.IO.Path]::GetInvalidFileNameChars()
        ($result.ToCharArray() | Where-Object { $invalid -contains $_ }).Count | Should -Be 0
    }

    It 'handles an empty string' {
        ConvertTo-SafeFileNameToken -Token '' | Should -Be ''
    }
}

Describe 'Get-RunFileSuffix' {
    It 'formats a date as yyyyMMdd_HHmm' {
        Get-RunFileSuffix -RunDate ([datetime]'2026-05-27T14:09:00') | Should -Be '20260527_1409'
    }
}

Describe 'ConvertTo-RunFileSuffix' {
    It 'round-trips a valid run directory name' {
        ConvertTo-RunFileSuffix -DirectoryName '2026-05-27_140905' | Should -Be '20260527_1409'
    }

    It 'returns $null for an unparseable directory name' {
        ConvertTo-RunFileSuffix -DirectoryName 'not-a-timestamp' | Should -BeNullOrEmpty
    }
}
