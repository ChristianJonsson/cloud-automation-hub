function Import-SharedLoggingModule {
    if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
        return
    }

    $candidatePaths = @(
        (Join-Path $PSScriptRoot '..\..\..\Common\Modules\Shared\Logging.psm1'),
        (Join-Path $PSScriptRoot '..\UserTypeNullRemediation\Logging.psm1')
    )

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -Path $candidatePath) {
            Import-Module $candidatePath -ErrorAction Stop
            return
        }
    }

    throw 'Unable to import Logging.psm1 from shared or feature module paths.'
}

Import-SharedLoggingModule

# Module-scoped record of the most recent successful Connect-MgGraph call from
# this session. Get-MgContext does not expose the bearer token's expiry in
# Graph PowerShell SDK 2.x, so the retry wrapper uses this timestamp to
# proactively refresh before the default 60-minute access-token TTL elapses.
# Null when an existing pre-session context was reused (token age unknown — in
# that case only reactive 401 handling kicks in).
$script:GraphTokenAcquiredAt = $null

function Set-GraphTokenAcquiredAt {
    param([datetime]$AcquiredAt = (Get-Date))
    $script:GraphTokenAcquiredAt = $AcquiredAt
}

function Get-GraphTokenAcquiredAt {
    return $script:GraphTokenAcquiredAt
}

function Get-GraphTokenAge {
    if ($null -eq $script:GraphTokenAcquiredAt) {
        return $null
    }
    return (Get-Date) - $script:GraphTokenAcquiredAt
}

function Invoke-GraphTokenRefresh {
    $existingContext = Get-MgContext
    if ($null -eq $existingContext) {
        throw 'Cannot refresh Microsoft Graph token: no active context.'
    }

    $scopes = @($existingContext.Scopes)
    Write-Log("Refreshing Microsoft Graph access token (reconnecting with $($scopes.Count) scope(s))...")
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
    Set-GraphTokenAcquiredAt
    Write-Log('Microsoft Graph access token refreshed.')
}

function Connect-MgGraphWithRequirements {
    [CmdletBinding()]
    param(
        [string[]]$GraphModuleNames = @('Microsoft.Graph.Users', 'Microsoft.Graph.Identity.DirectoryManagement'),

        [string[]]$RequiredScopes = @('User.Read.All', 'User.ReadWrite.All')
    )

    try {
        foreach ($moduleName in $GraphModuleNames) {
            if (-not (Get-Module -ListAvailable -Name $moduleName)) {
                Write-Log("Microsoft Graph module '$moduleName' not found. Installing for current user...")
                Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
                Write-Log("Module '$moduleName' installed successfully.")
            }
            else {
                Write-Log("Module '$moduleName' is already installed.")
            }

            if (-not (Get-Module -Name $moduleName)) {
                Import-Module $moduleName -ErrorAction Stop
                Write-Log("Module '$moduleName' imported.")
            }
            else {
                Write-Log("Module '$moduleName' is already imported.")
            }
        }

        $mgContext = Get-MgContext

        if (-not $mgContext) {
            Write-Log('No active Microsoft Graph session found. Connecting...')
            Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
            Set-GraphTokenAcquiredAt
            Write-Log('Connected to Microsoft Graph.')
            return
        }

        $currentScopes = @($mgContext.Scopes)
        $missingScopes = $RequiredScopes | Where-Object { $_ -notin $currentScopes }

        if ($missingScopes.Count -gt 0) {
            Write-Log("Connected to Graph, but missing required scopes: $($missingScopes -join ', '). Reconnecting...")
            Disconnect-MgGraph | Out-Null
            Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
            Set-GraphTokenAcquiredAt
            Write-Log('Reconnected to Microsoft Graph with required scopes.')
        }
        else {
            # Pre-existing context reused — token age unknown, leave acquired-at
            # null so the proactive refresh check is a no-op. Reactive 401
            # handling still applies if the token is in fact expired.
            Write-Log('Existing Microsoft Graph context is valid and has required scopes.')
        }
    }
    catch {
        $errorMessage = "Microsoft Graph bootstrap failed: $($_.Exception.Message)"
        Write-Log($errorMessage)
        throw $errorMessage
    }
}

Export-ModuleMember -Function Connect-MgGraphWithRequirements, Invoke-GraphTokenRefresh, Set-GraphTokenAcquiredAt, Get-GraphTokenAcquiredAt, Get-GraphTokenAge
