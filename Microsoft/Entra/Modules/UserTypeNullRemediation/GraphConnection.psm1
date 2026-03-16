if (-not (Get-Command -Name Write-Log -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'Logging.psm1') -ErrorAction Stop
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
            Write-Log('Connected to Microsoft Graph.')
            return
        }

        $currentScopes = @($mgContext.Scopes)
        $missingScopes = $RequiredScopes | Where-Object { $_ -notin $currentScopes }

        if ($missingScopes.Count -gt 0) {
            Write-Log("Connected to Graph, but missing required scopes: $($missingScopes -join ', '). Reconnecting...")
            Disconnect-MgGraph | Out-Null
            Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
            Write-Log('Reconnected to Microsoft Graph with required scopes.')
        }
        else {
            Write-Log('Existing Microsoft Graph context is valid and has required scopes.')
        }
    }
    catch {
        $errorMessage = "Microsoft Graph bootstrap failed: $($_.Exception.Message)"
        Write-Log($errorMessage)
        throw $errorMessage
    }
}

Export-ModuleMember -Function Connect-MgGraphWithRequirements