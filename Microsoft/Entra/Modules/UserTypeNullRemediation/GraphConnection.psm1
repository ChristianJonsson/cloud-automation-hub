function Write-GraphBootstrapLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('Info', 'Warning')]
        [string]$Level = 'Info'
    )

    if ($Level -eq 'Warning') {
        Write-Host $Message -ForegroundColor Yellow
    }
    else {
        Write-Host $Message
    }

    if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
        Write-Log($Message)
    }
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
                Write-GraphBootstrapLog -Message "Microsoft Graph module '$moduleName' not found. Installing for current user..." -Level Warning
                Install-Module -Name $moduleName -Scope CurrentUser -Repository PSGallery -Force -ErrorAction Stop
                Write-GraphBootstrapLog -Message "Module '$moduleName' installed successfully."
            }
            else {
                Write-GraphBootstrapLog -Message "Module '$moduleName' is already installed."
            }

            if (-not (Get-Module -Name $moduleName)) {
                Import-Module $moduleName -ErrorAction Stop
                Write-GraphBootstrapLog -Message "Module '$moduleName' imported."
            }
            else {
                Write-GraphBootstrapLog -Message "Module '$moduleName' is already imported."
            }
        }

        $mgContext = Get-MgContext

        if (-not $mgContext) {
            Write-GraphBootstrapLog -Message 'No active Microsoft Graph session found. Connecting...' -Level Warning
            Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
            Write-GraphBootstrapLog -Message 'Connected to Microsoft Graph.'
            return
        }

        $currentScopes = @($mgContext.Scopes)
        $missingScopes = $RequiredScopes | Where-Object { $_ -notin $currentScopes }

        if ($missingScopes.Count -gt 0) {
            Write-GraphBootstrapLog -Message "Connected to Graph, but missing required scopes: $($missingScopes -join ', '). Reconnecting..." -Level Warning
            Disconnect-MgGraph | Out-Null
            Connect-MgGraph -Scopes $RequiredScopes -NoWelcome -ErrorAction Stop
            Write-GraphBootstrapLog -Message 'Reconnected to Microsoft Graph with required scopes.'
        }
        else {
            Write-GraphBootstrapLog -Message 'Existing Microsoft Graph context is valid and has required scopes.'
        }
    }
    catch {
        $errorMessage = "Microsoft Graph bootstrap failed: $($_.Exception.Message)"
        Write-GraphBootstrapLog -Message $errorMessage -Level Warning
        throw $errorMessage
    }
}

Export-ModuleMember -Function Connect-MgGraphWithRequirements