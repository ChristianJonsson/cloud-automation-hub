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

# GraphConnection provides the token-age state and refresh helpers used by the
# retry wrapper (Get-GraphTokenAge, Invoke-GraphTokenRefresh).
if (-not (Get-Command -Name Get-GraphTokenAge -ErrorAction SilentlyContinue)) {
    Import-Module (Join-Path $PSScriptRoot 'GraphConnection.psm1') -ErrorAction Stop
}

function New-CacheValidationResult {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$IsReusable,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [object[]]$Users = @(),
        [string[]]$Domains = @()
    )

    return [pscustomobject]@{
        IsReusable = $IsReusable
        Reason = $Reason
        Users = @($Users)
        Domains = @($Domains)
    }
}

function Get-NormalizedNonEmptyStringArray {
    param([object]$Values)

    return @(
        @($Values) |
            ForEach-Object { "$_".Trim() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Test-IsTransientGraphError {
    param([string]$Message)

    $normalizedMessage = "$Message".ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalizedMessage)) {
        return $false
    }

    $transientTokens = @(
        'an error occurred while sending the request',
        'too many requests',
        'request timed out',
        'timed out',
        'temporarily unavailable',
        'service unavailable',
        'internal server error',
        'bad gateway',
        'gateway timeout',
        'http status code 429',
        'http status code 500',
        'http status code 502',
        'http status code 503',
        'http status code 504',
        'connection reset',
        'connection was closed',
        'task was canceled',
        'name resolution'
    )

    foreach ($token in $transientTokens) {
        if ($normalizedMessage.Contains($token)) {
            return $true
        }
    }

    return $false
}

function Test-IsAuthExpiryGraphError {
    param([string]$Message)

    $normalizedMessage = "$Message".ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalizedMessage)) {
        return $false
    }

    $authExpiryTokens = @(
        'http status code 401',
        'unauthorized',
        'token has expired',
        'token expired',
        'invalidauthenticationtoken',
        'lifetime validation failed',
        'authentication failed'
    )

    foreach ($token in $authExpiryTokens) {
        if ($normalizedMessage.Contains($token)) {
            return $true
        }
    }

    return $false
}

function Invoke-GraphOperationWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Operation,

        [Parameter(Mandatory = $true)]
        [string]$OperationName,

        [ValidateRange(1, 10)]
        [int]$MaxAttempts = 4,

        [ValidateRange(1, 60)]
        [int]$InitialDelaySeconds = 2,

        [ValidateRange(1, 120)]
        [int]$MaxDelaySeconds = 30,

        # Proactively refresh the Graph access token when its tracked age
        # reaches this many minutes, before invoking the operation. The default
        # 50 leaves a 10-minute buffer below the standard 60-minute TTL.
        [ValidateRange(1, 59)]
        [int]$ProactiveRefreshThresholdMinutes = 50
    )

    # Tracks whether the previous attempt's failure caused a reactive token
    # refresh. If we see another auth-expiry error immediately after, the
    # refresh didn't help — surface as a genuine 401 instead of looping.
    $previousAttemptRefreshedForAuth = $false

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $proactivelyRefreshedThisAttempt = $false

        $tokenAge = Get-GraphTokenAge
        if ($null -ne $tokenAge -and $tokenAge.TotalMinutes -ge $ProactiveRefreshThresholdMinutes) {
            try {
                Write-Log("Graph token age $([Math]::Round($tokenAge.TotalMinutes, 1)) min — proactive refresh before '$OperationName' (attempt $attempt).")
                Invoke-GraphTokenRefresh
                $proactivelyRefreshedThisAttempt = $true
            }
            catch {
                Write-Log("Proactive token refresh failed before '$OperationName': $($_.Exception.Message). Continuing — operation may still succeed or trigger reactive refresh.")
            }
        }

        try {
            return & $Operation
        }
        catch {
            $errorMessage = $_.Exception.Message
            $isTransient = Test-IsTransientGraphError -Message $errorMessage
            $isAuthExpiry = Test-IsAuthExpiryGraphError -Message $errorMessage

            if (-not ($isTransient -or $isAuthExpiry) -or $attempt -ge $MaxAttempts) {
                throw
            }

            if ($isAuthExpiry -and ($previousAttemptRefreshedForAuth -or $proactivelyRefreshedThisAttempt)) {
                Write-Log("Auth-expiry error during '$OperationName' persisted after token refresh — treating as genuine 401: $errorMessage")
                throw
            }

            if ($isAuthExpiry) {
                Write-Log("Auth-expiry error during '$OperationName' (attempt $attempt of $MaxAttempts): $errorMessage")
                try {
                    Invoke-GraphTokenRefresh
                    $previousAttemptRefreshedForAuth = $true
                }
                catch {
                    Write-Log("Reactive token refresh failed during '$OperationName': $($_.Exception.Message)")
                    throw
                }
            }
            else {
                Write-Log("Transient Graph error during '$OperationName' (attempt $attempt of $MaxAttempts): $errorMessage")
                $previousAttemptRefreshedForAuth = $false
            }

            $baseDelaySeconds = [Math]::Min($MaxDelaySeconds, [int]([Math]::Pow(2, $attempt - 1) * $InitialDelaySeconds))
            $jitterMilliseconds = Get-Random -Minimum 100 -Maximum 901
            $delaySeconds = [Math]::Min($MaxDelaySeconds, $baseDelaySeconds + ($jitterMilliseconds / 1000.0))

            Write-Log("Retrying '$OperationName' in $([Math]::Round($delaySeconds, 2)) seconds.")

            Start-Sleep -Milliseconds ([int]($delaySeconds * 1000))
        }
    }

    throw "Unexpected retry loop termination for operation '$OperationName'."
}

function Test-CachedUsersSelectedProperties {
    param(
        [string[]]$RequiredGraphProperties = @()
    )

    if ($RequiredGraphProperties.Count -eq 0) {
        return New-CacheValidationResult -IsReusable $true -Reason 'No required Graph property metadata provided for cache validation'
    }

    $cachedSelectionVariable = Get-Variable -Name usersSelectedProperties -Scope Global -ErrorAction SilentlyContinue
    if ($null -eq $cachedSelectionVariable) {
        return New-CacheValidationResult -IsReusable $false -Reason 'Cached users selected-properties metadata variable was not found'
    }

    $cachedSelection = @($cachedSelectionVariable.Value | ForEach-Object { "$_".ToLowerInvariant() })
    if ($cachedSelection.Count -eq 0) {
        return New-CacheValidationResult -IsReusable $false -Reason 'Cached users selected-properties metadata is empty'
    }

    $missingSelection = @(
        $RequiredGraphProperties |
            ForEach-Object { "$_".ToLowerInvariant() } |
            Where-Object { $_ -notin $cachedSelection }
    )

    if ($missingSelection.Count -gt 0) {
        return New-CacheValidationResult -IsReusable $false `
                                         -Reason "Cached users selected-properties metadata is missing required Graph fields: $($missingSelection -join ', ')"
    }

    return New-CacheValidationResult -IsReusable $true -Reason 'Cached users selected-properties metadata is valid'
}

function Get-TenantVerifiedDomains {
    if (-not (Get-Command -Name Get-MgOrganization -ErrorAction SilentlyContinue)) {
        Write-Log('Get-MgOrganization is unavailable. Domain-based confidence checks will be skipped.')
        return @()
    }

    try {
        $organization = Invoke-GraphOperationWithRetry -OperationName 'Get-MgOrganization verified domains query' -Operation {
            Get-MgOrganization -Property VerifiedDomains -ErrorAction Stop | Select-Object -First 1
        }
        $domains = @($organization.VerifiedDomains.Name | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        Write-Log("Loaded $($domains.Count) verified tenant domains for confidence checks.")
        return $domains
    }
    catch {
        Write-Log("Could not read verified tenant domains: $($_.Exception.Message). Domain-based checks will be skipped.")
        return @()
    }
}

function Test-CachedUsersData {
    param(
        [object]$CandidateUsers,
        [string[]]$RequiredProperties = @()
    )

    if ($null -eq $CandidateUsers) {
        return New-CacheValidationResult -IsReusable $false -Reason 'Cached users variable is null'
    }

    $userArray = @($CandidateUsers)
    if ($userArray.Count -eq 0) {
        return New-CacheValidationResult -IsReusable $false -Reason 'Cached users variable is empty'
    }

    $firstUser = $userArray[0]
    if ($null -eq $firstUser) {
        return New-CacheValidationResult -IsReusable $false -Reason 'First cached user entry is null'
    }

    $missingProperties = @($RequiredProperties | Where-Object { -not $firstUser.PSObject.Properties[$_] })
    if ($missingProperties.Count -gt 0) {
        return New-CacheValidationResult -IsReusable $false `
                                         -Reason "Cached users variable is missing required properties: $($missingProperties -join ', ')"
    }

    if ($RequiredProperties -contains 'OnPremisesExtensionAttributes') {
        $extensionAttributes = $firstUser.OnPremisesExtensionAttributes
        if ($null -eq $extensionAttributes) {
            return New-CacheValidationResult -IsReusable $false `
                                             -Reason 'Cached users variable is missing OnPremisesExtensionAttributes values'
        }

        $missingExtensionAttributeProperties = @(
            1..15 |
                ForEach-Object { "ExtensionAttribute$_" } |
                Where-Object { -not $extensionAttributes.PSObject.Properties[$_] }
        )

        if ($missingExtensionAttributeProperties.Count -gt 0) {
            return New-CacheValidationResult -IsReusable $false `
                                             -Reason "Cached users variable is missing extension attribute properties: $($missingExtensionAttributeProperties -join ', ')"
        }
    }

    return New-CacheValidationResult -IsReusable $true `
                                     -Reason "Cached users variable is valid. UserCount=$($userArray.Count)" `
                                     -Users $userArray
}

function Test-CachedVerifiedDomainsData {
    param(
        [object]$CandidateDomains
    )

    if ($null -eq $CandidateDomains) {
        return New-CacheValidationResult -IsReusable $false -Reason 'Cached verified domains variable is null'
    }

    $rawDomains = @($CandidateDomains)
    if ($rawDomains.Count -eq 0) {
        return New-CacheValidationResult -IsReusable $true `
                                         -Reason 'Cached verified domains variable is empty but valid'
    }

    $normalizedDomains = @(Get-NormalizedNonEmptyStringArray -Values $rawDomains)
    if ($normalizedDomains.Count -eq 0) {
        return New-CacheValidationResult -IsReusable $false `
                                         -Reason 'Cached verified domains variable contains only empty/whitespace values'
    }

    return New-CacheValidationResult -IsReusable $true `
                                     -Reason "Cached verified domains variable is valid. DomainCount=$($normalizedDomains.Count)" `
                                     -Domains $normalizedDomains
}

function Get-UsersFromGraphOrCache {
    param(
        [switch]$UseCachedGraphResults,
        [string[]]$Properties,
        [string[]]$RequiredCachedUserProperties = @()
    )

    $users = @()
    $usedCachedUsers = $false

    if ($UseCachedGraphResults) {
        $cachedUsersVariable = Get-Variable -Name users -Scope Global -ErrorAction SilentlyContinue
        $cachedSelectionValidation = Test-CachedUsersSelectedProperties -RequiredGraphProperties $Properties
        if (-not $cachedSelectionValidation.IsReusable) {
            Write-Log("Cached users variable could not be reused. Reason: $($cachedSelectionValidation.Reason)")
        }

        if ($cachedSelectionValidation.IsReusable -and $null -eq $cachedUsersVariable) {
            Write-Log('Cached users variable not found in global session scope. Live Graph query will be used.')
        }
        elseif ($cachedSelectionValidation.IsReusable) {
            $cachedUsersValidation = Test-CachedUsersData -CandidateUsers $cachedUsersVariable.Value -RequiredProperties $RequiredCachedUserProperties
            if ($cachedUsersValidation.IsReusable) {
                $users = @($cachedUsersValidation.Users)
                $usedCachedUsers = $true
                Write-Log("Using cached users variable. $($cachedUsersValidation.Reason)")
            }
            else {
                Write-Log("Cached users variable could not be reused. Reason: $($cachedUsersValidation.Reason)")
            }
        }
        elseif ($null -ne $cachedUsersVariable) {
            $cachedUsersValidation = Test-CachedUsersData -CandidateUsers $cachedUsersVariable.Value -RequiredProperties $RequiredCachedUserProperties
            if ($cachedUsersValidation.IsReusable) {
                $users = @($cachedUsersValidation.Users)
                $usedCachedUsers = $true
                $Global:usersSelectedProperties = @($Properties)
                Write-Log("Using cached users variable after direct property validation. $($cachedUsersValidation.Reason)")
            }
            else {
                Write-Log("Cached users variable could not be reused. Reason: $($cachedUsersValidation.Reason)")
            }
        }
    }

    if (-not $usedCachedUsers) {
        Write-Log('Retrieving users from Microsoft Graph... This will take several minutes...')
        $users = @(
            Invoke-GraphOperationWithRetry -OperationName 'Get-MgUser users listing query' -Operation {
                Get-MgUser -All -ConsistencyLevel eventual -Property $Properties -ErrorAction Stop
            }
        )
        $Global:usersSelectedProperties = @($Properties)
        Write-Log("Found $($users.Count) users from Graph query.")
    }
    else {
        Write-Log("Found $($users.Count) users from cached Graph results.")
    }

    return [pscustomobject]@{
        Users = $users
        UsedCache = $usedCachedUsers
    }
}

function Get-VerifiedDomainsFromGraphOrCache {
    param(
        [switch]$UseCachedGraphResults
    )

    $verifiedDomains = @()
    $usedCachedVerifiedDomains = $false

    if ($UseCachedGraphResults) {
        $cachedDomainsVariable = Get-Variable -Name verifiedDomains -Scope Global -ErrorAction SilentlyContinue
        if ($null -eq $cachedDomainsVariable) {
            Write-Log('Cached verified domains variable not found in global session scope. Live Graph query will be used.')
        }
        else {
            $cachedDomainsValidation = Test-CachedVerifiedDomainsData -CandidateDomains $cachedDomainsVariable.Value
            if ($cachedDomainsValidation.IsReusable) {
                $verifiedDomains = @($cachedDomainsValidation.Domains)
                $usedCachedVerifiedDomains = $true
                Write-Log("Using cached verified domains variable. $($cachedDomainsValidation.Reason)")
            }
            else {
                Write-Log("Cached verified domains variable could not be reused. Reason: $($cachedDomainsValidation.Reason)")
            }
        }
    }

    if (-not $usedCachedVerifiedDomains) {
        $verifiedDomains = @(Get-TenantVerifiedDomains)
    }

    return [pscustomobject]@{
        Domains = $verifiedDomains
        UsedCache = $usedCachedVerifiedDomains
    }
}

Export-ModuleMember -Function Invoke-GraphOperationWithRetry, Get-TenantVerifiedDomains, Test-CachedUsersData, Test-CachedVerifiedDomainsData, Get-UsersFromGraphOrCache, Get-VerifiedDomainsFromGraphOrCache
