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
        $organization = Get-MgOrganization -Property VerifiedDomains -ErrorAction Stop | Select-Object -First 1
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
        $cachedSelectionValidation = Test-CachedUsersSelectedProperties -RequiredGraphProperties $Properties
        if (-not $cachedSelectionValidation.IsReusable) {
            Write-Log("Cached users variable could not be reused. Reason: $($cachedSelectionValidation.Reason)")
        }

        $cachedUsersVariable = Get-Variable -Name users -Scope Global -ErrorAction SilentlyContinue
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
    }

    if (-not $usedCachedUsers) {
        Write-Log('Retrieving users from Microsoft Graph... This will take several minutes...')
        $users = @(Get-MgUser -All -ConsistencyLevel eventual -Property $Properties)
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

Export-ModuleMember -Function Get-TenantVerifiedDomains, Test-CachedUsersData, Test-CachedVerifiedDomainsData, Get-UsersFromGraphOrCache, Get-VerifiedDomainsFromGraphOrCache
