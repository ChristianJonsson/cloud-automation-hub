function Get-OnPremisesSyncSignals {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    $signals = @()

    if ($User.OnPremisesSyncEnabled -eq $true) {
        $signals += 'OnPremisesSyncEnabled=true'
    }

    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesImmutableId)) {
        $signals += 'OnPremisesImmutableId present'
    }

    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesSecurityIdentifier)) {
        $signals += 'OnPremisesSecurityIdentifier present'
    }

    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesDistinguishedName)) {
        $signals += 'OnPremisesDistinguishedName present'
    }

    return $signals
}

function Get-UpnDomain {
    param([string]$UserPrincipalName)

    $upn = "$UserPrincipalName"
    if ($upn -notmatch '@') {
        return ''
    }

    return ($upn.Split('@')[-1]).ToLowerInvariant()
}

function Test-VerifiedTenantDomainMatch {
    param(
        [string]$UserPrincipalName,
        [string[]]$TenantDomains = @()
    )

    $domain = Get-UpnDomain -UserPrincipalName $UserPrincipalName
    if ([string]::IsNullOrWhiteSpace($domain)) {
        return [pscustomobject]@{
            IsMatch = $false
            Domain = ''
        }
    }

    $knownDomains = @($TenantDomains | ForEach-Object { "$_".ToLowerInvariant() })

    return [pscustomobject]@{
        IsMatch = ($knownDomains -contains $domain)
        Domain = $domain
    }
}

function Test-ConfidentMemberCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [string[]]$TenantDomains = @()
    )

    if (-not [string]::IsNullOrWhiteSpace($User.UserType)) {
        return [pscustomobject]@{
            IsConfidentMember = $false
            Reason = "UserType already set to '$($User.UserType)'"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($User.UserPrincipalName) -and $User.UserPrincipalName -match '#EXT#') {
        return [pscustomobject]@{
            IsConfidentMember = $false
            Reason = 'Guest indicator: UPN contains #EXT#'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($User.ExternalUserState)) {
        return [pscustomobject]@{
            IsConfidentMember = $false
            Reason = "Guest indicator: ExternalUserState = '$($User.ExternalUserState)'"
        }
    }

    if ($User.CreationType -eq 'Invitation') {
        return [pscustomobject]@{
            IsConfidentMember = $false
            Reason = "Guest indicator: CreationType = '$($User.CreationType)'"
        }
    }

    $signals = @(Get-OnPremisesSyncSignals -User $User)

    if ($signals.Count -gt 0) {
        return [pscustomobject]@{
            IsConfidentMember = $true
            Reason = "Confident member (synced): $($signals -join '; ')"
        }
    }

    $domainMatch = Test-VerifiedTenantDomainMatch -UserPrincipalName $User.UserPrincipalName -TenantDomains $TenantDomains
    if ($domainMatch.IsMatch) {
        return [pscustomobject]@{
            IsConfidentMember = $true
            Reason = "Confident member (cloud-only): UPN domain '$($domainMatch.Domain)' is a verified tenant domain"
        }
    }

    return [pscustomobject]@{
        IsConfidentMember = $false
        Reason = 'Insufficient evidence to classify as Member with confidence'
    }
}

function Test-ConfidentGuestCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [string[]]$TenantDomains = @()
    )

    if (-not [string]::IsNullOrWhiteSpace($User.UserType)) {
        return [pscustomobject]@{
            IsConfidentGuest = $false
            Reason = "UserType already set to '$($User.UserType)'"
        }
    }

    $internalSignals = @(Get-OnPremisesSyncSignals -User $User)

    if ($internalSignals.Count -gt 0) {
        return [pscustomobject]@{
            IsConfidentGuest = $false
            Reason = "Internal/synced indicator(s): $($internalSignals -join '; ')"
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($User.UserPrincipalName) -and $User.UserPrincipalName -match '#EXT#') {
        return [pscustomobject]@{
            IsConfidentGuest = $true
            Reason = 'Confident guest: UPN contains #EXT#'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($User.ExternalUserState)) {
        return [pscustomobject]@{
            IsConfidentGuest = $true
            Reason = "Confident guest: ExternalUserState = '$($User.ExternalUserState)'"
        }
    }

    if ($User.CreationType -eq 'Invitation') {
        return [pscustomobject]@{
            IsConfidentGuest = $true
            Reason = "Confident guest: CreationType = '$($User.CreationType)'"
        }
    }

    $domainMatch = Test-VerifiedTenantDomainMatch -UserPrincipalName $User.UserPrincipalName -TenantDomains $TenantDomains
    if ($domainMatch.IsMatch) {
        return [pscustomobject]@{
            IsConfidentGuest = $false
            Reason = "UPN domain '$($domainMatch.Domain)' is a verified tenant domain and no strong guest indicator is present"
        }
    }

    return [pscustomobject]@{
        IsConfidentGuest = $false
        Reason = 'Insufficient evidence to classify as Guest with confidence'
    }
}

Export-ModuleMember -Function Test-ConfidentMemberCandidate, Test-ConfidentGuestCandidate
