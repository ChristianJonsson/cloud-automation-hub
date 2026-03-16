function Get-IdentitiesSummary {
    param([object[]]$Identities)

    if (-not $Identities -or $Identities.Count -eq 0) {
        return ''
    }

    $parts = foreach ($identity in $Identities) {
        $signInType = "$($identity.SignInType)"
        $issuer = "$($identity.Issuer)"
        $issuerAssignedId = "$($identity.IssuerAssignedId)"
        "$signInType|$issuer|$issuerAssignedId"
    }

    return ($parts -join '; ')
}

function New-PolicyImpactRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [string]$ProposedUserType = ''
    )

    [pscustomobject]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        UserPrincipalName = $User.UserPrincipalName
        DisplayName = $User.DisplayName
        Id = $User.Id
        CurrentUserType = $User.UserType
        ProposedUserType = $ProposedUserType
        Reason = $Reason
        CreationType = $User.CreationType
        ExternalUserState = $User.ExternalUserState
        AccountEnabled = $User.AccountEnabled
        OnPremisesSyncEnabled = $User.OnPremisesSyncEnabled
        OnPremisesImmutableId = $User.OnPremisesImmutableId
        OnPremisesSecurityIdentifier = $User.OnPremisesSecurityIdentifier
        AssignedLicensesCount = @($User.AssignedLicenses).Count
        IdentitiesSummary = Get-IdentitiesSummary -Identities $User.Identities
        PolicyImpactNotes = 'Review Conditional Access, dynamic group rules, app/group assignments, and entitlement policies before write.'
    }
}

function Test-ConfidentMemberCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [string[]]$TenantDomains = @()
    )

    $signals = @()

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

    if ($signals.Count -gt 0) {
        return [pscustomobject]@{
            IsConfidentMember = $true
            Reason = "Confident member (synced): $($signals -join '; ')"
        }
    }

    $upn = "$($User.UserPrincipalName)"
    if ($upn -match '@') {
        $domain = ($upn.Split('@')[-1]).ToLowerInvariant()
        $knownDomains = @($TenantDomains | ForEach-Object { $_.ToLowerInvariant() })
        if ($knownDomains -contains $domain) {
            return [pscustomobject]@{
                IsConfidentMember = $true
                Reason = "Confident member (cloud-only): UPN domain '$domain' is a verified tenant domain"
            }
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

    $internalSignals = @()
    if ($User.OnPremisesSyncEnabled -eq $true) { $internalSignals += 'OnPremisesSyncEnabled=true' }
    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesImmutableId)) { $internalSignals += 'OnPremisesImmutableId present' }
    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesSecurityIdentifier)) { $internalSignals += 'OnPremisesSecurityIdentifier present' }
    if (-not [string]::IsNullOrWhiteSpace($User.OnPremisesDistinguishedName)) { $internalSignals += 'OnPremisesDistinguishedName present' }

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

    $upn = "$($User.UserPrincipalName)"
    if ($upn -match '@') {
        $domain = ($upn.Split('@')[-1]).ToLowerInvariant()
        $knownDomains = @($TenantDomains | ForEach-Object { $_.ToLowerInvariant() })
        if ($knownDomains -contains $domain) {
            return [pscustomobject]@{
                IsConfidentGuest = $false
                Reason = "UPN domain '$domain' is a verified tenant domain and no strong guest indicator is present"
            }
        }
    }

    return [pscustomobject]@{
        IsConfidentGuest = $false
        Reason = 'Insufficient evidence to classify as Guest with confidence'
    }
}

Export-ModuleMember -Function Get-IdentitiesSummary, New-PolicyImpactRecord, Test-ConfidentMemberCandidate, Test-ConfidentGuestCandidate
