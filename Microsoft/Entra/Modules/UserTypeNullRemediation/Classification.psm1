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

function Get-OnPremisesExtensionAttributeMap {
    param([object]$OnPremisesExtensionAttributes)

    $attributeMap = [ordered]@{}

    foreach ($index in 1..15) {
        $propertyName = "ExtensionAttribute$index"
        $attributeMap[$propertyName] = if ($null -ne $OnPremisesExtensionAttributes) {
            $OnPremisesExtensionAttributes.$propertyName
        }
        else {
            $null
        }
    }

    return $attributeMap
}

function New-PolicyImpactRecord {
    param(
        [Parameter(Mandatory = $true)]
        [object]$User,

        [Parameter(Mandatory = $true)]
        [string]$Reason,

        [string]$ProposedUserType = '',

        [object]$PolicyImpact = $null,

        [string]$PreflightRunId = '',

        [string]$PreflightSummary = ''
    )

    $impact = if ($null -ne $PolicyImpact) {
        $PolicyImpact
    }
    else {
        [pscustomobject]@{
            CoverageLevel = 'NotEvaluated'
            RiskLevel = 'Unknown'
            ConditionalAccessCount = 0
            DynamicGroupRuleCount = 0
            GroupMembershipCount = 0
            AppRoleAssignmentCount = 0
            DirectoryRoleAssignmentCount = 0
            EntitlementAssignmentCount = 0
            TeamsCount = 0
            HasMailbox = $false
            BlockingFlags = ''
            Summary = 'Policy impact was not evaluated for this record.'
        }
    }

    $record = [ordered]@{
        # Band 1 — Run metadata
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        PreflightRunId = $PreflightRunId
        PreflightSummary = $PreflightSummary
        # Band 2 — User identity & org attributes
        UserPrincipalName = $User.UserPrincipalName
        DisplayName = $User.DisplayName
        Id = $User.Id
        JobTitle = $User.JobTitle
        CompanyName = $User.CompanyName
        Department = $User.Department
        OfficeLocation = $User.OfficeLocation
        AccountEnabled = $User.AccountEnabled
        CreatedDateTime = $User.CreatedDateTime
        CreationType = $User.CreationType
        ExternalUserState = $User.ExternalUserState
        OnPremisesSyncEnabled = $User.OnPremisesSyncEnabled
        OnPremisesImmutableId = $User.OnPremisesImmutableId
        OnPremisesSecurityIdentifier = $User.OnPremisesSecurityIdentifier
        AssignedLicensesCount = @($User.AssignedLicenses).Count
        IdentitiesSummary = Get-IdentitiesSummary -Identities $User.Identities
        # Band 3 — Classification decision
        CurrentUserType = $User.UserType
        ProposedUserType = $ProposedUserType
        Reason = $Reason
        # Band 4 — Policy impact
        PolicyCoverageLevel = $impact.CoverageLevel
        PolicyRiskLevel = $impact.RiskLevel
        ConditionalAccessCount = $impact.ConditionalAccessCount
        DynamicGroupRuleCount = $impact.DynamicGroupRuleCount
        GroupMembershipCount = $impact.GroupMembershipCount
        AppRoleAssignmentCount = $impact.AppRoleAssignmentCount
        DirectoryRoleAssignmentCount = $impact.DirectoryRoleAssignmentCount
        EntitlementAssignmentCount = $impact.EntitlementAssignmentCount
        TeamsCount = $impact.TeamsCount
        HasMailbox = $impact.HasMailbox
        BlockingFlags = $impact.BlockingFlags
        PolicyImpactNotes = $impact.Summary
    }
    # Include all on-premises extension attributes in the record for potential troubleshooting value, even though they are not currently used in classification logic.
    foreach ($entry in (Get-OnPremisesExtensionAttributeMap -OnPremisesExtensionAttributes $User.OnPremisesExtensionAttributes).GetEnumerator()) {
        $record[$entry.Key] = $entry.Value
    }

    return [pscustomobject]$record
}

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

Export-ModuleMember -Function Get-IdentitiesSummary, New-PolicyImpactRecord, Test-ConfidentMemberCandidate, Test-ConfidentGuestCandidate
