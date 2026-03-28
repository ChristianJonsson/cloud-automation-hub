function Import-SharedLoggingModule {
    if (Get-Command -Name Write-Log -ErrorAction SilentlyContinue) {
        return
    }

    $candidatePaths = @(
        (Join-Path $PSScriptRoot '..\..\..\Common\Modules\Shared\Logging.psm1'),
        (Join-Path $PSScriptRoot 'Logging.psm1')
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

function Get-ClassificationMethod {
    param(
        [string]$Reason,
        [string]$ProposedUserType
    )

    if ([string]::IsNullOrWhiteSpace($ProposedUserType)) {
        if ($Reason -match '(?i)conflict') { return 'ConflictingSignals' }
        return 'Skipped'
    }
    if ($Reason -match '(?i)(synced|OnPremises.*Sync|Sync.*Enabled)') { return 'Synced' }
    if ($Reason -match '(?i)cloud-only') { return 'CloudOnlyDomainMatch' }
    if ($Reason -match '#EXT#') { return 'EXT_HashUPN' }
    if ($Reason -match '(?i)ExternalUserState') { return 'ExternalUserState' }
    if ($Reason -match '(?i)(Invitation|CreationType)') { return 'Invitation' }
    return 'Unknown'
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

        [string]$PreflightSummary = '',

        [string]$MemberClassificationReason = '',

        [string]$GuestClassificationReason = ''
    )

    $impact = if ($null -ne $PolicyImpact) {
        $PolicyImpact
    }
    else {
        [pscustomobject]@{
            CoverageLevel = 'NotEvaluated'
            RiskLevel = 'Unknown'
            ConditionalAccessCount = 0
            ConditionalAccessPolicyNames = ''
            ConditionalAccessDirections = ''
            ConditionalAccessPolicyTransitions = ''
            ConditionalAccessPolicyDetailsJson = '[]'
            DynamicGroupRuleCount = 0
            DynamicGroupNames = ''
            DynamicGroupImpactDirections = ''
            DynamicGroupImpactDetailsJson = '[]'
            GroupMembershipCount = 0
            GroupMembershipNames = ''
            GroupMembershipDetailsJson = '[]'
            AppRoleAssignmentCount = 0
            AppRoleAssignmentNames = ''
            AppRoleAssignmentDetailsJson = '[]'
            DirectoryRoleAssignmentCount = 0
            DirectoryRoleNames = ''
            DirectoryRoleDetailsJson = '[]'
            EligibleDirectoryRoleCount = 0
            EligibleDirectoryRoleNames = ''
            EligibleDirectoryRoleDetailsJson = '[]'
            EntitlementAssignmentCount = 0
            EntitlementPackageNames = ''
            EntitlementPackageDetailsJson = '[]'
            LicensingImpactCount = 0
            LicensingImpactDirections = ''
            LicensingImpactNames = ''
            LicensingAssignedNames = ''
            LicensingImpactDetailsJson = '[]'
            TeamsCount = 0
            HasMailbox = $false
            BlockingFlags = ''
            Summary = 'Policy impact was not evaluated for this record.'
        }
    }

    # Derived classification fields.
    $classificationMethod = Get-ClassificationMethod -Reason $Reason -ProposedUserType $ProposedUserType

    # Provisioning errors — flag users with outstanding errors before any userType write.
    $hasProvisioningErrors = $false
    $provisioningErrorSummary = ''
    try {
        $provErrors = @($User.ServiceProvisioningErrors)
        if ($provErrors.Count -gt 0) {
            $hasProvisioningErrors = $true
            $provisioningErrorSummary = @(
                $provErrors | Select-Object -First 3 | ForEach-Object { "$_" } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            ) -join '; '
        }
    }
    catch { }

    # Sign-in activity — populated when 'signInActivity' is included in the user query
    # (requires AuditLog.Read.All scope). Columns are blank until that scope is added.
    $lastSignInDateTime = $null
    $daysSinceLastSignIn = $null
    if ($null -ne $User.SignInActivity) {
        try {
            $rawLastSignIn = $User.SignInActivity.LastSignInDateTime
            if ($null -ne $rawLastSignIn) {
                $lastSignInDateTime = "$rawLastSignIn"
                $parsedSignIn = [DateTime]::Parse("$rawLastSignIn", [System.Globalization.CultureInfo]::InvariantCulture)
                $daysSinceLastSignIn = [int]((Get-Date).ToUniversalTime() - $parsedSignIn.ToUniversalTime()).TotalDays
            }
        }
        catch { }
    }

    # Plain-English change description — one-line summary usable directly in a spreadsheet review.
    $currentTypeDisplay = if ([string]::IsNullOrWhiteSpace("$($User.UserType)")) { 'null' } else { "$($User.UserType)" }
    $proposedTypeDisplay = if ([string]::IsNullOrWhiteSpace($ProposedUserType)) { 'Skipped' } else { $ProposedUserType }
    $descParts = @("$currentTypeDisplay -> $proposedTypeDisplay", "Risk: $($impact.RiskLevel)")
    if ($impact.ConditionalAccessCount -gt 0) {
        $descParts += "CA: $($impact.ConditionalAccessCount) ($($impact.ConditionalAccessDirections))"
    }
    else { $descParts += 'CA: 0' }
    if ($impact.DynamicGroupRuleCount -gt 0) {
        $descParts += "DynGroups: $($impact.DynamicGroupRuleCount) ($($impact.DynamicGroupImpactDirections))"
    }
    else { $descParts += 'DynGroups: 0' }
    if ($impact.EntitlementAssignmentCount -gt 0) { $descParts += "Entitlements: $($impact.EntitlementAssignmentCount)" }
    if ($impact.DirectoryRoleAssignmentCount -gt 0) { $descParts += "Roles: $($impact.DirectoryRoleAssignmentCount)" }
    if ($impact.EligibleDirectoryRoleCount -gt 0) { $descParts += "EligibleRoles: $($impact.EligibleDirectoryRoleCount)" }
    if ($impact.LicensingImpactCount -gt 0) {
        $licNote = "Licensing: $($impact.LicensingImpactDirections)"
        if (-not [string]::IsNullOrWhiteSpace($impact.LicensingImpactNames)) {
            $licNote += " [$($impact.LicensingImpactNames)]"
        }
        $descParts += $licNote
    }
    if (-not [string]::IsNullOrWhiteSpace($impact.BlockingFlags)) { $descParts += "Flags: $($impact.BlockingFlags)" }
    $changeDescription = $descParts -join ' | '

    $record = [ordered]@{
        TimestampUtc                     = (Get-Date).ToUniversalTime().ToString('o')
        PreflightRunId                   = $PreflightRunId
        PreflightSummary                 = $PreflightSummary
        UserPrincipalName                = $User.UserPrincipalName
        DisplayName                      = $User.DisplayName
        Id                               = $User.Id
        Mail                             = $User.Mail
        JobTitle                         = $User.JobTitle
        CompanyName                      = $User.CompanyName
        Department                       = $User.Department
        OfficeLocation                   = $User.OfficeLocation
        AccountEnabled                   = $User.AccountEnabled
        CreatedDateTime                  = $User.CreatedDateTime
        CreationType                     = $User.CreationType
        ExternalUserState                = $User.ExternalUserState
        OnPremisesSyncEnabled            = $User.OnPremisesSyncEnabled
        OnPremisesLastSyncDateTime       = $User.OnPremisesLastSyncDateTime
        OnPremisesImmutableId            = $User.OnPremisesImmutableId
        OnPremisesSecurityIdentifier     = $User.OnPremisesSecurityIdentifier
        AssignedLicensesCount            = @($User.AssignedLicenses).Count
        HasProvisioningErrors            = $hasProvisioningErrors
        ProvisioningErrorSummary         = $provisioningErrorSummary
        LastSignInDateTime               = $lastSignInDateTime
        DaysSinceLastSignIn              = $daysSinceLastSignIn
        IdentitiesSummary                = Get-IdentitiesSummary -Identities $User.Identities
        CurrentUserType                  = $User.UserType
        ProposedUserType                 = $ProposedUserType
        Reason                           = $Reason
        ClassificationMethod             = $classificationMethod
        MemberClassificationReason       = $MemberClassificationReason
        GuestClassificationReason        = $GuestClassificationReason
        ChangeDescription                = $changeDescription
        PolicyCoverageLevel              = $impact.CoverageLevel
        PolicyRiskLevel                  = $impact.RiskLevel
        ConditionalAccessCount           = $impact.ConditionalAccessCount
        ConditionalAccessPolicyNames     = $impact.ConditionalAccessPolicyNames
        ConditionalAccessDirections      = $impact.ConditionalAccessDirections
        ConditionalAccessPolicyTransitions = $impact.ConditionalAccessPolicyTransitions
        ConditionalAccessPolicyDetailsJson = $impact.ConditionalAccessPolicyDetailsJson
        DynamicGroupRuleCount            = $impact.DynamicGroupRuleCount
        DynamicGroupNames                = $impact.DynamicGroupNames
        DynamicGroupImpactDirections     = $impact.DynamicGroupImpactDirections
        DynamicGroupImpactDetailsJson    = $impact.DynamicGroupImpactDetailsJson
        GroupMembershipCount             = $impact.GroupMembershipCount
        GroupMembershipNames             = $impact.GroupMembershipNames
        GroupMembershipDetailsJson       = $impact.GroupMembershipDetailsJson
        AppRoleAssignmentCount           = $impact.AppRoleAssignmentCount
        AppRoleAssignmentNames           = $impact.AppRoleAssignmentNames
        AppRoleAssignmentDetailsJson     = $impact.AppRoleAssignmentDetailsJson
        DirectoryRoleAssignmentCount     = $impact.DirectoryRoleAssignmentCount
        DirectoryRoleNames               = $impact.DirectoryRoleNames
        DirectoryRoleDetailsJson         = $impact.DirectoryRoleDetailsJson
        EligibleDirectoryRoleCount       = $impact.EligibleDirectoryRoleCount
        EligibleDirectoryRoleNames       = $impact.EligibleDirectoryRoleNames
        EligibleDirectoryRoleDetailsJson = $impact.EligibleDirectoryRoleDetailsJson
        EntitlementAssignmentCount       = $impact.EntitlementAssignmentCount
        EntitlementPackageNames          = $impact.EntitlementPackageNames
        EntitlementPackageDetailsJson    = $impact.EntitlementPackageDetailsJson
        LicensingImpactCount             = $impact.LicensingImpactCount
        LicensingImpactDirections        = $impact.LicensingImpactDirections
        LicensingImpactNames             = $impact.LicensingImpactNames
        LicensingAssignedNames           = $impact.LicensingAssignedNames
        LicensingImpactDetailsJson       = $impact.LicensingImpactDetailsJson
        TeamsCount                       = $impact.TeamsCount
        HasMailbox                       = $impact.HasMailbox
        BlockingFlags                    = $impact.BlockingFlags
        PolicyImpactNotes                = $impact.Summary
    }

    foreach ($entry in (Get-OnPremisesExtensionAttributeMap -OnPremisesExtensionAttributes $User.OnPremisesExtensionAttributes).GetEnumerator()) {
        $record[$entry.Key] = $entry.Value
    }

    return [pscustomobject]$record
}

function Initialize-DirectoryIfNeeded {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [bool]$Condition = $true
    )

    if ($Condition -and -not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force -WhatIf:$false | Out-Null
    }
}

function Export-PolicyImpactCsvIfAny {
    param(
        [object[]]$Candidates = @(),

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$ProposedUserType = '',

        [Parameter(Mandatory = $true)]
        [string]$SuccessPrefix,

        [Parameter(Mandatory = $true)]
        [string]$EmptyMessage,

        [string]$PreflightRunId = '',

        [string]$PreflightSummary = ''
    )

    $candidateArray = @($Candidates)
    if ($candidateArray.Count -eq 0) {
        Write-Log($EmptyMessage)
        return
    }

    $exportRows = $candidateArray | ForEach-Object {
        $resolvedProposedUserType = if (-not [string]::IsNullOrWhiteSpace($ProposedUserType)) {
            $ProposedUserType
        }
        else {
            "$($_.ProposedUserType)"
        }

        New-PolicyImpactRecord `
            -User $_.User `
            -Reason $_.Reason `
            -ProposedUserType $resolvedProposedUserType `
            -PolicyImpact $_.PolicyImpact `
            -PreflightRunId $PreflightRunId `
            -PreflightSummary $PreflightSummary `
            -MemberClassificationReason "$($_.MemberReason)" `
            -GuestClassificationReason "$($_.GuestReason)"
    }

    try {
        Initialize-DirectoryIfNeeded -Path (Split-Path -Path $Path -Parent)
        $exportRows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -WhatIf:$false
        Write-Log("${SuccessPrefix}: $Path")
    }
    catch {
        $exportError = "Failed to export policy impact CSV '$Path': $($_.Exception.Message)"
        Write-Log($exportError)
        Write-Error $exportError -ErrorAction Stop
    }
}

Export-ModuleMember -Function Initialize-DirectoryIfNeeded, Export-PolicyImpactCsvIfAny
