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
            ConditionalAccessPolicyNames = ''
            ConditionalAccessPolicyDetailsJson = '[]'
            DynamicGroupRuleCount = 0
            DynamicGroupNames = ''
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
            EntitlementAssignmentCount = 0
            EntitlementPackageNames = ''
            EntitlementPackageDetailsJson = '[]'
            TeamsCount = 0
            HasMailbox = $false
            BlockingFlags = ''
            Summary = 'Policy impact was not evaluated for this record.'
        }
    }

    $record = [ordered]@{
        TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
        PreflightRunId = $PreflightRunId
        PreflightSummary = $PreflightSummary
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
        CurrentUserType = $User.UserType
        ProposedUserType = $ProposedUserType
        Reason = $Reason
        PolicyCoverageLevel = $impact.CoverageLevel
        PolicyRiskLevel = $impact.RiskLevel
        ConditionalAccessCount = $impact.ConditionalAccessCount
        ConditionalAccessPolicyNames = $impact.ConditionalAccessPolicyNames
        ConditionalAccessPolicyDetailsJson = $impact.ConditionalAccessPolicyDetailsJson
        DynamicGroupRuleCount = $impact.DynamicGroupRuleCount
        DynamicGroupNames = $impact.DynamicGroupNames
        DynamicGroupImpactDetailsJson = $impact.DynamicGroupImpactDetailsJson
        GroupMembershipCount = $impact.GroupMembershipCount
        GroupMembershipNames = $impact.GroupMembershipNames
        GroupMembershipDetailsJson = $impact.GroupMembershipDetailsJson
        AppRoleAssignmentCount = $impact.AppRoleAssignmentCount
        AppRoleAssignmentNames = $impact.AppRoleAssignmentNames
        AppRoleAssignmentDetailsJson = $impact.AppRoleAssignmentDetailsJson
        DirectoryRoleAssignmentCount = $impact.DirectoryRoleAssignmentCount
        DirectoryRoleNames = $impact.DirectoryRoleNames
        DirectoryRoleDetailsJson = $impact.DirectoryRoleDetailsJson
        EntitlementAssignmentCount = $impact.EntitlementAssignmentCount
        EntitlementPackageNames = $impact.EntitlementPackageNames
        EntitlementPackageDetailsJson = $impact.EntitlementPackageDetailsJson
        TeamsCount = $impact.TeamsCount
        HasMailbox = $impact.HasMailbox
        BlockingFlags = $impact.BlockingFlags
        PolicyImpactNotes = $impact.Summary
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

        New-PolicyImpactRecord -User $_.User -Reason $_.Reason -ProposedUserType $resolvedProposedUserType -PolicyImpact $_.PolicyImpact -PreflightRunId $PreflightRunId -PreflightSummary $PreflightSummary
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