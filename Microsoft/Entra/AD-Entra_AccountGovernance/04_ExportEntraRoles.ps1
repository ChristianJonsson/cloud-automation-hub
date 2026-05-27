# ==============================================================================
# 04_ExportEntraRoles.ps1
# Purpose : Export Entra directory role definitions and assignments (active +
#           PIM-eligible) for downstream admin summary and reporting.
# Run on  : Any machine with Microsoft.Graph.Identity.Governance available
# Output  : <RunOutputPath>\Entra_RoleDefinitions_<RunFileSuffix>.ndjson
#           <RunOutputPath>\Entra_RoleAssignments_<RunFileSuffix>.ndjson
#           <RunOutputPath>\Entra_RoleEligibilities_<RunFileSuffix>.ndjson
# Requires: 00_Config.ps1 (shared configuration)
#
# PIM behaviour:
#   When $IncludePimEligibilities = $false, the eligibility query is skipped
#   entirely. When $true (default), the query runs but is wrapped in try/catch
#   so tenants without Entra ID P2 (or with restricted permissions) get an
#   empty eligibilities file rather than aborting the run.
# ==============================================================================

. "$PSScriptRoot\00_Config.ps1"

# --- Module imports -----------------------------------------------------------
$loggingModulePath   = Join-Path $PSScriptRoot '..\..\Common\Modules\Shared\Logging.psm1'
$graphConnModulePath = Join-Path $PSScriptRoot '..\Modules\Shared\GraphConnection.psm1'
$graphDataModulePath = Join-Path $PSScriptRoot '..\Modules\Shared\GraphData.psm1'

Import-Module $loggingModulePath   -Force -ErrorAction Stop
Import-Module $graphConnModulePath -Force -ErrorAction Stop
Import-Module $graphDataModulePath -Force -ErrorAction Stop

# --- Run output directory -----------------------------------------------------
$resolvedRun  = Resolve-RunOutputPath -OutputPathRoot $OutputPath `
                                      -ExistingPath (Get-Variable -Name RunOutputPath -ValueOnly -ErrorAction SilentlyContinue)
$RunOutputPath = $resolvedRun.RunOutputPath
$RunFileSuffix = $resolvedRun.RunFileSuffix
Set-LogFilePath -Path (Join-Path $RunOutputPath 'AccountGovernance.log')
Write-Log "=== 04_ExportEntraRoles started (IncludePimEligibilities: $IncludePimEligibilities) ==="

# --- Connect to Microsoft Graph -----------------------------------------------
Connect-MgGraphWithRequirements `
    -GraphModuleNames @('Microsoft.Graph.Identity.Governance') `
    -RequiredScopes @('RoleManagement.Read.Directory', 'Directory.Read.All')

# --- Helpers ------------------------------------------------------------------
# The Principal navigation property comes back as a generic DirectoryObject
# whose concrete type (User / Group / ServicePrincipal) lives in @odata.type.
function Resolve-PrincipalType {
    param($Principal)

    if ($null -eq $Principal -or $null -eq $Principal.AdditionalProperties) {
        return $null
    }

    $odataType = $Principal.AdditionalProperties['@odata.type']
    switch ($odataType) {
        '#microsoft.graph.user'             { return 'User' }
        '#microsoft.graph.group'            { return 'Group' }
        '#microsoft.graph.servicePrincipal' { return 'ServicePrincipal' }
        default                             { return ($odataType -replace '^#microsoft\.graph\.', '') }
    }
}

function Flatten-RoleDefinition ($definition) {
    [PSCustomObject]@{
        Id              = $definition.Id
        TemplateId      = $definition.TemplateId
        DisplayName     = $definition.DisplayName
        Description     = $definition.Description
        IsBuiltIn       = $definition.IsBuiltIn
        IsEnabled       = $definition.IsEnabled
        Version         = $definition.Version
        RolePermissions = @($definition.RolePermissions | ForEach-Object {
                              [PSCustomObject]@{
                                  AllowedResourceActions = @($_.AllowedResourceActions)
                                  ExcludedResourceActions = @($_.ExcludedResourceActions)
                                  Condition              = $_.Condition
                              }
                          })
    }
}

function Flatten-RoleAssignment ($assignment, [string]$AssignmentType, $ExtraFields = $null) {
    $principal = $assignment.Principal
    $principalType        = Resolve-PrincipalType $principal
    $principalDisplayName = $null
    $principalUpn         = $null

    if ($null -ne $principal -and $null -ne $principal.AdditionalProperties) {
        $principalDisplayName = $principal.AdditionalProperties['displayName']
        if ($principalType -eq 'User') {
            $principalUpn = $principal.AdditionalProperties['userPrincipalName']
        }
    }

    $record = [ordered]@{
        Id                         = $assignment.Id
        RoleDefinitionId           = $assignment.RoleDefinitionId
        PrincipalId                = $assignment.PrincipalId
        PrincipalType              = $principalType
        PrincipalDisplayName       = $principalDisplayName
        PrincipalUserPrincipalName = $principalUpn
        DirectoryScopeId           = $assignment.DirectoryScopeId
        AppScopeId                 = $assignment.AppScopeId
        AssignmentType             = $AssignmentType
    }

    if ($null -ne $ExtraFields) {
        foreach ($key in $ExtraFields.Keys) {
            $record[$key] = $ExtraFields[$key]
        }
    }

    [PSCustomObject]$record
}

# --- 1. Role definitions ------------------------------------------------------
Write-Log 'Fetching directory role definitions...'
$roleDefinitions = Invoke-GraphOperationWithRetry -OperationName 'Get-MgRoleManagementDirectoryRoleDefinition listing' -Operation {
    Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop
}
Write-Log "  Count: $($roleDefinitions.Count)"

$roleDefinitionsFile = "Entra_RoleDefinitions_$RunFileSuffix.ndjson"
$roleDefinitions | ForEach-Object { Flatten-RoleDefinition $_ | ConvertTo-Json -Compress -Depth 5 } |
    Out-File (Join-Path $RunOutputPath $roleDefinitionsFile) -Encoding UTF8
Write-Log "  Written -> $roleDefinitionsFile"

# --- 2. Active role assignments -----------------------------------------------
Write-Log 'Fetching active directory role assignments...'
$roleAssignments = Invoke-GraphOperationWithRetry -OperationName 'Get-MgRoleManagementDirectoryRoleAssignment listing' -Operation {
    Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop
}
Write-Log "  Count: $($roleAssignments.Count)"

$roleAssignmentsFile = "Entra_RoleAssignments_$RunFileSuffix.ndjson"
$roleAssignments | ForEach-Object { Flatten-RoleAssignment $_ 'Active' | ConvertTo-Json -Compress -Depth 5 } |
    Out-File (Join-Path $RunOutputPath $roleAssignmentsFile) -Encoding UTF8
Write-Log "  Written -> $roleAssignmentsFile"

# --- 3. PIM eligible role assignments -----------------------------------------
$roleEligibilities = @()
$roleEligibilitiesFile = "Entra_RoleEligibilities_$RunFileSuffix.ndjson"
$eligibilitiesPath = Join-Path $RunOutputPath $roleEligibilitiesFile

if (-not $IncludePimEligibilities) {
    Write-Log 'Skipping PIM eligibility query (IncludePimEligibilities = $false). Writing empty file.'
    '' | Out-File $eligibilitiesPath -Encoding UTF8
    Clear-Content $eligibilitiesPath
} else {
    Write-Log 'Fetching PIM-eligible directory role assignments...'
    try {
        $roleEligibilities = Invoke-GraphOperationWithRetry -OperationName 'Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance listing' -Operation {
            Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal -ErrorAction Stop
        }
        Write-Log "  Count: $($roleEligibilities.Count)"

        $roleEligibilities | ForEach-Object {
            $extras = [ordered]@{
                StartDateTime = $_.StartDateTime
                EndDateTime   = $_.EndDateTime
                MemberType    = $_.MemberType
            }
            Flatten-RoleAssignment $_ 'Eligible' $extras | ConvertTo-Json -Compress -Depth 5
        } | Out-File $eligibilitiesPath -Encoding UTF8

        Write-Log "  Written -> $roleEligibilitiesFile"
    }
    catch {
        $msg = $_.Exception.Message
        # Prefer the HTTP status code (locale-independent) and fall back to message
        # matching. PIM eligibility is unavailable without Entra ID P2 (or with
        # insufficient consent), which surfaces as 401/402/403 or a licensing message.
        $statusCode = $null
        try { $statusCode = [int]$_.Exception.Response.StatusCode } catch { }
        $isLicenseOrAuth = ($statusCode -in 401, 402, 403) -or
            ($msg -match 'licen[sc]|premium|\bP2\b|subscription|authorization_requestdenied|forbidden|unauthorized|tenant does not have|not licensed')
        if ($isLicenseOrAuth) {
            Write-Log "  WARNING: PIM eligibility query failed (likely no Entra ID P2 license or insufficient permissions): $msg"
            Write-Log "  Writing empty $roleEligibilitiesFile and continuing."
            '' | Out-File $eligibilitiesPath -Encoding UTF8
            Clear-Content $eligibilitiesPath
            $roleEligibilities = @()
        }
        else {
            throw
        }
    }
}

# --- Summary ------------------------------------------------------------------
Write-Log '=== 04_ExportEntraRoles complete ==='
Write-Log "  Role definitions  : $($roleDefinitions.Count)"
Write-Log "  Role assignments  : $($roleAssignments.Count)"
Write-Log "  Role eligibilities: $($roleEligibilities.Count)"
Write-Log "  Output directory  : $RunOutputPath"
