# ==============================================================================
# 05_ExportEntraGroups.ps1
# Purpose : Export all Entra groups, their direct members, and their owners.
#           Direct (non-transitive) membership only — step 08 handles nested
#           expansion when resolving effective admins.
# Run on  : Any machine with Microsoft.Graph.Groups available
# Output  : <RunOutputPath>\Entra_Groups.ndjson
#           <RunOutputPath>\Entra_GroupMembers.ndjson
#           <RunOutputPath>\Entra_GroupOwners.ndjson
# Requires: 00_Config.ps1 (shared configuration)
#
# Throttling note:
#   Group enumeration is the heaviest pipeline step. Initial $expand=members,
#   owners returns up to 20 entries per relationship in the bulk Get-MgGroup
#   call; groups whose expanded collection looks paginated (20+ entries) fall
#   back to a dedicated per-group call. Role-assignable groups (PAGs) are
#   processed first so that if the run dies mid-way the most security-relevant
#   data is already on disk.
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
if (-not (Get-Variable -Name RunOutputPath -ErrorAction SilentlyContinue)) {
    $RunOutputPath = Join-Path $OutputPath (Get-Date -Format 'yyyy-MM-dd_HHmmss')
    New-Item -ItemType Directory -Path $RunOutputPath -Force | Out-Null
}
Set-LogFilePath -Path (Join-Path $RunOutputPath 'AccountGovernance.log')
Write-Log '=== 05_ExportEntraGroups started ==='

# --- Connect to Microsoft Graph -----------------------------------------------
Connect-MgGraphWithRequirements `
    -GraphModuleNames @('Microsoft.Graph.Groups') `
    -RequiredScopes @('Group.Read.All', 'GroupMember.Read.All', 'Directory.Read.All')

# --- Property list ------------------------------------------------------------
$groupProperties = @(
    'Id', 'DisplayName', 'Description',
    'MailEnabled', 'SecurityEnabled', 'MailNickname', 'Mail',
    'GroupTypes', 'IsAssignableToRole',
    'Visibility', 'MembershipRule', 'MembershipRuleProcessingState',
    'OnPremisesSyncEnabled', 'OnPremisesDomainName', 'OnPremisesSecurityIdentifier',
    'CreatedDateTime', 'RenewedDateTime', 'ExpirationDateTime',
    'ResourceProvisioningOptions'
)

# --- Helpers ------------------------------------------------------------------
# Page-size threshold for the bulk $expand=members,owners. If a group's expanded
# collection returns this many entries, paginate via a dedicated per-group call
# to be sure no entries are missed. Graph's default page size for this expand
# is 20.
$ExpandPageSizeThreshold = 20

function Resolve-MemberType {
    param($Member)

    if ($null -eq $Member) { return $null }

    $odataType = $null
    if ($null -ne $Member.AdditionalProperties) {
        $odataType = $Member.AdditionalProperties['@odata.type']
    }

    switch ($odataType) {
        '#microsoft.graph.user'             { return 'User' }
        '#microsoft.graph.group'            { return 'Group' }
        '#microsoft.graph.servicePrincipal' { return 'ServicePrincipal' }
        '#microsoft.graph.device'           { return 'Device' }
        $null                               { return $null }
        default                             { return ($odataType -replace '^#microsoft\.graph\.', '') }
    }
}

function Get-DirectoryObjectField {
    param($Object, [string]$Field)

    if ($null -eq $Object -or $null -eq $Object.AdditionalProperties) { return $null }
    return $Object.AdditionalProperties[$Field]
}

function Flatten-Group ($group) {
    [PSCustomObject]@{
        Id                              = $group.Id
        DisplayName                     = $group.DisplayName
        Description                     = $group.Description
        MailEnabled                     = $group.MailEnabled
        SecurityEnabled                 = $group.SecurityEnabled
        MailNickname                    = $group.MailNickname
        Mail                            = $group.Mail
        GroupTypes                      = @($group.GroupTypes)
        IsAssignableToRole              = $group.IsAssignableToRole
        Visibility                      = $group.Visibility
        MembershipRule                  = $group.MembershipRule
        MembershipRuleProcessingState   = $group.MembershipRuleProcessingState
        OnPremisesSyncEnabled           = $group.OnPremisesSyncEnabled
        OnPremisesDomainName            = $group.OnPremisesDomainName
        OnPremisesSecurityIdentifier    = $group.OnPremisesSecurityIdentifier
        CreatedDateTime                 = $group.CreatedDateTime
        RenewedDateTime                 = $group.RenewedDateTime
        ExpirationDateTime              = $group.ExpirationDateTime
        ResourceProvisioningOptions     = @($group.ResourceProvisioningOptions)
    }
}

function Flatten-GroupRelationship {
    param($Group, $Object)

    [PSCustomObject]@{
        GroupId                    = $Group.Id
        GroupDisplayName           = $Group.DisplayName
        GroupIsAssignableToRole    = $Group.IsAssignableToRole
        MemberId                   = $Object.Id
        MemberType                 = Resolve-MemberType $Object
        MemberDisplayName          = Get-DirectoryObjectField $Object 'displayName'
        MemberUserPrincipalName    = Get-DirectoryObjectField $Object 'userPrincipalName'
    }
}

# --- 1. Bulk group fetch (with expand) ----------------------------------------
Write-Log 'Fetching all groups (with $expand=members,owners)...'
$startTime = Get-Date

$allGroups = Invoke-GraphOperationWithRetry -OperationName 'Get-MgGroup full tenant listing' -Operation {
    Get-MgGroup -All -Property $groupProperties -ExpandProperty 'Members,Owners' -ErrorAction Stop
}

$elapsed = (Get-Date) - $startTime
Write-Log "  Fetched $($allGroups.Count) groups in $([int]$elapsed.TotalSeconds) seconds"

# Order PAGs first so the most security-relevant data is written even if the
# membership pass is interrupted.
$allGroups = $allGroups | Sort-Object @{Expression = { [bool]$_.IsAssignableToRole }; Descending = $true}, DisplayName

# --- 2. Write group inventory -------------------------------------------------
Write-Log 'Writing group inventory...'
$allGroups | ForEach-Object { Flatten-Group $_ | ConvertTo-Json -Compress -Depth 5 } |
    Out-File (Join-Path $RunOutputPath 'Entra_Groups.ndjson') -Encoding UTF8
Write-Log '  Written -> Entra_Groups.ndjson'

# --- 3. Members and owners ----------------------------------------------------
$membersPath = Join-Path $RunOutputPath 'Entra_GroupMembers.ndjson'
$ownersPath  = Join-Path $RunOutputPath 'Entra_GroupOwners.ndjson'

if (Test-Path $membersPath) { Remove-Item $membersPath -Force }
if (Test-Path $ownersPath)  { Remove-Item $ownersPath  -Force }

$totalGroups   = $allGroups.Count
$processed     = 0
$memberCount   = 0
$ownerCount    = 0
$paginatedMembers = 0
$paginatedOwners  = 0
$relStart      = Get-Date

foreach ($group in $allGroups) {
    $processed++

    # --- Members --------------------------------------------------------------
    $expandedMembers = @($group.Members)
    if ($expandedMembers.Count -ge $ExpandPageSizeThreshold) {
        $members = Invoke-GraphOperationWithRetry -OperationName "Get-MgGroupMember for $($group.Id)" -Operation {
            Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop
        }
        $paginatedMembers++
    } else {
        $members = $expandedMembers
    }

    if ($members.Count -gt 0) {
        $members |
            ForEach-Object { Flatten-GroupRelationship -Group $group -Object $_ | ConvertTo-Json -Compress -Depth 5 } |
            Out-File $membersPath -Encoding UTF8 -Append
        $memberCount += $members.Count
    }

    # --- Owners ---------------------------------------------------------------
    $expandedOwners = @($group.Owners)
    if ($expandedOwners.Count -ge $ExpandPageSizeThreshold) {
        $owners = Invoke-GraphOperationWithRetry -OperationName "Get-MgGroupOwner for $($group.Id)" -Operation {
            Get-MgGroupOwner -GroupId $group.Id -All -ErrorAction Stop
        }
        $paginatedOwners++
    } else {
        $owners = $expandedOwners
    }

    if ($owners.Count -gt 0) {
        $owners |
            ForEach-Object { Flatten-GroupRelationship -Group $group -Object $_ | ConvertTo-Json -Compress -Depth 5 } |
            Out-File $ownersPath -Encoding UTF8 -Append
        $ownerCount += $owners.Count
    }

    if ($processed % 250 -eq 0 -or $processed -eq $totalGroups) {
        $relElapsed = (Get-Date) - $relStart
        $rate = if ($relElapsed.TotalSeconds -gt 0) { $processed / $relElapsed.TotalSeconds } else { 0 }
        $remaining = $totalGroups - $processed
        $etaSeconds = if ($rate -gt 0) { [int]($remaining / $rate) } else { 0 }
        Write-Log ("  Progress: {0}/{1} groups ({2:N0} members, {3:N0} owners; paginated members: {4}, owners: {5}); elapsed {6:N0}s, ETA {7:N0}s" -f `
                    $processed, $totalGroups, $memberCount, $ownerCount, $paginatedMembers, $paginatedOwners, [int]$relElapsed.TotalSeconds, $etaSeconds)
    }
}

# Ensure files exist even when there were no rows to write (downstream loaders
# expect them).
if (-not (Test-Path $membersPath)) { '' | Out-File $membersPath -Encoding UTF8; Clear-Content $membersPath }
if (-not (Test-Path $ownersPath))  { '' | Out-File $ownersPath  -Encoding UTF8; Clear-Content $ownersPath }

Write-Log '  Written -> Entra_GroupMembers.ndjson'
Write-Log '  Written -> Entra_GroupOwners.ndjson'

# --- Summary ------------------------------------------------------------------
$totalElapsed = (Get-Date) - $startTime
Write-Log '=== 05_ExportEntraGroups complete ==='
Write-Log "  Groups            : $totalGroups"
Write-Log "  Member rows       : $memberCount"
Write-Log "  Owner rows        : $ownerCount"
Write-Log "  Paginated (members): $paginatedMembers groups"
Write-Log "  Paginated (owners) : $paginatedOwners groups"
Write-Log "  Total elapsed     : $([int]$totalElapsed.TotalMinutes) minutes"
Write-Log "  Output directory  : $RunOutputPath"
