# Entra / AD Sync Status Audit

## Overview

This folder contains scripts and documentation for auditing Active Directory and Entra ID (formerly Azure AD) user account sync status. The goal is to categorise all user accounts into three buckets:

| Bucket | Description |
|--------|-------------|
| **Actively synced** | AD accounts currently syncing to Entra via Entra Connect |
| **Previously synced** | Accounts that were synced but no longer are (orphaned cloud objects) |
| **Cloud-only** | Entra accounts with no on-premises presence whatsoever |

A fourth bucket — **AD-only** — is identified from the AD side and cross-referenced against the above.

---

## Audit Goals

- [ ] Identify stale/inactive accounts across all buckets
- [ ] Review access rights and licensing hygiene
- [ ] Surface orphaned accounts (previously synced, no longer active in either directory)
- [ ] Cross-reference AD accounts not appearing in any Entra bucket (AD-only)
- [ ] Review accounts with provisioning errors
- [ ] Complete governance check on all user properties

---

## Prerequisites

- Access to the **Entra Connect server** (for sync configuration queries — scripts 01 and 02)
- **Active Directory Users and Computers** or PowerShell with RSAT AD module
- **Microsoft Graph PowerShell module** — installed automatically by the scripts if missing
- Output directory defaults to an `Output\` folder next to the scripts (configurable in `00_Config.ps1`)

---

## Quick Start — Orchestrated Run

The recommended way to run a complete audit:

```powershell
# Single-forest environments
.\Run-AccountGovernanceAudit.ps1

# Multi-forest — export a specific forest only
.\Run-AccountGovernanceAudit.ps1 -Forest "corp.local"

# Skip Entra export (reuse prior run's Entra NDJSON files)
.\Run-AccountGovernanceAudit.ps1 -SkipEntraExport

# NDJSON only — skip the Excel JSON conversion step
.\Run-AccountGovernanceAudit.ps1 -SkipConvertToJson
```

Each run creates a timestamped subdirectory under `Output\` (e.g. `Output\2026-04-20_143052\`) so previous runs are never overwritten. A `RunManifest.json` and `AccountGovernance.log` are written there on completion.

Scripts 03–06 can also be run individually — see the step-by-step sections below.

---

## Configuration

Before running any scripts, edit **`00_Config.ps1`** to match your environment:

```powershell
$ImmutableIdMethod = "ObjectGUID"   # See "Common AD-Entra Setups" below
$Forests           = @("default")   # Multi-forest: @("corp.local", "subsidiary.com")
$KeySyncRuleNames  = @(...)         # Sync rules to inspect in detail
```

`$OutputPath` is resolved automatically relative to the scripts folder — no manual path configuration needed unless you want to write output elsewhere.

See `ENVIRONMENT.md` for a per-setting reference table and a worked example.

---

## Breaking Change — Multi-value fields are now JSON arrays

Multi-value fields (`OtherMails`, `ProxyAddresses`, `Identities`, `AssignedLicenses`, `AssignedPlans`, `OnPremisesProvisioningErrors`, `ServicePrincipalNames`) were previously exported as semicolon-delimited strings. They are now proper JSON arrays.

**Impact:** Any existing Excel Power Query formulas that split on `";"` will need to be updated to use the JSON array expansion instead (`List.Transform`, `Table.ExpandListColumn`).

---

## Understanding Your AD-Entra Setup

Before running the scripts, identify which setup applies to your environment. The key question is: **what attribute is used as the source anchor (ImmutableID)?**

### Quick diagnostic — PowerShell

Run on the Entra Connect server:

```powershell
Get-ADSyncGlobalSettings | Select-Object -Property *Anchor*
```

Or inspect the connector directly:

```powershell
$connector = Get-ADSyncConnector | Where-Object { $_.ConnectorTypeName -eq "AD" }
$connector | Select-Object Name, AnchorConstructionSettings | Format-List
```

### Quick diagnostic — ADUC (Attribute Editor)

1. Open **Active Directory Users and Computers**
2. Enable **View → Advanced Features**
3. Open any synced user's **Properties → Attribute Editor** tab
4. Check whether `mS-DS-ConsistencyGuid` is populated:
   - **Not set** → your environment uses ObjectGUID as source anchor (Setup 1)
   - **Set to a GUID value** → your environment uses mS-DS-ConsistencyGuid (Setup 2)
5. If neither applies, check with your directory team for a custom attribute (Setup 3 variant)

---

## Common AD-Entra Setups

### Setup 1 — Single-forest, ObjectGUID source anchor *(Default)*

**When this applies:** Most standard single-forest Entra Connect deployments. ObjectGUID is the default source anchor for environments where `mS-DS-ConsistencyGuid` has not been explicitly configured.

**How to detect:**
- PowerShell: `Get-ADUser -Identity <samaccountname> -Properties mS-DS-ConsistencyGuid` returns `$null` or no value
- ADUC Attribute Editor: `mS-DS-ConsistencyGuid` shows as `<not set>`
- Entra: `OnPremisesImmutableId` values are 24-character Base64 strings ending in `==`

**Viewing complete AD user properties:**

*PowerShell:*
```powershell
Get-ADUser -Identity <samaccountname> -Properties *
```
By default `Get-ADUser` returns only a base set of attributes. The `-Properties *` flag returns everything, including extension attributes, `msDS-*` attributes, and any custom schema extensions.

*ADUC (GUI):*
1. Enable **View → Advanced Features** in ADUC
2. Open a user's **Properties → Attribute Editor** tab
3. All attributes — including those hidden in standard tabs — are listed here with their current values

> The Attribute Editor is the fastest way to verify which source anchor method is in use and whether `msDS-*` attributes are populated on synced users.

**Script configuration (`00_Config.ps1`):**
```powershell
$ImmutableIdMethod = "ObjectGUID"
```

**ImmutableId calculation (`06_ExportADUsers.ps1`):**
```powershell
[System.Convert]::ToBase64String($user.ObjectGUID.ToByteArray())
```

**This is the default assumption for all scripts in this folder.**

---

### Setup 2 — Single-forest, mS-DS-ConsistencyGuid source anchor

**When this applies:** Environments where Microsoft's guidance for explicit source anchor control has been followed. Recommended for large organisations, environments planning forest merges, or where users may be migrated between domains. The `mS-DS-ConsistencyGuid` attribute is explicitly populated by Entra Connect and used as the source anchor instead of ObjectGUID.

**How to detect:**
- PowerShell: `Get-ADUser -Identity <samaccountname> -Properties mS-DS-ConsistencyGuid` returns a byte array
- ADUC Attribute Editor: `mS-DS-ConsistencyGuid` is populated with a GUID
- Entra Connect: `Get-ADSyncGlobalSettings` shows `mS-DS-ConsistencyGuid` as the source anchor

**Viewing complete AD user properties:** Same as Setup 1 — use `Get-ADUser -Properties *` or ADUC Attribute Editor.

**Script configuration (`00_Config.ps1`):**
```powershell
$ImmutableIdMethod = "mS-DS-ConsistencyGuid"
```

**Key difference for scripts 06 and 07:** `06_ExportADUsers.ps1` reads `mS-DS-ConsistencyGuid` instead of `ObjectGUID` and Base64-encodes it. Users where this attribute is `$null` will have a `$null` ImmutableId — flag these as potential sync mismatches worth investigating.

---

### Setup 3 — Multi-forest

**When this applies:** Enterprise environments with multiple AD forests syncing to a single Entra tenant. Each forest has its own AD connector in Entra Connect.

**How to detect:**
```powershell
Get-ADSyncConnector | Where-Object { $_.ConnectorTypeName -eq "AD" } | Select-Object Name
```
More than one result indicates a multi-forest configuration.

**Key differences:**
- Each forest may use a different source anchor method — confirm per-forest before running
- ImmutableID collisions are possible if ObjectGUID is used across forests — this is the primary reason Microsoft recommends `mS-DS-ConsistencyGuid` for multi-forest environments

**Script configuration (`00_Config.ps1`):**
```powershell
$Forests = @("corp.local", "subsidiary.com")
$ImmutableIdMethod = "mS-DS-ConsistencyGuid"  # Recommended for multi-forest
```

The orchestrator (`Run-AccountGovernanceAudit.ps1`) runs `06_ExportADUsers.ps1` once per forest automatically, producing separate output files (`AD_AllUsers_corp.local.ndjson`, `AD_AllUsers_subsidiary.com.ndjson`). Script 07 unions them before cross-referencing.

To export a specific forest manually:
```powershell
.\06_ExportADUsers.ps1 -ForestName "corp.local" -Server "dc01.corp.local"
```

---

## Step 1 — Identify Entra Connect Configuration

Run **`01_EntraConnect_Config.ps1`** on the Entra Connect server.

Key things to establish:
- Sync method (PHS / PTA / Federation)
- Sync scope (which OUs are included)
- Scheduler status (is sync healthy or broken?)

### Useful commands

```powershell
Get-ADSyncGlobalSettings
Get-ADSyncAADCompanyFeature
Get-ADSyncScheduler
Get-ADSyncConnector | Select-Object Name, Type, ConnectorTypeName
```

---

## Step 2 — Identify Sync Scope and Rules

Run **`02_SyncRules.ps1`** on the Entra Connect server.

### Check OU filtering

```powershell
$connector = Get-ADSyncConnector | Where-Object { $_.ConnectorTypeName -eq "AD" }
$connector.Partitions
```

### Export all inbound sync rules

```powershell
Get-ADSyncRule | Where-Object { $_.Direction -eq "Inbound" } |
    Select-Object Name, ConnectorName, ScopeFilterGroups |
    Format-List | Out-File "C:\tmp\SyncRules_Inbound.txt"
```

### Inspect specific rules

The rules listed in `$KeySyncRuleNames` (`00_Config.ps1`) are exported in detail. Add any org-specific custom rules to that list before running.

### Disconnector scope condition (drill into nested object)

```powershell
$rule = Get-ADSyncRule | Where-Object { $_.Name -eq "In from AD - User Dirsync Disconnector" }
$rule.ScopeFilter | ForEach-Object {
    $_.ScopeConditionGroups | ForEach-Object {
        $_.ScopeConditions | Format-List *
    }
}
```

> **Note:** In some environments this rule has an empty ScopeFilter and sets `cloudFiltered = True` as a constant with no attribute-based expression. If the scope output is empty, the rule fires purely on precedence — this is expected behaviour, not an error. See `ENVIRONMENT.md` for a reference example.

---

## Step 3 — Export Entra User Buckets

Run **`03_ExportEntraUsers.ps1`** from any machine with the Microsoft.Graph module.

This script performs a **single Graph API fetch** of all users, then filters in memory into three buckets. This avoids running multiple full-tenant queries.

### Output files

| File | Contents |
|------|---------|
| `Entra_SyncedUsers.ndjson` | Bucket 1 — actively synced users |
| `Entra_PreviouslySynced.ndjson` | Bucket 2 — previously synced (ImmutableId set, sync disabled) |
| `Entra_CloudOnly.ndjson` | Bucket 3 — cloud-only accounts (no on-prem presence) |

### Why NDJSON instead of CSV

User properties can contain newline characters and special characters that corrupt CSV exports. NDJSON (one JSON object per line) handles these safely.

### Filtering logic

| Bucket | Filter |
|--------|--------|
| Actively synced | `OnPremisesSyncEnabled -eq $true` |
| Previously synced | `OnPremisesSyncEnabled -ne $true` AND `OnPremisesImmutableId -ne $null` |
| Cloud-only | `OnPremisesSyncEnabled -ne $true` AND `OnPremisesImmutableId -eq $null` |

### Manager lookup

Each user record carries `ManagerId` and `ManagerDisplayName` by default — the bulk fetch uses `$expand=manager` to attach the manager directoryObject inline, enabling manager-by-admin reporting and attestation flows in step 08. This roughly doubles the response payload from Graph. Set `$IncludeManagerLookup = $false` in `00_Config.ps1` to skip; the two manager fields will emit as `$null` but the schema stays stable.

---

## Step 4 — Export AD Users

Run **`06_ExportADUsers.ps1`** on a domain-joined machine with the RSAT AD module.

This script exports all AD user accounts and calculates each user's ImmutableId using the method configured in `$ImmutableIdMethod` (`00_Config.ps1`). The ImmutableId is used in Step 5 to match AD users against their Entra counterparts.

Output: `AD_AllUsers_<ForestName>.ndjson` (default: `AD_AllUsers_default.ndjson`)

For **multi-forest environments** (Setup 3): use the orchestrator or run manually with `-ForestName` per forest.

---

## Step 5 — Cross-reference and Analysis

Run **`07_CrossReference.ps1`** from any machine with access to the NDJSON output files.

- Cross-reference AD export against Entra buckets by ImmutableId
- Identify AD accounts missing from Entra entirely (Bucket 4: AD-only)
- Flag Entra synced accounts with `OnPremisesProvisioningErrors`
- Output: `AD_OnlyAccounts.ndjson` and `Entra_ProvisioningErrors.ndjson`

---

## Permissions Audit (scripts 04 and 05)

Scripts `04_ExportEntraRoles.ps1` and `05_ExportEntraGroups.ps1` run between the Entra user export and the AD export, capturing **who has privileges in the tenant** so that admin accounts and group memberships can be reported on alongside the sync data.

The orchestrator runs both automatically. Each can be skipped independently with `-SkipRoleExport` / `-SkipGroupExport`.

### Script 04 — Entra role export

Captures directory role definitions and assignments:

| File | Contents |
|------|---------|
| `Entra_RoleDefinitions.ndjson` | All directory role definitions (built-in + custom), including their `RolePermissions` |
| `Entra_RoleAssignments.ndjson` | Active role assignments. Each row carries `PrincipalType` (User / Group / ServicePrincipal), `DirectoryScopeId`, `AppScopeId`, and `AssignmentType = "Active"` |
| `Entra_RoleEligibilities.ndjson` | PIM-eligible role assignments. Same shape as active, plus `StartDateTime`, `EndDateTime`, `MemberType`, and `AssignmentType = "Eligible"`. Empty file on tenants without Entra ID P2 |

**PIM behaviour:** when `$IncludePimEligibilities = $false` in `00_Config.ps1`, the eligibility query is skipped entirely. When `$true` (default), the script catches license/permission errors from the PIM endpoint and writes an empty eligibilities file rather than aborting the run — so a tenant without P2 still completes the pipeline cleanly.

**Required Graph scopes:** `RoleManagement.Read.Directory`, `Directory.Read.All`.

### Script 05 — Entra group export

Captures all groups (security, M365, dynamic, distribution) plus direct membership and ownership:

| File | Contents |
|------|---------|
| `Entra_Groups.ndjson` | All groups with type flags (`SecurityEnabled`, `MailEnabled`, `GroupTypes`, `IsAssignableToRole`), membership rules for dynamic groups, on-prem sync info |
| `Entra_GroupMembers.ndjson` | One row per (group, member). Direct membership only — nested expansion happens in step 08 |
| `Entra_GroupOwners.ndjson` | One row per (group, owner) |

**Throttling:** group enumeration is the heaviest pipeline step. Members and owners are fetched via `$expand=members,owners` on the bulk group query, with a fallback per-group call when the expanded collection looks paginated (≥20 entries — Graph's default page size). Role-assignable groups (PAGs) are processed first so the most security-relevant data is on disk even if a long run is interrupted. Progress is logged every 250 groups with elapsed time and ETA.

**Token refresh:** `Invoke-GraphOperationWithRetry` keeps long runs alive across the default 60-minute Graph access-token TTL using a layered approach:

1. **Proactive** — `GraphConnection.psm1` records the acquisition time of every successful `Connect-MgGraph`. Before each call, the retry wrapper checks the tracked age; once it reaches 50 minutes (configurable via `-ProactiveRefreshThresholdMinutes`) it disconnects and reconnects with the same scopes before invoking the operation. The 10-minute buffer is comfortably below TTL.
2. **Reactive** — if a call still fails with a 401 / auth-expiry error (e.g. token rotated mid-flight, or pre-existing session whose age was not tracked), the wrapper performs a one-shot reconnect and retries.
3. **Genuine-401 escalation** — if an auth-expiry error recurs immediately after a refresh attempt, the wrapper does NOT loop. The error is treated as a genuine 401 (revoked consent, lost permission, broken trust) and rethrown so it surfaces clearly.

**Required Graph scopes:** `Group.Read.All`, `GroupMember.Read.All`, `Directory.Read.All`.

### Script 08 — Admin summary derivation

Joins users × roles × group memberships into the file top management actually wants. Pure transformation — no Graph calls.

| File | Contents |
|------|---------|
| `Entra_EffectiveAdmins.ndjson` | One row per (user, role, assignment-path). A user may appear multiple times when held by Direct *and* via a role-assignable group. Each row carries `UserType`, `OnPremisesSyncEnabled`, `AccountEnabled`, `LastSignInDateTime`, `IsStale`, `Scope`, `AssignmentType` (Active/Eligible). |
| `Entra_NonUserRoleHolders.ndjson` | Service principals and managed identities holding directory roles. Reported separately so the user-facing admin file stays clean. |
| `Entra_AdminSummary.json` | Aggregate counts: total admin rows / unique users, Active vs Eligible, Direct vs ViaGroup, synced vs cloud-only, guest admins, stale admins (using `$StaleAdminThresholdDays`), counts by role name. |

**Effective admins via groups:** when a directory role is assigned to a role-assignable group (a "PAG"), this step walks group nesting transitively to surface the actual users. `AssignmentPath` reads `ViaGroup:<GroupDisplayName>` so the lineage is traceable.

**No Graph scopes needed.** The script consumes the NDJSON files produced by steps 03/04/05.

---

## Testing

The join logic in `08_BuildAdminSummary.ps1` is covered by Pester 5 tests under `Tests\`:

```text
Tests\
    08_BuildAdminSummary.Tests.ps1
    Fixtures\
        Users.ndjson          (5 users: synced/cloud-only/guest mix)
        Roles.ndjson          (Global Admin, User Admin, custom role)
        RoleAssignments.ndjson (direct user, direct group, direct SP)
        RoleEligibilities.ndjson (one PIM-eligible user)
        Groups.ndjson         (one role-assignable group, one nested)
        GroupMembers.ndjson   (nested membership chain)
```

The tests cover Direct vs ViaGroup vs nested-group vs ServicePrincipal, dedup-but-keep-both for users with both paths, PIM eligibility, stale-admin threshold, and empty-input safety.

The script exposes `Build-AdminSummary` as a function and gates its main I/O block behind a global sentinel (`$BuildAdminSummary_TestMode`), so tests dot-source the script without triggering file I/O and call the function directly with fixture arrays.

**Running the tests** (Pester 5+ required):

```powershell
Install-Module Pester -Scope CurrentUser -MinimumVersion 5.0.0
Import-Module Pester
Invoke-Pester .\Microsoft\Entra\AD-Entra_AccountGovernance\Tests\
```

The data-extraction scripts (03/04/05/06) are not unit-tested — they are thin wrappers over Graph and AD calls where mocking the world produces little value compared to a smoke run against a dev tenant.

---

## Troubleshooting

### Get-ADUser returns no msDS-* attributes on synced users

By default `Get-ADUser` returns only a base set of properties. Use `-Properties *` to retrieve all attributes:

```powershell
Get-ADUser -Identity <samaccountname> -Properties *
```

Alternatively, use ADUC with **View → Advanced Features** enabled, then open the **Attribute Editor** tab on the user object.

### Calculating ImmutableId for a specific user

For **ObjectGUID** environments (Setup 1):
```powershell
$user = Get-ADUser -Identity <samaccountname> -Properties ObjectGUID
[System.Convert]::ToBase64String($user.ObjectGUID.ToByteArray())
```

For **mS-DS-ConsistencyGuid** environments (Setup 2):
```powershell
$user = Get-ADUser -Identity <samaccountname> -Properties mS-DS-ConsistencyGuid
[System.Convert]::ToBase64String($user."mS-DS-ConsistencyGuid")
```

### ScopeFilter on Disconnector rule returns empty

In some environments this is expected — the rule fires on precedence only and has no attribute-based scope condition. See `ENVIRONMENT.md` for a reference example of this behaviour.

### Get-ADSyncConnector Partitions — Parameter property not found

The `Parameter` property does not exist on partition objects. Use:

```powershell
$connector = Get-ADSyncConnector | Where-Object { $_.ConnectorTypeName -eq "AD" }
$connector.Partitions
```

Or export the full server configuration:

```powershell
Get-ADSyncServerConfiguration -Path "C:\tmp\SyncConfig"
```

### Checking OU scope visually

Run the Entra Connect wizard and navigate without committing changes:

```
C:\Program Files\Microsoft Azure AD Sync\UIShell\AzureADConnect.exe
```

Navigate to: Customize synchronization options → Filter by OUs

---

## Scheduling

To run the audit on a recurring schedule using Windows Task Scheduler:

```
Program:   powershell.exe
Arguments: -NonInteractive -ExecutionPolicy Bypass -File "C:\Scripts\AD-Entra_AccountGovernance\Run-AccountGovernanceAudit.ps1"
```

**Important:** The Microsoft Graph connection requires either:
- An interactive sign-in session (not suitable for unattended scheduling), **or**
- An app registration with `User.Read.All` **application** permission and a certificate, with `Connect-MgGraph -TenantId ... -ClientId ... -CertificateThumbprint ...` called before the orchestrator runs.

For unattended Graph auth, wrap the orchestrator call in a launcher script that handles the app-based connection first.

---

## Files in This Folder

| File | Purpose |
|------|---------|
| `README.md` | This file |
| `ENVIRONMENT.md` | Environment-specific reference values and configuration template |
| `00_Config.ps1` | Shared configuration — edit before running any scripts |
| `Run-AccountGovernanceAudit.ps1` | **Orchestrator** — runs the numbered scripts in sequence |
| `01_EntraConnect_Config.ps1` | Query Entra Connect server configuration (run on Connect server) |
| `02_SyncRules.ps1` | Export and inspect sync rules (run on Connect server) |
| `03_ExportEntraUsers.ps1` | Fetch all Entra users and split into audit buckets |
| `04_ExportEntraRoles.ps1` | Export directory role definitions, active assignments, and PIM eligibilities |
| `05_ExportEntraGroups.ps1` | Export all groups with direct members and owners |
| `06_ExportADUsers.ps1` | Export all AD users for cross-reference (`-ForestName`, `-Server` params) |
| `07_CrossReference.ps1` | Cross-reference AD and Entra exports |
| `08_BuildAdminSummary.ps1` | Derive effective admins, non-user role holders, and aggregate admin summary |
| `09_ConvertToJson.ps1` | Convert NDJSON files to JSON arrays for Excel/Power Query |
| `Tests\` | Pester 5 tests + fixtures for `08_BuildAdminSummary.ps1` |
