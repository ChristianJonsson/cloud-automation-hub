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
- **Microsoft Graph PowerShell module** installed and connected:
  ```powershell
  Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All"
  ```
- Output directory configured in `00_Config.ps1` (default: `C:\tmp\`)

---

## Configuration

Before running any scripts, edit **`00_Config.ps1`** to match your environment:

```powershell
$OutputPath        = "C:\tmp\"      # Output directory for all exports
$ImmutableIdMethod = "ObjectGUID"   # See "Common AD-Entra Setups" below
$KeySyncRuleNames  = @(...)         # Sync rules to inspect in detail
```

See `ENVIRONMENT.md` for a per-setting reference table and a worked example.

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

**ImmutableId calculation (`04_ExportADUsers.ps1`):**
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

**Key difference for scripts 04 and 05:** `04_ExportADUsers.ps1` reads `mS-DS-ConsistencyGuid` instead of `ObjectGUID` and Base64-encodes it. Users where this attribute is `$null` will have a `$null` ImmutableId — flag these as potential sync mismatches worth investigating.

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
- `04_ExportADUsers.ps1` must be run once per forest domain; rename the output file between runs and combine before running `05_CrossReference.ps1`
- ImmutableID collisions are possible if ObjectGUID is used across forests — this is the primary reason Microsoft recommends `mS-DS-ConsistencyGuid` for multi-forest environments

**Script configuration (`00_Config.ps1`):** Set `$ImmutableIdMethod` to match the source anchor used in the target forest. Run the script suite once per forest, adjusting output file names to avoid overwriting between runs.

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

---

## Step 4 — Export AD Users

> **TODO** — Not yet completed.

Run **`04_ExportADUsers.ps1`** on a domain-joined machine with the RSAT AD module.

This script exports all AD user accounts and calculates each user's ImmutableId using the method configured in `$ImmutableIdMethod` (`00_Config.ps1`). The ImmutableId is used in Step 5 to match AD users against their Entra counterparts.

For **multi-forest environments** (Setup 3): run once per forest domain, rename the output file between runs, and combine before cross-referencing.

---

## Step 5 — Cross-reference and Analysis

> **TODO** — Not yet completed.

Run **`05_CrossReference.ps1`** from any machine with access to the NDJSON output files.

- Cross-reference AD export against Entra buckets
- Identify accounts in sync scope that are missing from Entra (potential sync failures)
- Flag accounts with `OnPremisesProvisioningErrors`
- Review last sign-in / last sync dates for stale account identification
- Licensing review against active/enabled accounts

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

## Files in This Folder

| File | Purpose |
|------|---------|
| `README.md` | This file |
| `ENVIRONMENT.md` | Environment-specific reference values and configuration template |
| `00_Config.ps1` | Shared configuration — edit before running any scripts |
| `01_EntraConnect_Config.ps1` | Query Entra Connect server configuration |
| `02_SyncRules.ps1` | Export and inspect sync rules |
| `03_ExportEntraUsers.ps1` | Fetch all Entra users and split into audit buckets |
| `04_ExportADUsers.ps1` | Export all AD users for cross-reference |
| `05_CrossReference.ps1` | Cross-reference AD and Entra exports |
