# Entra Automation

This folder contains Entra-focused automation scripts and supporting modules.

## Script

- `Update-Users-Where-UserType-Missing.ps1`

## What This Script Does

`Update-Users-Where-UserType-Missing.ps1` finds users with a null `userType`, classifies them with high confidence as `Member` or `Guest`, exports audit/review CSVs, and updates `userType` based on selected target mode.

The script supports preview execution (`-DryRun` and `-WhatIf`) and can reuse cached Graph query results from the current PowerShell session.

## Requirements

1. PowerShell session with access to the repository.
2. Microsoft Graph PowerShell connectivity and scopes required by the script.
3. Permissions to read users and update users in your tenant.

The script ensures Graph prerequisites using module logic in:

- `Modules/UserTypeNullRemediation/GraphConnection.psm1`

The script is orchestrated from the main `.ps1` file and uses helper modules for focused responsibilities:

- `Modules/UserTypeNullRemediation/GraphData.psm1`
- `Modules/UserTypeNullRemediation/Classification.psm1`
- `Modules/UserTypeNullRemediation/Logging.psm1`

## Parameters

- `-TargetType Member|Guest|Both`
  - Selects which inferred user types to process.
  - Default: `Member`.

- `-UseCachedGraphResults`
  - Reuses cached Graph query variables from the current PowerShell session when valid.
  - Cached variables checked:
    - `$users`
    - `$verifiedDomains`
  - If a cached value is missing or invalid, the script logs the reason and falls back to live Graph queries.

- `-EnableGuestUpdates`
  - Safety gate for real guest writes.
  - Required for non-preview `Guest` or `Both` runs.

- `-DryRun`
  - Preview mode. No update writes are attempted.

- `-WhatIf`
  - Standard PowerShell simulation through `ShouldProcess`.

- `-Confirm`
  - Prompts before each update operation.

- `-Help` or `-h`
  - Displays script usage help.

## Outputs

- Skipped users CSV (created only when there are skipped candidates):
  - `Review_Skipped_Users/SkippedUsers-<timestamp>.csv`

- Preview candidate CSVs (only in `-DryRun` or `-WhatIf`, and only when that candidate set is non-empty):
  - `Review_Would_Update_Members/WouldUpdateMembers-<timestamp>.csv`
  - `Review_Would_Update_Guests/WouldUpdateGuests-<timestamp>.csv`

- Log file:
  - `Logs/UserUpdate.log`
  - Written for both preview (`-DryRun` / `-WhatIf`) and non-preview runs.

## Usage Examples

### 1) Default preview (member target)

```powershell
.\Update-Users-Where-UserType-Missing.ps1 -DryRun
```

### 2) Preview both member and guest candidates

```powershell
.\Update-Users-Where-UserType-Missing.ps1 -TargetType Both -WhatIf
```

### 3) Real member updates

```powershell
.\Update-Users-Where-UserType-Missing.ps1 -TargetType Member
```

### 4) Real guest updates (explicit safety gate)

```powershell
.\Update-Users-Where-UserType-Missing.ps1 -TargetType Guest -EnableGuestUpdates
```

### 5) Reuse cached Graph results in the same session

```powershell
# First run builds in-session variables via live Graph queries
. .\Update-Users-Where-UserType-Missing.ps1 -DryRun

# Second run reuses cached $users and $verifiedDomains when valid
. .\Update-Users-Where-UserType-Missing.ps1 -UseCachedGraphResults -DryRun
```

## Cache Reuse Behavior

- Cache reuse is in-memory only and scoped to the current PowerShell session.
- The script stores fetched values in session variables (`$users`, `$verifiedDomains`) so subsequent runs can reuse them.
- The script validates cached values before reuse.
- Validation is performed independently for each cached variable:
  - `$users`
  - `$verifiedDomains`
- If one cache is valid and the other is not, the script mixes behavior safely:
  - Reuse valid cache.
  - Query Graph for invalid/missing cache.

## Safety Notes

1. Use `-DryRun` or `-WhatIf` before write operations.
2. Guest writes can affect Conditional Access, dynamic group rules, app/group assignments, and entitlement behavior.
3. `-EnableGuestUpdates` is intentionally required for non-preview guest writes.

## Related Layout Documentation

For overall Microsoft module layout conventions, see:

- `../README.md`
