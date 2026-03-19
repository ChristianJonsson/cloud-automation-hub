# Entra Automation

This folder contains Entra-focused automation scripts and supporting modules.

## Script

- `Update-Users-Where-UserType-Missing.ps1`

## What This Script Does

`Update-Users-Where-UserType-Missing.ps1` finds users with a null `userType`, classifies them with high confidence as `Member` or `Guest`, exports audit/review CSVs, and updates `userType` based on selected target mode.

The script supports preview execution (`-DryRun` and `-WhatIf`), strictness-based preflight policy checks, and can reuse cached Graph query results from the current PowerShell session.

## Requirements

1. PowerShell session with access to the repository.
2. Microsoft Graph PowerShell connectivity.
3. Operator permissions in your tenant for user read/update and policy-impact review.

### Microsoft Graph Delegated Scopes

The script currently uses these delegated scopes:

Core scopes (required for script operation)

- `User.Read.All`
- `User.ReadWrite.All`
- `Organization.Read.All`

Policy-impact preflight scopes (required for full policy coverage)

- `Policy.Read.All`
- `Directory.Read.All`
- `EntitlementManagement.Read.All`
- `RoleManagement.Read.Directory`

Advisory policy-impact scopes (optional in v1; used for expanded heuristic visibility)

- `Team.ReadBasic.All`
- `Mail.ReadBasic.All`

Scope behavior notes:

- Preview mode can continue with partial policy coverage when some policy scopes are unavailable.
- Write mode enforcement depends on `-StrictnessMode`.
- `Permissive` allows write mode when only entitlement preflight visibility is unavailable; coverage is marked as partial in outputs.

The script ensures Graph prerequisites using module logic in:

- `Modules/Shared/GraphConnection.psm1`

The script is orchestrated from the main `.ps1` file and uses helper modules for focused responsibilities:

- `Modules/Shared/GraphData.psm1`
- `Modules/UserTypeNullRemediation/Classification.psm1`
- `Modules/UserTypeNullRemediation/PolicyImpactValidation.psm1`
- `../Common/Modules/Shared/Logging.psm1`

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

- `-StrictnessMode Strict|Balanced|Permissive`
  - Controls how policy preflight findings are enforced in write mode.
  - `Strict`: critical and advisory unavailable findings can block writes.
  - `Balanced` (default): only critical failures block writes.
  - `Permissive`: allows write mode to continue when only EntitlementManagement checks are unavailable.
  - `Permissive` still records partial policy coverage in log/CSV outputs and blocks on other critical failures.

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
  - `Reports/UserTypeNullRemediation/Reports_Skipped_Users/SkippedUsers-<timestamp>.csv`

- Preview candidate CSVs (only in `-DryRun` or `-WhatIf`, and only when that candidate set is non-empty):
  - `Reports/UserTypeNullRemediation/Reports_Would_Update_Members/WouldUpdateMembers-<timestamp>.csv`
  - `Reports/UserTypeNullRemediation/Reports_Would_Update_Guests/WouldUpdateGuests-<timestamp>.csv`

- Preflight artifact:
  - `Reports/UserTypeNullRemediation/Preflight-<timestamp>.json`
  - Includes compact summary plus per-area policy prerequisite results for audit sign-off.

- Log file:
  - `Logs/UserUpdate.log`
  - Written for both preview (`-DryRun` / `-WhatIf`) and non-preview runs.

- Terminal progress logging during updates:
  - To keep `Write-Progress` readable, progress checkpoint messages are shown only at:
    - first user
    - every 50 users
    - last user

- Exported CSV impact metadata:
  - `PreflightRunId`, `PreflightSummary`, `PolicyCoverageLevel`, `PolicyRiskLevel`
  - Impact counters for Conditional Access, dynamic groups, memberships, app roles, directory roles, and entitlement assignments
  - `BlockingFlags` and computed `PolicyImpactNotes`

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
4. In non-preview mode, write behavior is controlled by `-StrictnessMode` and preflight outcomes.
5. If entitlement preflight checks are unavailable due to missing authorization, preview still works, but write behavior depends on strictness and criticality.

## Related Layout Documentation

For overall Microsoft module layout conventions, see:

- `../README.md`
