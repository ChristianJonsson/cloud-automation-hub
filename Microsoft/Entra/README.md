# Entra Automation

This folder contains Entra-focused automation scripts and supporting modules.

## Script

- `UserTypeNullRemediation.ps1`

## What This Script Does

`UserTypeNullRemediation.ps1` finds users with a null `userType`, classifies them with high confidence as `Member` or `Guest`, exports audit/review CSVs, and updates `userType` based on selected target mode.

The script supports preview execution (`-WhatIf`), strictness-based preflight policy checks, and can reuse cached Graph query results from the current PowerShell session.

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


## Policy Impact Evaluation Areas

The script evaluates these policy-impact areas when building preflight and per-user impact results.

Critical areas (write mode can block when unavailable, depending on `-StrictnessMode`)

- **ConditionalAccess** — fetches all CA policies via `Get-MgIdentityConditionalAccessPolicy -All` (requires `Policy.Read.All`). For each user, evaluates `Conditions.Users`: included when `IncludeUsers` contains `All` or the user's ID, or when any `IncludeGroups` entry matches a group the user belongs to; excluded when `ExcludeUsers` or `ExcludeGroups` matches. A policy is a match when included and not excluded. Matching policy count is recorded as `ConditionalAccessCount` and elevates `PolicyRiskLevel` to `High`. **Not evaluated:** whether the policy is enabled or disabled (disabled policies still count as matches), `GuestsOrExternalUsers` conditions, named locations, device compliance, sign-in risk, and application-scoped conditions.

- **DynamicGroups** — fetches all dynamic-membership groups via `Get-MgGroup -Filter "groupTypes/any(c:c eq 'DynamicMembership')"` (requires `Directory.Read.All`), retrieving `Id`, `DisplayName`, and `MembershipRule`. For each user, filters groups whose `MembershipRule` references `user.userType` or `userType` (case-insensitive), or contains the proposed UserType value as a literal string. For each matched group, calls `POST /groups/{id}/evaluateDynamicMembership` with the user's ID to determine current membership status, then applies simple pattern extraction (`-eq`/`-ne` comparisons on `user.userType`) to estimate post-change membership. Reports `ImpactDirection` per group: `WouldJoin`, `WouldLeave`, `RequiresManualReview`, or `NoChange` (excluded from count). Count of impacted groups is recorded as `DynamicGroupRuleCount` and contributes to `PolicyRiskLevel` `Low`. Evaluation failures are written to the log as warnings. **Not evaluated:** complex rule expressions beyond simple `-eq`/`-ne` comparisons on `user.userType`; groups where the evaluate API call fails are reported as `RequiresManualReview`.

- **GroupAndAppAssignments** — per-user: calls `Get-MgUserMemberOf -All` to retrieve all group memberships, and `Get-MgUserAppRoleAssignment -All` to retrieve app role assignments (both require `Directory.Read.All`). Counts are recorded as `GroupMembershipCount` and `AppRoleAssignmentCount`. App role assignments elevate `PolicyRiskLevel` to `Medium`; group memberships elevate to `Low`. Group memberships are also used as input for the ConditionalAccess and DynamicGroups per-user checks. **Not evaluated:** transitive group-of-group nesting beyond what `Get-MgUserMemberOf` returns directly.

- **EntitlementManagement** — per-user: calls `Get-MgEntitlementManagementAssignment -Filter "targetId eq '<userId>'" -All` (requires `EntitlementManagement.Read.All`). Count is recorded as `EntitlementAssignmentCount`, elevates `PolicyRiskLevel` to `Medium`, and adds `EntitlementAssignment` to `BlockingFlags`. In `Permissive` mode, an unavailable entitlement scope does not block writes but is recorded as partial coverage. **Not evaluated:** individual access package policies and their userType eligibility rules.

- **DirectoryRoleAssignments** — fetches all directory role assignments once via `Get-MgRoleManagementDirectoryRoleAssignment -All` (requires `RoleManagement.Read.Directory`). Per-user: filters assignments where `PrincipalId` matches the user's ID. Count is recorded as `DirectoryRoleAssignmentCount`, elevates `PolicyRiskLevel` to `High`, and adds `DirectoryRoleAssignment` to `BlockingFlags`. **Not evaluated:** PIM eligible assignments or group-based role assignments (only directly assigned roles are matched).

Advisory areas

- **LicensingHeuristics** — probe only: verifies `Get-MgSubscribedSku` is callable via `Organization.Read.All` and that `Microsoft.Graph.Identity.DirectoryManagement` is imported. No per-user licensing impact is computed in the current implementation; the probe only validates scope availability. Does not affect `PolicyRiskLevel` or any per-user counter.

- **TeamsExchangeHeuristics** — **disabled.** The scope matrix entry and prerequisite probe are commented out. Per-user Teams and mailbox probes are not executed; `TeamsCount` and `HasMailbox` are not populated in policy impact output. `Team.ReadBasic.All` and `Mail.ReadBasic.All` are not requested.

Scope behavior notes:

- Preview mode can continue with partial policy coverage when some policy scopes are unavailable.
- Write mode enforcement depends on `-StrictnessMode`.
- `Permissive` allows write mode when only entitlement preflight visibility is unavailable; coverage is marked as partial in outputs.

The script ensures Graph prerequisites using module logic in:

- `Modules/Shared/GraphConnection.psm1`

The script is orchestrated from the main `.ps1` file and uses helper modules for focused responsibilities:

- `Modules/Shared/GraphData.psm1`
- `Modules/UserTypeNullRemediation/Classification.psm1`
- `Modules/UserTypeNullRemediation/PolicyImpactExport.psm1`
- `Modules/UserTypeNullRemediation/PolicyImpactValidation.psm1`
- `../Common/Modules/Shared/Logging.psm1`

`PolicyImpactExport.psm1` owns the policy-impact CSV contract for this workflow: row shaping, export directory preparation, and CSV writing. It remains feature-specific by design because the exported schema includes remediation-specific preflight metadata, classification output, and policy-impact counters.

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
  - `Strict`: critical failures block writes, and advisory findings with `Unavailable` status also block writes.
  - `Balanced` (default): only critical failures block writes.
  - `Permissive`: allows write mode to continue when only EntitlementManagement checks are unavailable.
  - `Permissive` still records partial policy coverage in log/CSV outputs and blocks on other critical failures.

- `-TopUsers <count>`
  - Limits classification, policy evaluation, and update/preview processing to the first `N` users from the set where `userType` is null.
  - Default: `0` (process all matching users).

- `-WhatIf`
  - Preview mode. No update writes are attempted.
  - Writes preview CSV exports and preflight artifacts for review.
  - Suppresses per-item `ShouldProcess` WhatIf console output for large runs; use preview CSVs for detailed review.

- `-Confirm`
  - Prompts before each update operation.

- `-Help` or `-h`
  - Displays script usage help.

## Outputs

- Skipped users CSV (created only when there are skipped candidates):
  - `Reports/UserTypeNullRemediation/Reports_Skipped_Users/SkippedUsers-<timestamp>.csv`

- Preview candidate CSVs (only in `-WhatIf`, and only when that candidate set is non-empty):
  - `Reports/UserTypeNullRemediation/Reports_Would_Update_Members/WouldUpdateMembers-<timestamp>.csv`
  - `Reports/UserTypeNullRemediation/Reports_Would_Update_Guests/WouldUpdateGuests-<timestamp>.csv`

- Non-preview update outcome CSVs (only when that result set is non-empty):
  - `Reports/UserTypeNullRemediation/Reports_Updated_Users/UpdatedUsers-<timestamp>.csv`
  - `Reports/UserTypeNullRemediation/Reports_Failed_Updates/FailedUpdates-<timestamp>.csv`

- Preflight artifact:
  - Preview runs (`-WhatIf`): `Reports/UserTypeNullRemediation/Preflight.preview-<timestamp>.json`
  - Non-preview runs: `Reports/UserTypeNullRemediation/Preflight-<timestamp>.json`
  - Includes compact summary plus per-area policy prerequisite results for audit sign-off.

- Log file:
  - Preview runs (`-WhatIf`): `Logs/UserUpdate.preview.log`
  - Non-preview runs: `Logs/UserUpdate.log`
  - Records every user classification result, every update or preview action, and policy-evaluation warnings/errors.

- Terminal progress logging during updates:
  - The console keeps `Write-Progress` output readable by avoiding per-user console spam.
  - Detailed per-user activity is written to the log file instead.

- Exported CSV impact metadata:
  - `PreflightRunId`, `PreflightSummary`, `PolicyCoverageLevel`, `PolicyRiskLevel`
  - Impact counters for Conditional Access, dynamic groups, memberships, app roles, directory roles, entitlement assignments, Teams, and mailbox presence
  - `BlockingFlags` and computed `PolicyImpactNotes`

- Exported CSV column groups:
  - Run metadata: `TimestampUtc`, `PreflightRunId`, `PreflightSummary`
  - User identity: `UserPrincipalName`, `DisplayName`, `Id`, `JobTitle`, `CompanyName`, `Department`, `OfficeLocation`
  - Account state: `AccountEnabled`, `CreatedDateTime`, `CreationType`, `ExternalUserState`
  - Sync and identity signals: `OnPremisesSyncEnabled`, `OnPremisesImmutableId`, `OnPremisesSecurityIdentifier`, `AssignedLicensesCount`, `IdentitiesSummary`
  - Classification: `CurrentUserType`, `ProposedUserType`, `Reason`
  - Policy impact: `PolicyCoverageLevel`, `PolicyRiskLevel`, `ConditionalAccessCount`, `DynamicGroupRuleCount`, `GroupMembershipCount`, `AppRoleAssignmentCount`, `DirectoryRoleAssignmentCount`, `EntitlementAssignmentCount`, `TeamsCount`, `HasMailbox`, `BlockingFlags`, `PolicyImpactNotes`
  - Diagnostic extension attributes: `ExtensionAttribute1` through `ExtensionAttribute15`

## Usage Examples

### 1) Default preview (member target)

```powershell
.\UserTypeNullRemediation.ps1 -WhatIf
```

### 2) Preview both member and guest candidates

```powershell
.\UserTypeNullRemediation.ps1 -TargetType Both -WhatIf
```

### 3) Real member updates

```powershell
.\UserTypeNullRemediation.ps1 -TargetType Member
```

### 4) Real guest updates (explicit safety gate)

```powershell
.\UserTypeNullRemediation.ps1 -TargetType Guest -EnableGuestUpdates
```

### 5) Reuse cached Graph results in the same session

```powershell
# First run builds in-session variables via live Graph queries
. .\UserTypeNullRemediation.ps1 -WhatIf

# Second run reuses cached $users and $verifiedDomains when valid
. .\UserTypeNullRemediation.ps1 -UseCachedGraphResults -WhatIf
```

### 6) Evaluate only the first 25 matching users

```powershell
.\UserTypeNullRemediation.ps1 -TopUsers 25 -WhatIf
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

1. Use `-WhatIf` before write operations.
2. Guest writes can affect Conditional Access, dynamic group rules, app/group assignments, and entitlement behavior.
3. `-EnableGuestUpdates` is intentionally required for non-preview guest writes.
4. In non-preview mode, write behavior is controlled by `-StrictnessMode` and preflight outcomes.
5. Report/export/preflight paths are validated early; invalid path values fail fast before Graph processing.
5. If entitlement preflight checks are unavailable due to missing authorization, preview still works, but write behavior depends on strictness and criticality.

## Related Layout Documentation

For overall Microsoft module layout conventions, see:

- `../README.md`
