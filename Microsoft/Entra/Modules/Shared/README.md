# Entra Shared Modules

Use this folder for Entra modules reused by multiple Entra scripts.

Current shared Entra modules:

- `GraphConnection.psm1`
	- Ensures required Microsoft Graph modules are installed/imported.
	- Validates/re-establishes Graph context with required scopes.

- `GraphData.psm1`
	- Handles cached Graph data reuse and validation.
	- Retrieves users and verified domains when cache is unavailable or invalid.

## Dependency notes

- `GraphConnection.psm1` imports required Microsoft Graph modules dynamically before validating the active Graph context.
- `GraphConnection.psm1` enforces the effective delegated scope set supplied by the calling script.
- `GraphData.psm1` validates cached `$users` and `$verifiedDomains` data before reuse and falls back to live Graph queries when the cache shape is incomplete.
- Policy-impact evaluation and export remain feature-specific by design, so `Classification.psm1`, `PolicyImpactExport.psm1`, and `PolicyImpactValidation.psm1` stay under `Modules/UserTypeNullRemediation/` rather than moving into shared modules.

Shared modules are intentionally provider-wide helpers. Policy-impact classification,
report shaping/export, preflight enforcement, and per-user impact modeling remain feature-specific and are implemented in:

- `Modules/UserTypeNullRemediation/PolicyImpactValidation.psm1`
- `Modules/UserTypeNullRemediation/PolicyImpactExport.psm1`
- `Modules/UserTypeNullRemediation/Classification.psm1`

Keep feature-specific logic in dedicated folders, for example:

- `Modules/UserTypeNullRemediation/`
