# Entra Shared Modules

Use this folder for Entra modules reused by multiple Entra scripts.

Current shared Entra modules:

- `GraphConnection.psm1`
	- Ensures required Microsoft Graph modules are installed/imported.
	- Validates/re-establishes Graph context with required scopes.

- `GraphData.psm1`
	- Handles cached Graph data reuse and validation.
	- Retrieves users and verified domains when cache is unavailable or invalid.

Shared modules are intentionally provider-wide helpers. Policy-impact classification,
preflight enforcement, and per-user impact modeling remain feature-specific and are implemented in:

- `Modules/UserTypeNullRemediation/PolicyImpactValidation.psm1`
- `Modules/UserTypeNullRemediation/Classification.psm1`

Keep feature-specific logic in dedicated folders, for example:

- `Modules/UserTypeNullRemediation/`
