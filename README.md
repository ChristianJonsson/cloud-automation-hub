# cloud-automation-hub
PowerShell scripts and automation tools for Azure and Entra administration. Work in progress, intended to be an extensible toolkit for cloud and identity operations. More to be added over time.

## Structure

- `Microsoft/Entra/Modules/<FeatureName>/` for feature-specific Entra modules.
- `Microsoft/Entra/Modules/Shared/` for reusable Entra modules.
- `Microsoft/Azure/Modules/<FeatureName>/` for feature-specific Azure modules.
- `Microsoft/Azure/Modules/Shared/` for reusable Azure modules.
- `Microsoft/Common/Modules/` for cross-provider shared modules.

See `Microsoft/README.md` for module layout and import conventions.
