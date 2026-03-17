# Azure Modules

Use this folder for Azure PowerShell modules.

## Suggested structure

- `Modules/<FeatureName>/` for feature-specific modules.
- `Modules/Shared/` for Azure-wide reusable modules.

Use `$PSScriptRoot` + `Join-Path` in scripts for reliable module imports.
