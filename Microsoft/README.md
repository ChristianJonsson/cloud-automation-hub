# Microsoft Automation Layout

This folder groups cloud automation by provider and identity platform.

## Module conventions

- Place feature-specific modules under `<Provider>/Modules/<FeatureName>/`.
- Place provider-wide reusable modules under `<Provider>/Modules/Shared/`.
- Place cross-provider reusable modules under `Common/Modules/`.
- In scripts, import local modules using `$PSScriptRoot` + `Join-Path`.

## Current examples

- Entra feature module: `Entra/Modules/UserTypeNullRemediation/`
- Entra script: `Entra/Update-Users-Where-UserType-Missing.ps1`
- Azure module root (ready): `Azure/Modules/`
- Cross-provider module root (ready): `Common/Modules/`
