# Cross-Provider Shared Modules

Reusable helper modules intended for use across Azure, Entra, and future providers.

Current shared modules:

- `Logging.psm1`
	- Central logging helper with console/file output control.
	- Supports absolute/relative log path configuration via `Set-LogFilePath`.
