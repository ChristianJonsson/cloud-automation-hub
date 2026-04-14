# Environment Configuration Reference

This file serves two purposes:

1. **Template** — use the table below to identify the values you need to fill in to `00_Config.ps1` for your environment.
2. **Reference implementation** — the current deployment is documented below with anonymised values as a worked example.

---

## Configuration Template

Run `01_EntraConnect_Config.ps1` and `02_SyncRules.ps1` to retrieve these values from your Entra Connect server.

| Setting | Where to find it | `00_Config.ps1` variable |
|---------|-----------------|--------------------------|
| Output path | Your preference (default: `C:\tmp\`) | `$OutputPath` |
| Source anchor method | `Get-ADSyncGlobalSettings` — `SourceAnchor` field; or ADUC Attribute Editor on a synced user | `$ImmutableIdMethod` |
| Custom ImmutableId attribute | Only if source anchor is a custom AD attribute | `$CustomImmutableIdAttribute` |
| AD connector type name | `Get-ADSyncConnector \| Select ConnectorTypeName` (standard: `"AD"`) | `$ADConnectorTypeName` |
| Custom sync rule names | `Get-ADSyncRule \| Where Direction -eq "Inbound" \| Select Name` | `$KeySyncRuleNames` |

---

## Reference Implementation

The following describes the environment for which these scripts were originally developed. Use it as a worked example when configuring for a new environment.

### Identity and Domain

| Item | Reference value | Your value |
|------|----------------|------------|
| Domain | `<your-domain>` (e.g. `corp.local`, `company.com`) | |
| Entra Connect server | `<entraconnect-server>.<your-domain>` | |
| Last DC used | `<dc-name>.<your-domain>` | |
| Entra Connect version | *(run `01_EntraConnect_Config.ps1` to retrieve)* | |

### Sync Configuration

| Item | Reference value | Your value |
|------|----------------|------------|
| Sync method | Pass-Through Authentication (PasswordHashSync: False) | |
| Staging mode | False (active server) | |
| Sync interval | 30 minutes (Delta) | |
| OU filter | Connector-level only — no attribute-based scope filters | |
| Writeback | All writeback features disabled | |

### Source Anchor

| Item | Reference value | Your value |
|------|----------------|------------|
| `$ImmutableIdMethod` | `"ObjectGUID"` | |
| `$CustomImmutableIdAttribute` | `$null` | |
| `mS-DS-ConsistencyGuid` populated? | No — standard ObjectGUID conversion in use | |

> **Note:** In this reference environment `mS-DS-ConsistencyGuid` is not populated on AD user objects. The ImmutableId for each user is derived by Base64-encoding the `ObjectGUID`. See [README.md](README.md) — Setup 1 for full details.

### Custom Sync Rules

| Rule name pattern | Purpose |
|------------------|---------|
| `In from AD - User Dirsync Disconnector` | Standard Microsoft rule present in all Entra Connect environments. Filters accounts that don't match any higher-priority inbound rule by setting `cloudFiltered = True`. |
| `<ORG-PREFIX> - In from AD - <attribute>` | Example of an org-specific custom rule. Add your environment's custom rule names to `$KeySyncRuleNames` in `00_Config.ps1`. |

### Disconnector Rule Behaviour

In this reference environment the Disconnector rule (`In from AD - User Dirsync Disconnector`) has an **empty ScopeFilter**. It fires on precedence (99) only — accounts that do not match any higher-priority inbound rule are assigned `cloudFiltered = True` as a constant with no attribute-based expression.

If `02_SyncRules.ps1` outputs an empty scope condition file for the Disconnector rule, this is expected behaviour — not an error. See the Troubleshooting section in [README.md](README.md) for context.
