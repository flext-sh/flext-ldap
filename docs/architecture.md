# FLEXT-LDAP Architecture

FLEXT-LDAP wraps `ldap3` and `flext-ldif` behind a small service layer and a
facade class. Dependency injection keeps the public API stable while letting
callers replace services or adapters for testing and alternative runtimes.

## Layered View

```
 FlextLdap facade (api.py)
  ├── Connection (services/connection.py)
  ├── Operations (services/operations.py)
  ├── Sync (services/sync.py)
  └── Server detection (services/detection.py)
        └── Ldap3Adapter / EntryAdapter (adapters/*.py)
            └── ldap3 + flext-ldif
```

- **Facade**: :class:`flext_ldap.api.FlextLdap` composes the services and exposes
  the high-level API used by callers.
- **Services**: Connection, Operations, Sync, and Server Detection manage LDAP
  lifecycle concerns and return typed :class:`flext_core.FlextResult` values.
- **Adapters**: :class:`flext_ldap.adapters.ldap3.Ldap3Adapter` and
  :class:`flext_ldap.adapters.entry.FlextLdapEntryAdapter` isolate protocol
  handling and entry normalization.
- **Shared types**: `config.py`, `models.py`, `constants.py`,
  `protocols.py`, and `typings.py` define pydantic models, enums, and typing
  contracts used across layers.

## Module Map

- **Facade**: `src/flext_ldap/api.py`
- **Services**: `src/flext_ldap/services/{connection,operations,sync,detection}.py`
- **Adapters**: `src/flext_ldap/adapters/{ldap3,entry}.py`
- **Shared contracts**: `src/flext_ldap/{config,models,constants,protocols,typings}.py`

## Runtime Flows

### Connecting

1. `FlextLdap.connect` converts incoming dictionaries to
   :class:`~flext_ldap.models.FlextLdapModels.ConnectionConfig` when needed.
2. :class:`~flext_ldap.services.connection.FlextLdapConnection` delegates
   binding to :class:`~flext_ldap.adapters.ldap3.Ldap3Adapter`, with optional
   retry handling.
3. After a successful bind, the connection service can trigger
   :class:`~flext_ldap.services.detection.FlextLdapServerDetector` to infer the
   server type from `rootDSE` attributes.

### Search and CRUD

1. The facade forwards search/add/modify/delete calls to
   :class:`~flext_ldap.services.operations.FlextLdapOperations`.
2. The operations service normalizes DNs and delegates protocol calls to the
   LDAP adapter, which returns typed results already parsed by `flext-ldif`.
3. Results are wrapped in `FlextResult` instances for explicit
   success/failure handling.

### Synchronization

1. :class:`~flext_ldap.services.sync.FlextLdapSyncService` reads LDIF content
   (from files or pre-parsed entries) and streams it through the operations
   service.
2. Batch mode collects per-entry stats and supports progress callbacks;
   multi-phase syncs reuse the same pipeline while attaching phase metadata.
3. Final statistics are returned via
   :class:`flext_ldap.models.FlextLdapModels.SyncStats`.

### Server Detection

1. :class:`~flext_ldap.services.detection.FlextLdapServerDetector` queries
   `rootDSE` using the active ldap3 connection.
2. Vendor attributes are matched against lightweight in-project heuristics to
   return a server label (for example, `rfc`, `openldap`, `ad`) without
   relying on external detection helpers.

## Design Notes

- **Dependency injection** keeps the facade decoupled from specific adapters and
  services while simplifying tests.
- **Typed boundaries** use pydantic models and protocols to normalize data
  exchanged across layers.
- **Railway-oriented results** rely on `FlextResult` to surface errors without
  exceptions in the main control flow.
- **Adapter isolation** ensures protocol quirks and conversions stay localized to
  the adapter layer.
