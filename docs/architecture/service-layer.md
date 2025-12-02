# Service Layer

The service layer contains the composable building blocks that power the
`FlextLdap` facade. Each service is focused on a single responsibility and uses
`FlextResult` to make success and failure explicit.

## Services

### Connection
- **File**: `src/flext_ldap/services/connection.py`
- **Responsibility**: Manage the `ldap3` connection lifecycle (create, bind,
  disconnect) while optionally retrying transient errors.
- **Inputs**: `FlextLdapModels.ConnectionConfig`
- **Outputs**: `FlextResult[bool]` plus logging and optional server detection.

### Operations
- **File**: `src/flext_ldap/services/operations.py`
- **Responsibility**: Perform search, add, modify, delete, and upsert
  operations against an active connection.
- **Inputs**: Typed models such as `SearchOptions`, `Entry`, and
  `ModifyChanges` structures.
- **Outputs**: `FlextResult` wrappers containing operation metadata and parsed
  entries.

### Synchronization
- **File**: `src/flext_ldap/services/sync.py`
- **Responsibility**: Stream LDIF data into LDAP, emitting progress callbacks,
  tracking per-entry statistics, and supporting multi-phase syncs.
- **Inputs**: LDIF file paths or raw LDIF strings plus sync options.
- **Outputs**: `FlextLdapModels.SyncStats` and `MultiPhaseSyncResult` models.

### Server Detection
- **File**: `src/flext_ldap/services/detection.py`
- **Responsibility**: Inspect `rootDSE` attributes from a live connection and
  infer the directory server type using in-project heuristics instead of the
  flext-ldif detector.
- **Inputs**: Bound `ldap3.Connection`
- **Outputs**: `FlextResult[str]` containing the detected server label.

## Collaboration Pattern

```
FlextLdap → Connection → (optional) ServerDetector
          → Operations (search/CRUD/upsert)
          → SyncService (uses Operations under the hood)
```

Services are constructed directly and passed into `FlextLdap`, allowing callers
or tests to replace implementations without altering the facade API.
