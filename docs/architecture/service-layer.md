# Service Layer

<!-- TOC START -->

- [Services](#services)
  - [Connection](#connection)
  - [Operations](#operations)
  - [Synchronization](#synchronization)
  - [Server Detection](#server-detection)
- [Collaboration Pattern](#collaboration-pattern)

<!-- TOC END -->

The service layer contains the composable building blocks that power the `ldap` facade.
Each service is focused on a single responsibility and uses `r` to make success and
failure explicit.

## Services

### Connection

- **File**: `src/flext_ldap/services/connection.py`
- **Responsibility**: Manage the `ldap3` connection lifecycle (create, bind, disconnect)
  while optionally retrying transient errors.
- **Inputs**: `FlextLdapModels.ConnectionConfig`
- **Outputs**: `r[bool]` plus logging and optional server detection.

### Operations

- **File**: `src/flext_ldap/services/operations.py`
- **Responsibility**: Perform search, add, modify, delete, and upsert operations against
  an active connection.
- **Inputs**: Typed models such as `SearchOptions`, `Entry`, and `ModifyChanges`
  structures.
- **Outputs**: `r` wrappers containing operation metadata and parsed entries.

### Synchronization

- **File**: `src/flext_ldap/services/sync.py`
- **Responsibility**: Stream LDIF data into LDAP, emitting progress callbacks, tracking
  per-entry statistics, and supporting multi-phase syncs.
- **Inputs**: LDIF file paths or raw LDIF strings plus sync options.
- **Outputs**: `FlextLdapModels.SyncStats` and `MultiPhaseSyncResult` models.

### Server Detection

- **Files**: `src/flext_ldap/services/connection.py`, `src/flext_ldap/adapters/ldap3.py`
- **Responsibility**: After bind, the adapter's `root_dse` reads `rootDSE` on the
  connection and `u.Ldap.detect_from_root_dse` infers the directory server type using
  in-project heuristics instead of the flext-ldif detector.
- **Outputs**: the detected server label used for result parsing.

## Collaboration Pattern

```text
ldap → Connection (rootDSE server detection)
          → Operations (search/CRUD/upsert)
          → SyncService (uses Operations under the hood)
```

Services are constructed directly and passed into `ldap`, allowing callers or tests to
replace implementations without altering the facade API.
