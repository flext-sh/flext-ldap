# Adapter Layer

Adapters isolate external libraries so that services remain focused on domain
logic. flext-ldap ships two adapters that wrap `ldap3` and normalize entries to
`flext-ldif` models.

## Ldap3Adapter

- **File**: `src/flext_ldap/adapters/ldap3.py`
- **Role**: Wraps `ldap3.Server` and `ldap3.Connection` objects with a typed API
  that returns `FlextResult` objects and parsed flext-ldif entries.
- **Key features**:
  - Connection construction with TLS/SSL handling.
  - Search and CRUD helpers that reuse `FlextLdifParser`.
  - Conversion of raw ldap3 responses into normalized attribute dictionaries.

## FlextLdapEntryAdapter

- **File**: `src/flext_ldap/adapters/entry.py`
- **Role**: Converts between ldap3 entries and flext-ldif `Entry` models,
  handling DN normalization, attribute typing, and metadata preservation.
- **Key features**:
  - Map ldap3 attribute collections to `Attributes` objects.
  - Build ldap3 attribute payloads from flext-ldif entries for write operations.
  - Centralizes conversion rules so service code stays free of protocol details.

## Why Adapters Matter

Isolating protocol nuances in the adapter layer means the service layer can stay
small, composable, and easy to test. Mocking adapters or swapping them out for
stubs does not require changes to business logic or the public `FlextLdap`
interface.
