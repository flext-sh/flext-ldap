# API Reference Documentation


<!-- TOC START -->
- Overview
- Public API
  - Primary Entry Point
  - Core Modules
  - Server Operations
- Quick Reference
  - Import Patterns
  - Common Operations
- API Stability
  - Stable (Public API)
  - Internal (Subject to Change)
- Return Types
- Related Documentation
<!-- TOC END -->

**Version**: 1.0 (v0.10.0)
**Date**: 2025-01-24
**Python**: 3.13+

## Overview

Complete API reference for flext-ldap v0.10.0, covering all public interfaces, classes, and methods.

## Public API

### Primary Entry Point

**FlextLdap** - Main API facade

```python
from flext_ldap import FlextLdap

api = FlextLdap()
result = api.search_entries(search_request)
```

### Core Modules

1. **FlextLdapModels** - Domain models and entities
   - SearchRequest, Connection, Entry models
   - Domain logic and validations

2. **FlextLdapClients** - LDAP client operations
   - Authentication - Bind operations
   - Search - Search operations

3. **FlextLdapAcl** - ACL management
   - Manager - ACL operations
   - Parsers - ACL parsing
   - Converters - Format conversion

4. **FlextLdapSchema** - Schema operations
   - Discover - Schema discovery
   - Sync - Schema synchronization

5. **FlextLdapEntryAdapter** - Entry conversion
   - ldap3 → flext-ldif
   - flext-ldif → ldap3

### Server Operations

6. **Server Operations** - Server-specific implementations
   - OpenLDAP2Operations
   - OpenLDAP1Operations
   - OracleOIDOperations
   - OracleOUDOperations
   - ActiveDirectoryOperations
   - GenericServerOperations

## Quick Reference

### Import Patterns

```python
# Public API (recommended)
from flext_ldap import (
    FlextLdap,              # Main API
    FlextLdapModels,        # Models
    FlextLdapClients,       # Client operations
    FlextLdapAcl,           # ACL management
)

# Server operations
from flext_ldap.servers import (
    OpenLDAP2Operations,
    OracleOIDOperations,
)

# Entry adapter
from flext_ldap import FlextLdapEntryAdapter
```

### Common Operations

**Search**:

```python
api = FlextLdap()
search_request = FlextLdapModels.SearchRequest(
    base_dn="dc=example,dc=com",
    filter_str="(objectClass=person)"
)
result = api.search_entries(search_request)
```

**Authentication**:

```python
auth = FlextLdapClients.Authentication()
result = auth.bind(connection, dn, password)
```

**ACL Management**:

```python
acl_manager = FlextLdapAcl.Manager()
result = acl_manager.get_acls(connection, dn, server_type)
```

## API Stability

### Stable (Public API)

- ✅ FlextLdap - Main API facade
- ✅ FlextLdapModels - Domain models
- ✅ FlextLdapClients - Client operations
- ✅ FlextLdapAcl - ACL management

### Internal (Subject to Change)

- ⚠️ FlextLdapServices - Internal business logic
- ⚠️ FlextLdapHandlers - Internal handlers
- ⚠️ Server operations - May evolve with new features

## Return Types

All operations return `FlextResult[T]` from flext-core:

```python
result = api.search_entries(request)

# Success path
if result.is_success:
    entries = result.unwrap()

# Failure path
if result.is_failure:
    error = result.error
```

## Related Documentation

- Architecture - Architecture patterns
- Development - Contributing guidelines
- Migration Guide - v0.9.0 → v0.10.0

---

**Last Updated**: 2025-01-24
**API Version**: v0.10.0
