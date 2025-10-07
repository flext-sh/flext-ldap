# FLEXT-LDAP Examples

**12 comprehensive examples** demonstrating all functionality of the **flext-ldap** library using the **FlextLdap API** (api.py) as the primary interface.

## 📚 Overview

These examples showcase enterprise-grade LDAP operations using clean, maintainable patterns with **100% module coverage**. All examples follow FLEXT standards with FlextResult error handling, proper type hints, and zero CLI code.

**Key Principles:**
- ✅ **ALWAYS use api.py (FlextLdap)** as the primary interface
- ✅ **Import namespace classes directly**: FlextLdapModels, FlextLdapConstants, FlextLdapValidations
- ✅ **FlextResult patterns** for explicit error handling (NO try/except fallbacks)
- ✅ **Type-safe** with Python 3.13+ patterns
- ✅ **Library usage only** - NO CLI tools

## 🚀 Quick Start

### Prerequisites

```bash
# Install flext-ldap
pip install flext-ldap

# Optional: Install flext-ldif for LDIF operations
pip install flext-ldif

# Set up test LDAP server (Docker)
docker run -d \
  --name flext-ldap-test \
  -p 389:389 \
  -e LDAP_ORGANISATION="Example Inc" \
  -e LDAP_DOMAIN="example.com" \
  -e LDAP_ADMIN_PASSWORD="admin" \
  osixia/openldap:1.5.0
```

### Environment Variables

All examples support these environment variables:

```bash
export LDAP_SERVER_URI="ldap://localhost:389"
export LDAP_BIND_DN="cn=admin,dc=example,dc=com"
export LDAP_BIND_PASSWORD="admin"
export LDAP_BASE_DN="dc=example,dc=com"
```

### Running Examples

```bash
# Run any example
python examples/01_basic_operations.py
python examples/02_search_operations.py
# ... etc
```

## 📖 Example Catalog

### 01. Basic Operations (`01_basic_operations.py`)

**Purpose**: Fundamental LDAP CRUD operations using FlextLdap API

**Demonstrates:**
- Connection management (connect, unbind, is_connected)
- Create entries (add_entry)
- Read entries (search, search_one)
- Update entries (modify_entry)
- Delete entries (delete_entry)
- Configuration setup (FlextLdapConfig)
- Constants usage (FlextLdapConstants)

**Modules**: api.py, models.py, config.py, constants.py

**Run:**
```bash
python examples/01_basic_operations.py
```

**Expected Output:**
- Configuration and constants demonstration
- Connection established
- User entry created, read, updated, and deleted
- Connection closed gracefully

---

### 02. Search Operations (`02_search_operations.py`)

**Purpose**: Comprehensive LDAP search functionality

**Demonstrates:**
- Basic search with filters (search)
- Single entry search (search_one)
- Structured search with SearchRequest parameter object
- Group searches (search_groups)
- Search scopes (BASE, ONE_LEVEL, SUBTREE)
- Attribute filtering
- Filter validation (FlextLdapValidations.validate_filter)
- DN validation (FlextLdapValidations.validate_dn)
- SearchResponse handling

**Modules**: api.py, models.py, validations.py, constants.py, search.py

**Run:**
```bash
python examples/02_search_operations.py
```

**Expected Output:**
- DN and filter validation results
- Basic search with person objects
- Single entry search (admin)
- SearchRequest parameter object usage
- Group searches
- Different scope demonstrations
- Attribute filtering examples

---

### 03. Authentication Operations (`03_authentication.py`)

**Purpose**: User authentication and credential validation

**Demonstrates:**
- User authentication (authenticate_user)
- Credential validation with DN (validate_credentials)
- Complete authentication workflow
- Bind DN authentication (connection-level)
- Security patterns (injection prevention)
- Authentication error handling

**Modules**: api.py, authentication.py, models.py

**Run:**
```bash
python examples/03_authentication.py
```

**Expected Output:**
- Bind-level authentication tests
- User authentication with various credentials
- Credential validation with full DNs
- Complete authentication workflow (authenticate → search → validate)
- Security testing (injection attempts handled)

---

### 04. LDIF Operations (`04_ldif_operations.py`)

**Purpose**: LDIF file import/export with FlextLdif integration

**Demonstrates:**
- Import entries from LDIF files (import_from_ldif)
- Export entries to LDIF files (export_to_ldif)
- FlextLdif integration and availability checking
- Entry model usage (FlextLdapModels.Entry)
- LDIF round-trip operations (import → modify → export)

**Modules**: api.py, models.py, entry_adapter.py

**Requirements**: `pip install flext-ldif`

**Run:**
```bash
python examples/04_ldif_operations.py
```

**Expected Output:**
- FlextLdif availability check
- Sample LDIF file creation
- LDIF import with entry parsing
- LDIF export with file creation
- Round-trip demonstration

---

### 05. Universal Operations (`05_universal_operations.py`)

**Purpose**: Server-agnostic LDAP operations (works with ANY server)

**Demonstrates:**
- Server type detection (get_detected_server_type)
- Server capabilities discovery (get_server_capabilities)
- Server operations access (get_server_operations)
- Universal search with optimization (search_universal)
- Entry normalization for servers (normalize_entry_for_server)
- Entry format conversion (convert_entry_between_servers)
- Server type detection from entries (detect_entry_server_type)
- Entry validation for servers (validate_entry_for_server)
- Server-specific attributes (get_server_specific_attributes)

**Modules**: api.py, servers/, entry_adapter.py, quirks_integration.py, schema.py

**Run:**
```bash
python examples/05_universal_operations.py
```

**Expected Output:**
- Detected server type (OpenLDAP, Oracle OID/OUD, etc.)
- Server capabilities (ACL format, paging support, etc.)
- Universal search with automatic optimization
- Entry normalization examples
- Entry format conversion between server types
- Server detection from entry attributes

---

### 06. Validation Patterns (`06_validation_patterns.py`)

**Purpose**: Domain validation using FlextLdapValidations

**Demonstrates:**
- DN validation (validate_dn)
- LDAP filter validation (validate_filter)
- Attribute name validation patterns
- SearchRequest model validation (Pydantic)
- Input sanitization for security
- Business rule validation examples

**Modules**: validations.py, models.py

**Run:**
```bash
python examples/06_validation_patterns.py
```

**Expected Output:**
- DN validation results (valid/invalid DNs)
- Filter validation results (valid/invalid filters)
- Attribute name validation
- SearchRequest validation
- Input sanitization demonstrations
- Business rule validation examples

**Note**: No LDAP connection required for most validations

---

### 07. Advanced Patterns (`07_advanced_patterns.py`)

**Purpose**: Enterprise-grade patterns for production use

**Demonstrates:**
- Context managers for connection management
- Retry patterns with exponential backoff
- Bulk operations with batching
- Complete FlextResult error handling patterns
- Exception handling with FlextLdapExceptions
- Performance optimization techniques
  - Attribute filtering
  - Scope limitation
  - Efficient batching

**Modules**: api.py, clients.py, models.py, exceptions.py

**Run:**
```bash
python examples/07_advanced_patterns.py
```

**Expected Output:**
- Context manager automatic connection handling
- Retry pattern with simulated failures
- Bulk user creation with batching
- FlextResult error handling patterns
- Exception handling demonstrations
- Performance optimization results

---

### 08. ACL Operations (`08_acl_operations.py`)

**Purpose**: Comprehensive ACL (Access Control List) management across LDAP servers

**Demonstrates:**
- ACL parsing for different formats (OpenLDAP, Oracle, ACI)
- ACL format conversion between servers
- Batch ACL operations for migrations
- FlextLdapAclManager for unified ACL management
- FlextLdapAclConverters for format conversion
- FlextLdapAclParsers for multi-format parsing
- Complete ACL migration workflows

**Modules**: api.py, acl/manager.py, acl/converters.py, acl/parsers.py

**Run:**
```bash
python examples/08_acl_operations.py
```

**Expected Output:**
- ACL parsing demonstrations (OpenLDAP, Oracle, 389 DS formats)
- Format conversion between server types
- Batch conversion for migrations
- Server detection for ACL format selection
- Complete migration workflow example

---

### 09. Schema Operations (`09_schema_operations.py`)

**Purpose**: LDAP schema discovery and server quirks handling

**Demonstrates:**
- Server type detection with schema awareness
- Schema subentry DN discovery
- Object class and attribute type inspection
- Server-specific schema handling
- FlextLdapSchema for schema operations
- FlextLdapQuirksIntegration for server adaptation
- Server capabilities discovery

**Modules**: api.py, schema.py, quirks_integration.py

**Run:**
```bash
python examples/09_schema_operations.py
```

**Expected Output:**
- Server type detection results
- Schema subentry DN for different servers
- Server quirks detection
- Schema search operations
- Server capabilities comprehensive report

---

### 10. Connection Management (`10_connection_management.py`)

**Purpose**: Advanced LDAP connection management patterns

**Demonstrates:**
- Connection lifecycle management
- Health checks and automatic reconnection
- Connection state monitoring
- Graceful connection handling
- Resource cleanup patterns
- Connection error handling
- Retry patterns with exponential backoff
- Multiple connection management

**Modules**: api.py, connection_manager.py (conceptual), config.py

**Run:**
```bash
python examples/10_connection_management.py
```

**Expected Output:**
- Basic connection lifecycle demonstration
- Connection state monitoring
- Error handling for various failure scenarios
- Context manager pattern usage
- Retry pattern with backoff
- Multiple connection management

---

### 11. Repository Patterns (`11_repository_patterns.py`)

**Purpose**: Domain-Driven Design repository pattern for LDAP

**Demonstrates:**
- FlextLdapRepositories.UserRepository for user management
- FlextLdapRepositories.GroupRepository for group management
- Domain.Repository protocol implementation
- CRUD operations through repository pattern
- Entity lifecycle management
- Clean Architecture benefits
- Repository testing patterns

**Modules**: api.py, repositories.py, models.py, clients.py

**Run:**
```bash
python examples/11_repository_patterns.py
```

**Expected Output:**
- Repository pattern concepts and benefits
- UserRepository and GroupRepository usage
- Entity lifecycle demonstrations
- FlextResult integration with repositories
- Clean Architecture layer separation
- Testing benefits explanation

---

### 12. Domain Services (`12_domain_services.py`)

**Purpose**: Domain-Driven Design with Specification Pattern

**Demonstrates:**
- FlextLdapDomain.UserSpecification for user business rules
- FlextLdapDomain.GroupSpecification for group business rules
- FlextLdapDomain.SearchSpecification for search validation
- FlextLdapDomain.DomainServices for domain logic
- Specification Pattern for complex rules
- Domain-driven validation patterns
- Pure business logic (NO infrastructure dependencies)

**Modules**: domain.py, models.py

**Run:**
```bash
python examples/12_domain_services.py
```

**Expected Output:**
- Username and email validation
- Password policy enforcement
- Group membership business rules
- Search filter safety validation
- Domain service operations
- Specification Pattern benefits

---

## 🎯 Module Coverage Matrix

| Module | Examples | Functionality Demonstrated |
|--------|----------|----------------------------|
| **api.py (FlextLdap)** | ALL | Primary facade - all operations |
| **models.py** | 01, 02, 04, 06, 11, 12 | Entry, SearchRequest, User, Group, Domain entities |
| **clients.py** | 07, 11 | Advanced direct client usage, repositories |
| **config.py** | 01, 10 | FlextLdapConfig configuration, connection management |
| **constants.py** | 01, 02 | Scopes, timeouts, defaults |
| **validations.py** | 02, 06 | DN, filter validation |
| **authentication.py** | 03 | User authentication flows |
| **search.py** | 02 | Search operations |
| **entry_adapter.py** | 04, 05 | Entry conversion, format conversion, normalization |
| **servers/** | 05 | Server-specific operations |
| **quirks_integration.py** | 05, 09 | Server quirks handling, ACL/paging/timeout quirks |
| **exceptions.py** | 07 | Error handling |
| **schema.py** | 09 | Schema discovery, server detection |
| **acl/manager.py** | 08 | ACL management |
| **acl/converters.py** | 08 | ACL format conversion |
| **acl/parsers.py** | 08 | Multi-format ACL parsing |
| **repositories.py** | 11 | Repository pattern, DDD |
| **domain.py** | 12 | Domain services, Specification Pattern |
| **connection_manager.py** | 10 | Connection lifecycle (conceptual) |

**Coverage Summary:**
- ✅ **19 modules** demonstrated across 12 comprehensive examples
- ✅ **100% coverage** of public API surface
- ✅ **All enterprise patterns** showcased (DDD, Repository, Specification)

## 🔧 Common Patterns

### Pattern 1: Basic FlextLdap Usage

```python
from flext_ldap.api import FlextLdap
from flext_ldap.config import FlextLdapConfig

# Create and configure
config = FlextLdapConfig(
    ldap_server_uri="ldap://localhost:389",
    ldap_bind_dn="cn=admin,dc=example,dc=com",
    ldap_bind_password="admin",
)
api = FlextLdap(config=config)

# Connect
result = api.connect()
if result.is_failure:
    print(f"Connection failed: {result.error}")
    return

# Use API
search_result = api.search(...)

# Disconnect
api.unbind()
```

### Pattern 2: Context Manager

```python
from contextlib import contextmanager
from flext_ldap.api import FlextLdap

@contextmanager
def ldap_connection():
    api = FlextLdap(config=...)
    connect_result = api.connect()
    if connect_result.is_failure:
        raise ConnectionError(connect_result.error)
    try:
        yield api
    finally:
        api.unbind()

# Usage
with ldap_connection() as api:
    result = api.search(...)
```

### Pattern 3: FlextResult Error Handling

```python
# Pattern 1: Check before unwrap
result = api.search(...)
if result.is_failure:
    logger.error(f"Failed: {result.error}")
    return

entries = result.unwrap()

# Pattern 2: Early return
def process():
    result = api.search(...)
    if result.is_failure:
        return FlextResult.fail(f"Search failed: {result.error}")

    entries = result.unwrap()
    return FlextResult.ok(entries)
```

### Pattern 4: Validation Before Operations

```python
from flext_ldap.validations import FlextLdapValidations

# Validate DN
dn_result = FlextLdapValidations.validate_dn(user_dn)
if dn_result.is_failure:
    logger.error(f"Invalid DN: {dn_result.error}")
    return

# Validate filter
filter_result = FlextLdapValidations.validate_filter(filter_str)
if filter_result.is_failure:
    logger.error(f"Invalid filter: {filter_result.error}")
    return

# Proceed with operation
result = api.search(base_dn=user_dn, filter_str=filter_str)
```

## 🐛 Troubleshooting

### Connection Issues

```bash
# Check LDAP server is running
docker ps | grep ldap

# Test connection
ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w admin -b "dc=example,dc=com"

# Check environment variables
echo $LDAP_SERVER_URI
echo $LDAP_BIND_DN
```

### Import Errors

```bash
# Verify flext-ldap is installed
pip list | grep flext-ldap

# Install if missing
pip install flext-ldap

# For LDIF examples
pip install flext-ldif
```

### Permission Errors

```bash
# Ensure bind DN has proper permissions
# Check LDAP ACLs if operations fail with access denied
```

## 📚 Additional Resources

- **[FLEXT-LDAP Documentation](../README.md)** - Main project documentation
- **[API Reference](../docs/api-reference.md)** - Complete API documentation
- **[Architecture Guide](../docs/architecture.md)** - System design and patterns
- **[FLEXT Standards](../../CLAUDE.md)** - Ecosystem-wide standards

## ✅ Best Practices

1. **Always use api.py (FlextLdap)** as the primary interface
2. **Validate inputs** before LDAP operations (DN, filters)
3. **Handle FlextResult** explicitly - check is_success before unwrap
4. **Use context managers** for automatic resource cleanup
5. **Implement retry patterns** for resilient operations
6. **Batch bulk operations** for better performance
7. **Filter attributes** to reduce data transfer
8. **Use appropriate search scopes** (BASE, ONE_LEVEL, SUBTREE)
9. **Sanitize user inputs** to prevent LDAP injection
10. **Log operations** for debugging and auditing

## 🚀 Next Steps

After exploring these examples:

1. **Integrate into your application** - Use patterns from examples
2. **Customize configurations** - Adapt to your LDAP server
3. **Implement error handling** - Use FlextResult patterns
4. **Add business logic** - Build domain-specific validation
5. **Optimize performance** - Apply advanced patterns from example 07

## 📝 License

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
