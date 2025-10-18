# Getting Started with FLEXT-LDAP
## Table of Contents

- [Getting Started with FLEXT-LDAP](#getting-started-with-flext-ldap)
  - [Prerequisites](#prerequisites)
    - [**System Requirements**](#system-requirements)
    - [**LDAP Server Requirements**](#ldap-server-requirements)
  - [Installation](#installation)
    - [**Production Installation**](#production-installation)
- [or with poetry](#or-with-poetry)
    - [**Development Installation**](#development-installation)
    - [**Verify Installation**](#verify-installation)
  - [Configuration](#configuration)
    - [**Environment Variables**](#environment-variables)
- [Basic LDAP server configuration](#basic-ldap-server-configuration)
- [Authentication](#authentication)
- [Connection settings](#connection-settings)
    - [**Configuration File**](#configuration-file)
  - [First Steps](#first-steps)
    - [**Basic Connection Test**](#basic-connection-test)
    - [**Simple Directory Search**](#simple-directory-search)
    - [**User Authentication**](#user-authentication)
  - [Universal LDAP Interface](#universal-ldap-interface)
    - [**Server-Specific Operations**](#server-specific-operations)
    - [**Entry Conversion (ldap3 ↔ FlextLdif)**](#entry-conversion-ldap3--flextldif)
- [ldap3 → FlextLdif](#ldap3--flextldif)
- [FlextLdif → ldap3](#flextldif--ldap3)
    - [**Schema Discovery**](#schema-discovery)
    - [**ACL Management**](#acl-management)
    - [**Paged Search**](#paged-search)
  - [Development Environment](#development-environment)
    - [**Test LDAP Server Setup**](#test-ldap-server-setup)
- [Start OpenLDAP test server](#start-openldap-test-server)
- [Verify server is running](#verify-server-is-running)
- [Stop test server](#stop-test-server)
    - [**Run Tests**](#run-tests)
- [Run all tests](#run-all-tests)
- [Run specific test categories](#run-specific-test-categories)
- [Run with coverage](#run-with-coverage)
    - [**Development Workflow**](#development-workflow)
- [Daily development cycle](#daily-development-cycle)
  - [Next Steps](#next-steps)
  - [Troubleshooting](#troubleshooting)
    - [**Common Issues**](#common-issues)


**LDAP directory services integration for the FLEXT ecosystem**

This guide covers installation, basic configuration, and first steps with flext-ldap.

**Version**: 0.9.9 | **Test Coverage**: 35% | **Phase 2**: ✅ Complete
**Architecture**: Clean Architecture + DDD + Railway-oriented programming

---

## Prerequisites

### **System Requirements**

- **Python 3.13+** with type system support
- **Poetry 1.8+** for dependency management
- **Git** for version control
- **Docker** (optional, for testing with OpenLDAP container)

### **LDAP Server Requirements**

**Production:**

- OpenLDAP 2.5+, Active Directory, or other LDAP v3 compliant server
- SSL/TLS configured (recommended)
- Service account with appropriate permissions

**Development/Testing:**

- Docker for running test LDAP server
- osixia/openldap:1.5.0 container (automatic setup available)

---

## Installation

### **Production Installation**

Install from PyPI:

```bash
pip install flext-ldap
# or with poetry
poetry add flext-ldap
```

### **Development Installation**

Clone and setup development environment:

```bash
git clone <repository-url>
cd flext-ldap
make setup      # Install dependencies, pre-commit hooks, dev tools
make validate   # Run quality checks to verify installation
```

### **Verify Installation**

Test your installation:

```bash
python -c "from flext_ldap import get_flext_ldap_api; print('Installation successful')"
```

---

## Configuration

### **Environment Variables**

Configure LDAP connection settings:

```bash
# Basic LDAP server configuration
export FLEXT_LDAP_HOST=ldap.example.com
export FLEXT_LDAP_PORT=636
export FLEXT_LDAP_USE_SSL=true
export FLEXT_LDAP_BASE_DN="dc=example,dc=com"

# Authentication
export FLEXT_LDAP_BIND_DN="cn=admin,dc=example,dc=com"
export FLEXT_LDAP_BIND_PASSWORD="your-password"

# Connection settings
export FLEXT_LDAP_TIMEOUT=30
export FLEXT_LDAP_POOL_SIZE=5
```

### **Configuration File**

Create `flext_ldap_config.py`:

```python
from Flext_ldap import FlextLdapConfig

config = FlextLdapConfig(
    host="ldap.example.com",
    port=636,
    use_ssl=True,
    base_dn="dc=example,dc=com",
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="your-password",
    timeout=30,
    pool_size=5
)
```

---

## First Steps

### **Basic Connection Test**

```python
from flext_ldap import get_flext_ldap_api

def test_connection():
    """Test basic LDAP connectivity."""
    api = get_flext_ldap_api()

    result = api.test_connection()
    if result.is_success:
        print("✅ LDAP connection successful")
    else:
        print(f"❌ Connection failed: {result.error}")

run(test_connection())
```

### **Simple Directory Search**

```python
from flext_ldap import get_flext_ldap_api, FlextLdapEntities

def basic_search():
    """Perform a basic directory search."""
    api = get_flext_ldap_api()

    search_request = FlextLdapEntities.SearchRequest(
        base_dn="dc=example,dc=com",
        filter_str="(objectClass=organizationalUnit)",
        scope="subtree",
        attributes=["ou", "description"]
    )

    result = api.search_entries(search_request)
    if result.is_success:
        entries = result.unwrap()
        print(f"Found {len(entries)} organizational units:")
        for entry in entries:
            print(f"  - {entry.ou}: {entry.description}")
    else:
        print(f"Search failed: {result.error}")

run(basic_search())
```

### **User Authentication**

```python
from flext_ldap import get_flext_ldap_api

def authenticate_user():
    """Authenticate a user against LDAP."""
    api = get_flext_ldap_api()

    username = "john.doe"
    password = "user-password"

    result = api.authenticate_user(username, password)
    if result.is_success:
        user = result.unwrap()
        print(f"✅ Authentication successful for {user.uid}")
    else:
        print(f"❌ Authentication failed: {result.error}")

run(authenticate_user())
```

---

## Universal LDAP Interface

### **Server-Specific Operations**

FLEXT-LDAP provides server-specific implementations with automatic server detection:

```python
import ldap3
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter
from flext_ldap.servers import OpenLDAP2Operations, OracleOIDOperations

def server_specific_operations():
    """Use server-specific operations with automatic detection."""

    # Connect to LDAP server
    connection = ldap3.Connection(
        ldap3.Server('ldap://server:389'),
        user='cn=admin,dc=example,dc=com',
        password='password',
        auto_bind=True
    )

    # Initialize adapters
    adapter = FlextLdapEntryAdapter()
    quirks = FlextLdapQuirksAdapter()

    # Search for entries
    connection.search('dc=example,dc=com', '(objectClass=*)', attributes=['*'])

    # Convert to FlextLdif
    entries = []
    for ldap3_entry in connection.entries:
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        if result.is_success:
            entries.append(result.unwrap())

    # Detect server type
    server_type_result = quirks.detect_server_type_from_entries(entries)
    if server_type_result.is_success:
        server_type = server_type_result.unwrap()
        print(f"Detected server: {server_type}")

        # Select appropriate operations
        if server_type == "openldap2":
            ops = OpenLDAP2Operations()
        elif server_type == "oid":
            ops = OracleOIDOperations()
        else:
            from flext_ldap.servers import GenericServerOperations
            ops = GenericServerOperations()

        # Discover schema
        schema_result = ops.discover_schema(connection)
        if schema_result.is_success:
            schema = schema_result.unwrap()
            print(f"Object classes: {len(schema['object_classes'])}")

run(server_specific_operations())
```

### **Entry Conversion (ldap3 ↔ FlextLdif)**

Convert between ldap3 and FlextLdif entry formats:

```python
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldif import FlextLdifModels
import ldap3

adapter = FlextLdapEntryAdapter()

# ldap3 → FlextLdif
connection.search('dc=example,dc=com', '(objectClass=person)')
for ldap3_entry in connection.entries:
    ldif_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
    if ldif_result.is_success:
        ldif_entry = ldif_result.unwrap()
        print(f"DN: {ldif_entry.dn}")

# FlextLdif → ldap3
ldif_entry = FlextLdifModels.Entry(
    dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
    attributes=FlextLdifModels.Attributes(attributes={
        "objectClass": ["person"],
        "cn": ["test"],
        "sn": ["Test User"]
    })
)

attrs_result = adapter.ldif_entry_to_ldap3_attributes(ldif_entry)
if attrs_result.is_success:
    attributes = attrs_result.unwrap()
    connection.add(str(ldif_entry.dn), attributes=attributes)
```

### **Schema Discovery**

Discover schema from different LDAP server types:

```python
from flext_ldap.servers import OpenLDAP2Operations
import ldap3

def discover_schema():
    """Discover schema from OpenLDAP 2.x server."""
    ops = OpenLDAP2Operations()

    connection = ldap3.Connection(
        ldap3.Server('ldap://server:389'),
        user='cn=admin,dc=example,dc=com',
        password='password',
        auto_bind=True
    )

    schema_result = ops.discover_schema(connection)
    if schema_result.is_success:
        schema = schema_result.unwrap()

        print(f"Object Classes: {len(schema['object_classes'])}")
        print(f"Attribute Types: {len(schema['attribute_types'])}")
        print(f"Syntaxes: {len(schema['syntaxes'])}")
        print(f"Server Type: {schema['server_type']}")

run(discover_schema())
```

### **ACL Management**

Manage server-specific ACLs:

```python
from flext_ldap.servers import OpenLDAP2Operations
import ldap3

def manage_acls():
    """Get and set ACLs on OpenLDAP 2.x server."""
    ops = OpenLDAP2Operations()

    connection = ldap3.Connection(
        ldap3.Server('ldap://server:389'),
        user='cn=admin,dc=example,dc=com',
        password='password',
        auto_bind=True
    )

    # Get ACLs
    dn = 'olcDatabase={1}mdb,cn=config'
    acl_result = ops.get_acls(connection, dn)

    if acl_result.is_success:
        acls = acl_result.unwrap()
        print(f"Found {len(acls)} ACLs")

        # Set new ACLs
        new_acls = [
            {"raw": "{0}to * by dn=\"cn=admin,dc=example,dc=com\" write"},
            {"raw": "{1}to * by self write by anonymous auth"}
        ]

        set_result = ops.set_acls(connection, dn, new_acls)
        if set_result.is_success:
            print("ACLs updated successfully")

run(manage_acls())
```

### **Paged Search**

Execute paged searches with automatic pagination:

```python
from flext_ldap.servers import OpenLDAP2Operations
import ldap3

def paged_search():
    """Execute paged search with automatic pagination."""
    ops = OpenLDAP2Operations()

    connection = ldap3.Connection(
        ldap3.Server('ldap://server:389'),
        user='cn=admin,dc=example,dc=com',
        password='password',
        auto_bind=True
    )

    result = ops.search_with_paging(
        connection,
        base_dn="ou=users,dc=example,dc=com",
        search_filter="(objectClass=person)",
        attributes=["uid", "cn", "mail"],
        page_size=100
    )

    if result.is_success:
        entries = result.unwrap()
        print(f"Found {len(entries)} entries")
        for entry in entries:
            print(f"  DN: {entry.dn}")

run(paged_search())
```

---

## Development Environment

### **Test LDAP Server Setup**

For development and testing, use Docker:

```bash
# Start OpenLDAP test server
make ldap-test-server

# Verify server is running
docker ps | grep flext-ldap-test-server

# Stop test server
make ldap-test-server-stop
```

### **Run Tests**

```bash
# Run all tests
make test

# Run specific test categories
pytest tests/unit/           # Unit tests
pytest tests/integration/   # Integration tests (requires LDAP server)
pytest tests/e2e/          # End-to-end tests

# Run with coverage
pytest --cov=src/flext_ldap
```

### **Development Workflow**

```bash
# Daily development cycle
make format     # Auto-format code
make lint       # Check code style
make type-check # Verify type annotations
make test       # Run tests
make validate   # Complete quality pipeline
```

---

## Next Steps

Once you have flext-ldap installed and working:

1. **[Server Operations Guide](server-operations.md)** - Server-specific LDAP operations
2. **[Architecture Guide](architecture.md)** - Universal LDAP interface architecture
3. **[API Reference](api-reference.md)** - Complete API documentation
4. **[Integration Guide](integration.md)** - FLEXT ecosystem and FlextLdif integration
5. **[Examples](examples/)** - Working code examples
6. **[Development Guide](development.md)** - Contributing to the project

---

## Troubleshooting

### **Common Issues**

**Connection refused:**

- Verify LDAP server is running and accessible
- Check firewall settings for LDAP port (389/636)
- Confirm SSL/TLS configuration

**Authentication failed:**

- Verify bind DN and password are correct
- Check user permissions in LDAP directory
- Ensure proper DN format (RFC 4514)

**Import errors:**

- Verify installation: `pip list | grep flext-ldap`
- Check Python version: `python --version` (requires 3.13+)
- Reinstall: `pip uninstall flext-ldap && pip install flext-ldap`

For more troubleshooting help, see [Troubleshooting Guide](troubleshooting.md).

---

**Next:** [Architecture Overview](architecture.md) →
