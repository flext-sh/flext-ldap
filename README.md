# FLEXT-LDAP

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**FLEXT-LDAP** is a universal, type-safe LDAP directory services library for the FLEXT ecosystem. It abstracts the complexities of different LDAP server implementations (OpenLDAP, Oracle OID/OUD, Active Directory) into a unified, railway-oriented API, enabling consistent directory operations across the enterprise.

Part of the [FLEXT](https://github.com/flext/flext) ecosystem.

## 🚀 Key Features

- **Universal LDAP Interface**: A single, consistent API for all LDAP operations, regardless of the underlying server software.
- **Server-Specific Adaptations**: Built-in support for OpenLDAP 2.x, Oracle Internet Directory (OID), Oracle Unified Directory (OUD), and Active Directory, with automatic handling of ACLs and schema quirks.
- **Entry Adaptation**: Seamless bidirectional conversion between `ldap3` entries and `flext-ldif` models.
- **Schema Discovery**: Automatic discovery and parsing of server schemas (objectClasses, attributeTypes).
- **ACL Management**: Unified management of Access Control Lists, abstracting differences like `olcAccess` (OpenLDAP) vs `orclaci` (OID).
- **Railway-Oriented**: All operations return `FlextResult[T]`, ensuring robust error handling without exception management.

## 📦 Installation

To install `flext-ldap`:

```bash
pip install flext-ldap
```

Or with Poetry:

```bash
poetry add flext-ldap
```

## 🛠️ Usage

### Connecting and Searching

Perform type-safe searches with automatic result handling.

```python
from flext_ldap import FlextLdap, FlextLdapModels

# 1. Initialize API
ldap = FlextLdap() 

# 2. execute Search
search_req = FlextLdapModels.SearchRequest(
    base_dn="dc=example,dc=com",
    filter_str="(objectClass=inetOrgPerson)",
    attributes=["cn", "mail", "uid"]
)

result = ldap.search_entries(search_req)

if result.is_success:
    entries = result.unwrap()
    for entry in entries:
        print(f"User: {entry.dn}, Mail: {entry.get_attribute('mail')}")
else:
    print(f"Search failed: {result.error}")
```

### Managing Entries

Add or modify entries using a consistent API.

```python
from flext_ldap import FlextLdap, FlextLdapModels

ldap = FlextLdap()

# Add a new entry
new_user = FlextLdapModels.Entry(
    dn="cn=jdoe,ou=users,dc=example,dc=com",
    attributes={
        "objectClass": ["top", "person", "inetOrgPerson"],
        "cn": ["John Doe"],
        "sn": ["Doe"],
        "uid": ["jdoe"],
        "mail": ["jdoe@example.com"]
    }
)

ldap.add_entry(new_user).map(lambda _: print("User created!"))
```

### Server-Specific Operations

Access server-specific capabilities when needed.

```python
from flext_ldap.servers import OpenLDAP2Operations
import ldap3

# Connect using standard ldap3 (or obtain connection from FlextLdap)
server = ldap3.Server('ldap://localhost')
conn = ldap3.Connection(server, auto_bind=True)

# Use OpenLDAP 2.x specific operations
ops = OpenLDAP2Operations()
schema_result = ops.discover_schema(conn)

if schema_result.is_success:
    print("Schema discovered successfully")
```

## 🏗️ Architecture

FLEXT-LDAP uses a layered architecture to isolate server differences:

- **API Layer**: `FlextLdap` provides the high-level facade.
- **Domain Layer**: Clean domain models for Entries, ACLs, and Schemas.
- **Adapter Layer**: Translates domain operations into specific `ldap3` calls.
- **Infrastructure Layer**: Specific implementations (`OpenLDAP2Operations`, `OracleOIDOperations`) handle the nuances of each directory server.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/development.md) for details on setting up your environment and adding support for new LDAP servers.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
