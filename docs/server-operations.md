# Server-Specific Operations Guide

**Complete guide to using server-specific LDAP operations in flext-ldap**

This document provides detailed information about server-specific implementations, their capabilities, and usage patterns.

---

## 🎯 Overview

FLEXT-LDAP provides complete, server-specific implementations for major LDAP servers with automatic quirks handling and FlextLdif integration.

### **Available Implementations**

| Server               | Status      | ACL Attribute        | Schema DN                  | Lines | Version Support |
| -------------------- | ----------- | -------------------- | -------------------------- | ----- | --------------- |
| **OpenLDAP 2.x**     | 🟢 Complete | olcAccess            | cn=subschema               | 525   | 2.4+            |
| **OpenLDAP 1.x**     | 🟢 Complete | access               | cn=subschema               | 102   | 1.x (legacy)    |
| **Oracle OID**       | 🟢 Complete | orclaci              | cn=subschemasubentry       | 361   | 11g+            |
| **Oracle OUD**       | 🟢 Complete | ds-privilege-name    | cn=schema                  | 373   | 11g+            |
| **Active Directory** | 🟡 Stub     | nTSecurityDescriptor | cn=schema,cn=configuration | 250   | Future          |
| **Generic**          | 🟢 Complete | aci                  | cn=subschema               | 310   | RFC 4510        |

---

## 📦 Importing Server Operations

```python
# Import specific server operations
from flext_ldap.servers import (
    BaseServerOperations,          # Abstract base
    OpenLDAP2Operations,            # OpenLDAP 2.x
    OpenLDAP1Operations,            # OpenLDAP 1.x (legacy)
    OracleOIDOperations,            # Oracle Internet Directory
    OracleOUDOperations,            # Oracle Unified Directory
    ActiveDirectoryOperations,      # Active Directory (stub)
    GenericServerOperations,        # Generic fallback
)

# Import supporting components
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter
from flext_ldif import FlextLdifModels
```

---

## 🔧 OpenLDAP 2.x Operations

### **Features**

- **cn=config** dynamic configuration
- **olcAccess** ACL syntax
- Paged results and VLV support
- Full schema discovery
- START_TLS support

### **Basic Usage**

```python
from flext_ldap.servers import OpenLDAP2Operations
import ldap3

# Initialize operations
ops = OpenLDAP2Operations()

# Connection
connection = ldap3.Connection(
    ldap3.Server('ldap://openldap-server:389'),
    user='cn=admin,dc=example,dc=com',
    password='password',
    auto_bind=True
)

# Schema discovery
schema_result = ops.discover_schema(connection)
if schema_result.is_success:
    schema = schema_result.unwrap()
    print(f"Object classes: {len(schema['object_classes'])}")
    print(f"Attribute types: {len(schema['attribute_types'])}")
    print(f"Syntaxes: {len(schema['syntaxes'])}")
    print(f"Matching rules: {len(schema['matching_rules'])}")
```

### **ACL Operations**

```python
# Get ACLs from cn=config entry
acl_result = ops.get_acls(
    connection,
    dn='olcDatabase={1}mdb,cn=config'
)

if acl_result.is_success:
    acls = acl_result.unwrap()
    for acl in acls:
        print(f"ACL: {acl}")

# Set ACLs
new_acls = [
    {"raw": "{0}to * by dn=\"cn=admin,dc=example,dc=com\" write"},
    {"raw": "{1}to * by self write by anonymous auth"}
]

set_result = ops.set_acls(
    connection,
    dn='olcDatabase={1}mdb,cn=config',
    acls=new_acls
)
```

### **Entry Operations**

```python
from flext_ldif import FlextLdifModels

# Create entry
entry = FlextLdifModels.Entry(
    dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
    attributes=FlextLdifModels.Attributes(attributes={
        "objectClass": ["person", "organizationalPerson"],
        "cn": ["test"],
        "sn": ["Test User"],
        "mail": ["test@example.com"]
    })
)

# Add entry
add_result = ops.add_entry(connection, entry)
if add_result.is_success:
    print("Entry added successfully")

# Modify entry
modify_result = ops.modify_entry(
    connection,
    dn="cn=test,dc=example,dc=com",
    modifications={"mail": ["newemail@example.com"]}
)

# Delete entry
delete_result = ops.delete_entry(
    connection,
    dn="cn=test,dc=example,dc=com"
)
```

### **Paged Search**

```python
# Large result set with paging
search_result = ops.search_with_paging(
    connection,
    base_dn="dc=example,dc=com",
    search_filter="(objectClass=person)",
    attributes=["cn", "mail", "sn"],
    page_size=100
)

if search_result.is_success:
    entries = search_result.unwrap()
    print(f"Found {len(entries)} entries")

    for entry in entries:
        print(f"DN: {entry.dn}")
        print(f"Attributes: {entry.attributes}")
```

---

## 🔧 OpenLDAP 1.x Operations

### **Features**

- **slapd.conf** static configuration
- **access** ACL syntax (legacy)
- Inherits most functionality from OpenLDAP 2.x
- Limited VLV support

### **Key Differences**

```python
from flext_ldap.servers import OpenLDAP1Operations

ops = OpenLDAP1Operations()

# ACL attribute is different
acl_attr = ops.get_acl_attribute_name()  # Returns "access"

# ACL format is legacy syntax
# access to <what> by <who> <access>
legacy_acl = {
    "raw": "access to * by dn=\"cn=admin,dc=example,dc=com\" write"
}
```

**Note**: OpenLDAP 1.x extends OpenLDAP 2.x operations, only overriding ACL-related methods for the legacy syntax.

---

## 🔧 Oracle OID Operations

### **Features**

- **orclaci** ACL syntax
- **cn=subschemasubentry** schema location
- Oracle-specific object classes (orclUserV2, orclContainer)
- VLV support
- Full replication support

### **Basic Usage**

```python
from flext_ldap.servers import OracleOIDOperations

ops = OracleOIDOperations()

# Connection to Oracle OID
connection = ldap3.Connection(
    ldap3.Server('ldap://oid-server:389'),
    user='cn=invalid_user',
    password='password',
    auto_bind=True
)

# Schema discovery (Oracle-specific)
schema_result = ops.discover_schema(connection)
if schema_result.is_success:
    schema = schema_result.unwrap()
    print(f"Server type: {schema['server_type']}")  # "oid"
```

### **Oracle OID ACLs**

```python
# Get orclaci ACLs
acl_result = ops.get_acls(
    connection,
    dn="dc=example,dc=com"
)

if acl_result.is_success:
    acls = acl_result.unwrap()
    for acl in acls:
        print(f"OID ACL: {acl['raw']}")

# Set orclaci ACLs
oid_acls = [
    {"raw": "access to entry by group=\"cn=admins,dc=example,dc=com\" (browse,add,delete)"}
]

set_result = ops.set_acls(connection, "dc=example,dc=com", oid_acls)
```

### **Oracle-Specific Features**

```python
# Get OID defaults
port = ops.get_default_port()  # 389 (LDAP) or 636 (LDAPS)
schema_dn = ops.get_schema_dn()  # "cn=subschemasubentry"
supports_vlv = ops.supports_vlv()  # True

# Bind mechanisms
mechanisms = ops.get_bind_mechanisms()
# Returns: ["SIMPLE", "SASL/EXTERNAL", "SASL/DIGEST-MD5"]
```

---

## 🔧 Oracle OUD Operations

### **Features**

- **ds-privilege-name** ACL attribute
- **cn=schema** schema location
- Based on 389 Directory Server
- Extended SASL support (GSSAPI, PLAIN)
- Full enterprise features

### **Basic Usage**

```python
from flext_ldap.servers import OracleOUDOperations

ops = OracleOUDOperations()

# Connection to Oracle OUD
connection = ldap3.Connection(
    ldap3.Server('ldap://oud-server:389'),
    user='cn=Directory Manager',
    password='password',
    auto_bind=True
)

# Schema discovery
schema_result = ops.discover_schema(connection)
if schema_result.is_success:
    schema = schema_result.unwrap()
    print(f"Server type: {schema['server_type']}")  # "oud"
```

### **ds-privilege-name ACLs**

```python
# Get ds-privilege-name ACLs
acl_result = ops.get_acls(
    connection,
    dn="dc=example,dc=com"
)

# Set ds-privilege-name ACLs
oud_acls = [
    {"raw": "bypass-acl"},
    {"raw": "config-read"},
    {"raw": "password-reset"}
]

set_result = ops.set_acls(connection, "cn=admin,dc=example,dc=com", oud_acls)
```

### **OUD-Specific Features**

```python
# Extended SASL mechanisms
mechanisms = ops.get_bind_mechanisms()
# Returns: ["SIMPLE", "SASL/EXTERNAL", "SASL/DIGEST-MD5", "SASL/GSSAPI", "SASL/PLAIN"]

# Schema location
schema_dn = ops.get_schema_dn()  # "cn=schema"

# VLV and paged results
supports_vlv = ops.supports_vlv()  # True
supports_paging = ops.supports_paged_results()  # True
```

---

## 🔧 Active Directory Operations (Stub)

### **Status**

Currently implemented as a stub with `NotImplementedError` for most operations. Provides the interface for future implementation.

### **Planned Features**

- **nTSecurityDescriptor** ACLs (Windows Security Descriptor format)
- **cn=schema,cn=configuration** schema location
- GUID-based DNs
- Global Catalog support
- SASL/GSSAPI authentication

### **Current Usage**

```python
from flext_ldap.servers import ActiveDirectoryOperations

ops = ActiveDirectoryOperations()

# Available methods (return NotImplementedError)
try:
    schema_result = ops.discover_schema(connection)
except Exception as e:
    print(f"AD not implemented: {e}")
    # Output: "Active Directory schema discovery not yet implemented..."

# Basic info available
port = ops.get_default_port()  # 389 (LDAP) or 636 (LDAPS)
acl_attr = ops.get_acl_attribute_name()  # "nTSecurityDescriptor"
schema_dn = ops.get_schema_dn()  # "cn=schema,cn=configuration"
```

### **Contributing AD Implementation**

If you want to contribute Active Directory support:

1. Implement schema discovery with AD schema format
2. Implement nTSecurityDescriptor parsing and formatting
3. Handle GUID-based DNs
4. Implement AD-specific entry normalization
5. Add Global Catalog support

See `src/flext_ldap/servers/ad_operations.py` for stub methods.

---

## 🔧 Generic Server Operations

### **Purpose**

RFC-compliant fallback for unknown or unimplemented LDAP servers. Provides basic operations that should work with any RFC 4510-compliant server.

### **Features**

- **aci** attribute (generic format)
- **cn=subschema** schema location (RFC 4512)
- Basic LDAP operations
- Conservative defaults
- Paged search support

### **Usage**

```python
from flext_ldap.servers import GenericServerOperations

ops = GenericServerOperations()

# Works with any RFC-compliant LDAP server
connection = ldap3.Connection(
    ldap3.Server('ldap://unknown-ldap-server:389'),
    user='cn=admin,dc=example,dc=com',
    password='password',
    auto_bind=True
)

# Basic schema discovery
schema_result = ops.discover_schema(connection)
if schema_result.is_success:
    schema = schema_result.unwrap()
    print(f"Server type: {schema['server_type']}")  # "generic"

# Basic entry operations (should work on any server)
entry = FlextLdifModels.Entry(...)
add_result = ops.add_entry(connection, entry)

# Paged search (if supported by server)
search_result = ops.search_with_paging(
    connection,
    base_dn="dc=example,dc=com",
    search_filter="(objectClass=*)",
    page_size=100
)
```

### **Limitations**

- ACL operations return minimal support
- Schema discovery provides basic info only
- No server-specific optimizations
- Conservative capability detection

---

## 🔄 Entry Adapter Integration

All server operations integrate with the Entry Adapter for ldap3 ↔ FlextLdif conversion:

```python
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.servers import OpenLDAP2Operations

adapter = FlextLdapEntryAdapter()
ops = OpenLDAP2Operations()

# Search and convert to FlextLdif
connection.search(base_dn, search_filter, attributes=attributes)
for ldap3_entry in connection.entries:
    # Convert ldap3 entry to FlextLdif
    ldif_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
    if ldif_result.is_success:
        ldif_entry = ldif_result.unwrap()

        # Process with FlextLdif models
        print(f"DN: {ldif_entry.dn.value}")
        print(f"Attributes: {ldif_entry.attributes.attributes}")

# Create FlextLdif entry and convert to ldap3
ldif_entry = FlextLdifModels.Entry(...)
attrs_result = adapter.ldif_entry_to_ldap3_attributes(ldif_entry)
if attrs_result.is_success:
    attributes = attrs_result.unwrap()
    # Use with server operations
    ops.add_entry(connection, ldif_entry)
```

---

## 🔍 Quirks Detection

Server type detection using FlextLdif quirks:

```python
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter

quirks = FlextLdapQuirksAdapter()

# Detect server type from entries
entries = [...]  # List of FlextLdifModels.Entry
server_type_result = quirks.detect_server_type_from_entries(entries)

if server_type_result.is_success:
    server_type = server_type_result.unwrap()
    print(f"Detected server: {server_type}")

    # Get server-specific information
    acl_attr_result = quirks.get_acl_attribute_name(server_type)
    schema_dn_result = quirks.get_schema_subentry(server_type)
    acl_format_result = quirks.get_acl_format(server_type)

    print(f"ACL attribute: {acl_attr_result.unwrap()}")
    print(f"Schema DN: {schema_dn_result.unwrap()}")
    print(f"ACL format: {acl_format_result.unwrap()}")

# Automatic server operations selection
if server_type == "openldap2":
    ops = OpenLDAP2Operations()
elif server_type == "oid":
    ops = OracleOIDOperations()
elif server_type == "oud":
    ops = OracleOUDOperations()
else:
    ops = GenericServerOperations()
```

---

## 📊 Server Comparison

### **Connection Features**

| Feature       | OpenLDAP 2.x | OpenLDAP 1.x | Oracle OID | Oracle OUD | AD      | Generic |
| ------------- | ------------ | ------------ | ---------- | ---------- | ------- | ------- |
| Default Port  | 389/636      | 389/636      | 389/636    | 389/636    | 389/636 | 389/636 |
| START_TLS     | ✅ Yes       | ✅ Yes       | ✅ Yes     | ✅ Yes     | ❌ No   | ✅ Yes  |
| SIMPLE Auth   | ✅ Yes       | ✅ Yes       | ✅ Yes     | ✅ Yes     | ✅ Yes  | ✅ Yes  |
| SASL/EXTERNAL | ✅ Yes       | ❌ No        | ✅ Yes     | ✅ Yes     | ❌ No   | ❌ No   |
| SASL/GSSAPI   | ❌ No        | ❌ No        | ❌ No      | ✅ Yes     | ✅ Yes  | ❌ No   |

### **Schema Operations**

| Feature         | OpenLDAP 2.x | OpenLDAP 1.x | Oracle OID           | Oracle OUD | AD                  | Generic      |
| --------------- | ------------ | ------------ | -------------------- | ---------- | ------------------- | ------------ |
| Schema DN       | cn=subschema | cn=subschema | cn=subschemasubentry | cn=schema  | cn=schema,cn=config | cn=subschema |
| Object Classes  | ✅ Full      | ✅ Full      | ✅ Full              | ✅ Full    | 🟡 Stub             | ⚠️ Basic     |
| Attribute Types | ✅ Full      | ✅ Full      | ✅ Full              | ✅ Full    | 🟡 Stub             | ⚠️ Basic     |
| Syntaxes        | ✅ Yes       | ✅ Yes       | ❌ No                | ✅ Yes     | 🟡 Stub             | ❌ No        |
| Matching Rules  | ✅ Yes       | ❌ No        | ❌ No                | ❌ No      | 🟡 Stub             | ❌ No        |

### **ACL Features**

| Feature       | OpenLDAP 2.x | OpenLDAP 1.x | Oracle OID | Oracle OUD        | AD                   | Generic    |
| ------------- | ------------ | ------------ | ---------- | ----------------- | -------------------- | ---------- |
| ACL Attribute | olcAccess    | access       | orclaci    | ds-privilege-name | nTSecurityDescriptor | aci        |
| Get ACLs      | ✅ Full      | ✅ Full      | ✅ Full    | ✅ Full           | 🟡 Stub              | ⚠️ Limited |
| Set ACLs      | ✅ Full      | ✅ Full      | ✅ Full    | ✅ Full           | 🟡 Stub              | ❌ No      |
| Parse ACL     | ✅ Full      | ✅ Full      | ⚠️ Basic   | ⚠️ Basic          | 🟡 Stub              | ⚠️ Basic   |
| Format ACL    | ✅ Full      | ✅ Full      | ⚠️ Basic   | ⚠️ Basic          | 🟡 Stub              | ⚠️ Basic   |

### **Search Features**

| Feature       | OpenLDAP 2.x | OpenLDAP 1.x | Oracle OID | Oracle OUD | AD     | Generic |
| ------------- | ------------ | ------------ | ---------- | ---------- | ------ | ------- |
| Paged Results | ✅ Yes       | ✅ Yes       | ✅ Yes     | ✅ Yes     | ✅ Yes | ✅ Yes  |
| VLV           | ✅ Yes       | ⚠️ Limited   | ✅ Yes     | ✅ Yes     | ❌ No  | ❌ No   |
| Max Page Size | 1000         | 1000         | 5000       | 1000       | 1000   | 1000    |

---

## 🎯 Best Practices

### **1. Use Server Detection**

Always detect the server type for optimal operations:

```python
quirks = FlextLdapQuirksAdapter()
server_type_result = quirks.detect_server_type_from_entries(entries)

if server_type_result.is_success:
    server_type = server_type_result.unwrap()
    # Select appropriate operations class
```

### **2. Handle Errors Explicitly**

All operations return `FlextResult` - always check for failures:

```python
result = ops.add_entry(connection, entry)
if result.is_failure:
    print(f"Operation failed: {result.error}")
    # Handle error appropriately
else:
    print("Operation succeeded")
```

### **3. Use Entry Adapter**

Always use the Entry Adapter for conversions:

```python
adapter = FlextLdapEntryAdapter()

# ldap3 → FlextLdif
ldif_result = adapter.ldap3_to_ldif_entry(ldap3_entry)

# FlextLdif → ldap3
attrs_result = adapter.ldif_entry_to_ldap3_attributes(ldif_entry)
```

### **4. Server-Specific Normalization**

Each server may require specific entry normalization:

```python
norm_result = ops.normalize_entry(entry)
if norm_result.is_success:
    normalized_entry = norm_result.unwrap()
    # Use normalized entry
```

### **5. Connection Management**

Proper connection lifecycle:

```python
# Create connection
connection = ldap3.Connection(...)
connection.bind()

try:
    # Operations
    result = ops.add_entry(connection, entry)
finally:
    # Always unbind
    connection.unbind()
```

---

## 🔧 Troubleshooting

### **Common Issues**

**Schema Discovery Fails**:

```python
# Check if server is properly connected
if not connection.bound:
    print("Connection not bound - check credentials")

# Check schema DN
schema_dn = ops.get_schema_dn()
print(f"Trying schema DN: {schema_dn}")
```

**ACL Operations Not Working**:

```python
# Verify ACL attribute for server
acl_attr = ops.get_acl_attribute_name()
print(f"Using ACL attribute: {acl_attr}")

# Check permissions
# ACL operations typically require admin privileges
```

**Paged Search Timing Out**:

```python
# Reduce page size
result = ops.search_with_paging(
    connection,
    base_dn,
    search_filter,
    page_size=50  # Smaller page size
)
```

**Entry Addition Fails**:

```python
# Check entry normalization
norm_result = ops.normalize_entry(entry)
if norm_result.is_failure:
    print(f"Normalization failed: {norm_result.error}")

# Verify required object classes and attributes
```

---

## 📚 Additional Resources

- **[Architecture Guide](architecture.md)** - Universal LDAP architecture
- **[API Reference](api-reference.md)** - Complete API documentation
- **[Integration Guide](integration.md)** - FlextLdif integration patterns
- **[ACL Management](ACL_MANAGEMENT.md)** - Server-specific ACL handling
- **[Troubleshooting](troubleshooting.md)** - Common issues and solutions

---

**Last Updated**: 2025-01-08
**Version**: 0.9.9
**Status**: Production-ready with complete server implementations
