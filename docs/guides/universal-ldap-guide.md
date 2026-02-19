# Universal LDAP Operations Guide


<!-- TOC START -->
- Table of Contents
- Overview
- Key Features
  - Supported LDAP Servers
  - Universal Capabilities
- Server Operations
  - Creating Server Operations
  - Server-Specific Operations
- Universal API Methods
  - 1. Get Detected Server Type
  - 2. Get Server Capabilities
  - 3. Universal Search with Optimization
  - 4. Entry Normalization
  - 5. Entry Conversion Between Servers
  - 6. Server Type Detection
  - 7. Entry Validation
  - 8. Server-Specific Attributes
- Entry Conversion Examples
  - OpenLDAP 1.x → OpenLDAP 2.x Migration
  - Oracle OID → Oracle OUD Migration
- Migration Scenarios
  - Scenario 1: Multi-Server Environment
  - Scenario 2: Progressive Migration
- Best Practices
  - 1. Always Detect Server Type
  - 2. Validate After Conversion
  - 3. Use Server Capabilities
  - 4. Handle Quirks Gracefully
- Troubleshooting
  - Server Detection Issues
  - Conversion Failures
  - ACL Translation Issues
- Contributing
<!-- TOC END -->

**flext-ldap** now provides complete universal LDAP support,
allowing you to work with any LDAP server type (OpenLDAP 1.x, OpenLDAP 2.x, Oracle OID, Oracle OUD,
Active Directory) through a unified interface.

**Version**: 0.9.9 | **Test Coverage**: 35% | **Phase 2**: ✅ Complete
**Architecture**: Clean Architecture + DDD + Railway-oriented programming

## Table of Contents

- Overview
- Key Features
- Server Operations
- Universal API Methods
- Entry Conversion Examples
- Migration Scenarios

## Overview

The universal LDAP system consists of:

1. **Server Operations**: Server-specific implementations (OpenLDAP, Oracle, AD)
2. **Entry Adapter**: Universal entry conversion with quirks integration
3. **Factory Pattern**: Dynamic server operations instantiation
4. **Universal API**: High-level methods exposing universal capabilities

## Key Features

### Supported LDAP Servers

- ✅ **OpenLDAP 1.x** - Complete implementation with `access` ACLs
- ✅ **OpenLDAP 2.x** - Complete implementation with `olcAccess` ACLs
- ✅ **Oracle OID** - Complete implementation with `orclaci` ACLs
- ✅ **Oracle OUD** - Complete implementation with `ds-privilege-name` ACLs
- 🚧 **Active Directory** - Stub implementation (contributions welcome)
- ✅ **Generic** - Fallback for unknown servers

### Universal Capabilities

- 🔄 **Automatic Server Detection** - Detects server type from Root DSE
- 🔄 **Entry Conversion** - Convert entries between server formats
- 🔄 **ACL Translation** - Translate ACLs between formats
- 🔄 **Schema Discovery** - Server-specific schema handling
- 🔄 **Quirks Integration** - Server-specific behavior handling

## Server Operations

### Creating Server Operations

```python
from flext_ldap import ServerOperationsFactory
from flext_core import FlextBus
from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import t
from flext_core import u

# Method 1: Explicit server type
factory = ServerOperationsFactory()
ops_result = factory.create_from_server_type("openldap2")
if ops_result.is_success:
    ops = ops_result.unwrap()
    print(f"ACL format: {ops.get_acl_format()}")
    print(f"Schema DN: {ops.get_schema_dn()}")

# Method 2: Auto-detect from connection
def detect_and_create():
    # Assuming you have an ldap3 connection
    ops_result = factory.create_from_connection(connection)
    if ops_result.is_success:
        ops = ops_result.unwrap()
        print(f"Detected: {ops.server_type}")

# Method 3: Detect from entries
from flext_ldif import FlextLdifModels

entries: list[FlextLdifModels.Entry] = [...]  # Your entries
ops_result = factory.create_from_entries(entries)
```

### Server-Specific Operations

```python
from flext_ldap import OpenLDAP2Operations, OracleOUDOperations

# OpenLDAP 2.x operations
openldap = OpenLDAP2Operations()
print(f"Port: {openldap.get_default_port()}")
print(f"Supports TLS: {openldap.supports_start_tls()}")
print(f"ACL attribute: {openldap.get_acl_attribute_name()}")

# Oracle OUD operations
oud = OracleOUDOperations()
print(f"Privileges: {oud.get_oud_privileges()}")
print(f"Replication: {oud.get_replication_mechanism()}")
```

## Universal API Methods

### 1. Get Detected Server Type

```python
from flext_ldap import FlextLdap

api = FlextLdap()
api.connect()

# Get detected server type
server_type_result = api.get_detected_server_type()
if server_type_result.is_success:
    server_type = server_type_result.unwrap()
    print(f"Connected to: {server_type}")
    # Output: "Connected to: openldap2" or "oud", "oid", etc.
```

### 2. Get Server Capabilities

```python
# Get comprehensive server capabilities
caps_result = api.get_server_capabilities()
if caps_result.is_success:
    caps = caps_result.unwrap()

    print(f"Server type: {caps['server_type']}")
    print(f"ACL format: {caps['acl_format']}")
    print(f"ACL attribute: {caps['acl_attribute']}")
    print(f"Schema DN: {caps['schema_dn']}")
    print(f"Default port: {caps['default_port']}")
    print(f"SSL port: {caps['default_ssl_port']}")
    print(f"Supports START_TLS: {caps['supports_start_tls']}")
    print(f"BIND mechanisms: {caps['bind_mechanisms']}")
    print(f"Max page size: {caps['max_page_size']}")
    print(f"Paged results: {caps['supports_paged_results']}")
    print(f"VLV support: {caps['supports_vlv']}")
```

### 3. Universal Search with Optimization

```python
# Universal search with automatic server-specific optimization
result = api.search_universal(
    base_dn="ou=users,dc=example,dc=com",
    filter_str="(objectClass=person)",
    attributes=["uid", "cn", "mail", "sn"],
    use_paging=True  # Automatically uses server's best paging method
)

if result.is_success:
    entries = result.unwrap()
    print(f"Found {len(entries)} entries")
    for entry in entries:
        print(f"DN: {entry.dn}")
```

### 4. Entry Normalization

```python
from flext_ldif import FlextLdifModels

# Normalize entry for current server
entry: FlextLdifModels.Entry = ...  # Your entry
normalized_result = api.normalize_entry_for_server(entry)

if normalized_result.is_success:
    normalized_entry = normalized_result.unwrap()
    print("Entry normalized for current server")

# Normalize for specific target server
normalized_result = api.normalize_entry_for_server(
    entry,
    target_server_type="oud"
)
```

### 5. Entry Conversion Between Servers

```python
# Convert entry from OpenLDAP 1.x to OpenLDAP 2.x
openldap1_entry: FlextLdifModels.Entry = ...  # Entry from OpenLDAP 1.x

convert_result = api.convert_entry_between_servers(
    entry=openldap1_entry,
    source_server_type="openldap1",
    target_server_type="openldap2"
)

if convert_result.is_success:
    openldap2_entry = convert_result.unwrap()
    # Entry now has:
    # - olcAccess instead of access
    # - Converted objectClasses
    # - Adjusted ACL format
```

### 6. Server Type Detection

```python
# Detect server type from entry attributes
unknown_entry: FlextLdifModels.Entry = ...  # Entry from unknown source

detection_result = api.detect_entry_server_type(unknown_entry)
if detection_result.is_success:
    detected_type = detection_result.unwrap()
    print(f"Entry originated from: {detected_type}")
    # Output: "openldap2", "oud", "oid", etc.
```

### 7. Entry Validation

```python
# Validate entry for target server
entry: FlextLdifModels.Entry = ...

validation_result = api.validate_entry_for_server(entry, "oud")
if validation_result.is_success and validation_result.unwrap():
    print("Entry is compatible with Oracle OUD")
else:
    print(f"Validation failed: {validation_result.error}")
```

### 8. Server-Specific Attributes

```python
# Get server-specific attribute information
attrs_result = api.get_server_specific_attributes("oid")
if attrs_result.is_success:
    attrs = attrs_result.unwrap()
    print(f"Required attributes: {attrs.get('required_attributes', [])}")
    print(f"Optional attributes: {attrs.get('optional_attributes', [])}")
```

## Entry Conversion Examples

### OpenLDAP 1.x → OpenLDAP 2.x Migration

```python
from flext_ldap import FlextLdap
from flext_ldif import FlextLdif

def migrate_openldap1_to_openldap2():
    # Parse OpenLDAP 1.x LDIF file
    ldif = FlextLdif()
    parse_result = ldif.parse_file("openldap1_backup.ldif")

    if parse_result.is_failure:
        print(f"Parse failed: {parse_result.error}")
        return

    openldap1_entries = parse_result.unwrap()

    # Convert each entry to OpenLDAP 2.x format
    api = FlextLdap()
    openldap2_entries = []

    for entry in openldap1_entries:
        convert_result = api.convert_entry_between_servers(
            entry=entry,
            source_server_type="openldap1",
            target_server_type="openldap2"
        )

        if convert_result.is_success:
            openldap2_entries.append(convert_result.unwrap())
        else:
            print(f"Conversion failed for {entry.dn}: {convert_result.error}")

    # Write converted entries to new LDIF
    write_result = ldif.write_file(openldap2_entries, "openldap2_converted.ldif")
    if write_result.is_success:
        print(f"Successfully converted {len(openldap2_entries)} entries")
```

### Oracle OID → Oracle OUD Migration

```python
def migrate_oid_to_oud():
    api = FlextLdap()
    ldif = FlextLdif()

    # Load OID entries
    oid_entries = ldif.parse_file("oid_export.ldif").unwrap()

    # Convert to OUD format
    oud_entries = []
    for entry in oid_entries:
        # Convert orclaci ACLs to ds-privilege-name
        convert_result = api.convert_entry_between_servers(
            entry=entry,
            source_server_type="oid",
            target_server_type="oud"
        )

        if convert_result.is_success:
            oud_entry = convert_result.unwrap()

            # Validate for OUD
            validation_result = api.validate_entry_for_server(oud_entry, "oud")
            if validation_result.is_success and validation_result.unwrap():
                oud_entries.append(oud_entry)
            else:
                print(f"Validation failed: {validation_result.error}")

    # Export to OUD-compatible LDIF
    ldif.write_file(oud_entries, "oud_import.ldif")
```

## Migration Scenarios

### Scenario 1: Multi-Server Environment

```python
from flext_ldap import FlextLdap, ServerOperationsFactory

def sync_across_servers():
    """Sync entries across different LDAP server types."""

    # Source: OpenLDAP 2.x
    source_api = FlextLdap()
    source_api.connect()  # Connects to OpenLDAP 2.x

    # Target: Oracle OUD
    target_api = FlextLdap()
    target_api.connect()  # Connects to Oracle OUD

    # Search source
    search_result = source_api.search_universal(
        base_dn="ou=users,dc=company,dc=com",
        filter_str="(objectClass=inetOrgPerson)"
    )

    if search_result.is_success:
        source_entries = search_result.unwrap()

        for entry in source_entries:
            # Detect source server type
            source_type = source_api.get_detected_server_type().unwrap()

            # Detect target server type
            target_type = target_api.get_detected_server_type().unwrap()

            # Convert entry format
            convert_result = source_api.convert_entry_between_servers(
                entry=entry,
                source_server_type=source_type,
                target_server_type=target_type
            )

            if convert_result.is_success:
                converted_entry = convert_result.unwrap()

                # Add to target server
                target_api.add_entry(
                    str(converted_entry.dn),
                    converted_entry.attributes.attributes
                )
```

### Scenario 2: Progressive Migration

```python
def progressive_migration():
    """Gradually migrate from old to new LDAP server."""

    api = FlextLdap()

    # Phase 1: Analyze source entries
    source_entries = []  # Load from source

    server_types = {}
    for entry in source_entries:
        detection_result = api.detect_entry_server_type(entry)
        if detection_result.is_success:
            detected_type = detection_result.unwrap()
            server_types[detected_type] = server_types.get(detected_type, 0) + 1

    print(f"Entry distribution: {server_types}")

    # Phase 2: Convert in batches
    target_type = "oud"
    converted_batches = []

    batch_size = 100
    for i in range(0, len(source_entries), batch_size):
        batch = source_entries[i:i+batch_size]
        converted_batch = []

        for entry in batch:
            source_type = api.detect_entry_server_type(entry).unwrap()

            if source_type != target_type:
                convert_result = api.convert_entry_between_servers(
                    entry=entry,
                    source_server_type=source_type,
                    target_server_type=target_type
                )

                if convert_result.is_success:
                    converted_batch.append(convert_result.unwrap())
            else:
                converted_batch.append(entry)

        converted_batches.append(converted_batch)
        print(f"Converted batch {i//batch_size + 1}")

    # Phase 3: Validate all entries
    for batch in converted_batches:
        for entry in batch:
            validation_result = api.validate_entry_for_server(entry, target_type)
            if validation_result.is_failure or not validation_result.unwrap():
                print(f"Validation failed for {entry.dn}")
```

## Best Practices

### 1. Always Detect Server Type

```python
# Good: Detect before operations
server_type_result = api.get_detected_server_type()
if server_type_result.is_success:
    server_type = server_type_result.unwrap()
    # Use server_type for operations
```

### 2. Validate After Conversion

```python
# Good: Validate converted entries
convert_result = api.convert_entry_between_servers(...)
if convert_result.is_success:
    entry = convert_result.unwrap()

    validation_result = api.validate_entry_for_server(entry, target_type)
    if validation_result.is_success and validation_result.unwrap():
        # Proceed with entry
        pass
```

### 3. Use Server Capabilities

```python
# Good: Check capabilities before operations
caps_result = api.get_server_capabilities()
if caps_result.is_success:
    caps = caps_result.unwrap()

    if caps['supports_paged_results']:
        # Use paged search
        api.search_universal(..., use_paging=True)
```

### 4. Handle Quirks Gracefully

```python
# Good: Use quirks system for server-specific behavior
from flext_ldap import FlextLdapEntryAdapter

adapter = FlextLdapEntryAdapter(server_type="oud")

# Adapter handles Oracle OUD quirks automatically
normalized = adapter.normalize_entry_for_server(entry, "oud")
```

## Troubleshooting

### Server Detection Issues

If server type is not detected:

```python
# Manual server type specification
from flext_ldap import ServerOperationsFactory

factory = ServerOperationsFactory()
ops_result = factory.create_from_server_type("openldap2")
```

### Conversion Failures

If conversion fails, check entry compatibility:

```python
# Validate source entry
validation_result = api.validate_entry_for_server(entry, source_type)
if validation_result.is_failure:
    print(f"Source entry invalid: {validation_result.error}")
```

### ACL Translation Issues

Different servers have different ACL formats. Check server capabilities:

```python
caps_result = api.get_server_capabilities()
if caps_result.is_success:
    caps = caps_result.unwrap()
    print(f"ACL format: {caps['acl_format']}")
    print(f"ACL attribute: {caps['acl_attribute']}")
```

## Contributing

To add support for additional LDAP servers:

1. Create new server operations class inheriting from `BaseServerOperations`
2. Implement all required methods (connection, schema, ACL, entry, search)
3. Add server-specific quirks to FlextLdif quirks system
4. Register in `ServerOperationsFactory`
5. Add tests and documentation

See `src/flext_ldap/servers/ad_operations.py` for stub template.

---

**Copyright (c) 2025 FLEXT Team. All rights reserved.**
**SPDX-License-Identifier: MIT**
