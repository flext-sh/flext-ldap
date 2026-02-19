# ACL Management System

<!-- TOC START -->

- [Table of Contents](#table-of-contents)
- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
  - [Basic Usage](#basic-usage)
  - [Converting ACL Formats](#converting-acl-formats)
  - [Batch Conversion](#batch-conversion)
- [ACL Format Examples](#acl-format-examples)
  - [OpenLDAP Format](#openldap-format)
  - [Oracle Directory Format](#oracle-directory-format)
  - [ACI Format (389 DS / Apache DS)](#aci-format-389-ds-apache-ds)
- [Creating Custom ACLs](#creating-custom-acls)
  - [Using the Unified Model](#using-the-unified-model)
- [ACL Validation](#acl-validation)
- [Migration Scenarios](#migration-scenarios)
  - [Oracle to OpenLDAP Migration](#oracle-to-openldap-migration)
  - [OpenLDAP to 389 DS Migration](#openldap-to-389-ds-migration)
- [Advanced Features](#advanced-features)
  - [ACL with Conditions](#acl-with-conditions)
  - [Permission Mapping](#permission-mapping)
  - [Subject Types](#subject-types)
- [Error Handling](#error-handling)
- [Integration with client-a OUD Migration](#integration-with-client-a-oud-migration)
- [Best Practices](#best-practices)
- [API Reference](#api-reference)
  - [FlextLdap ACL Methods](#flextldap-acl-methods)
  - [FlextLdapAclManager Methods](#flextldapaclmanager-methods)
- [See Also](#see-also)

<!-- TOC END -->

## Table of Contents

- ACL Management System
  - Overview
  - Architecture
  - Quick Start
    - Basic Usage
- Initialize API
- Parse an OpenLDAP ACL
  - Converting ACL Formats
- Convert OpenLDAP to Oracle format
  - Batch Conversion
- Convert multiple ACLs at once
  - ACL Format Examples
    - OpenLDAP Format
- Simple attribute ACL
- DN-based ACL
- Multiple attributes
  - Oracle Directory Format
- Attribute ACL
- Entry-level ACL
- Multiple attributes
  - ACI Format (389 DS / Apache DS)
- Simple ACI
- Deny ACL
- Group-based ACI
  - Creating Custom ACLs
    - Using the Unified Model
- Create ACL components
- Create unified ACL
- Convert to any format
  - ACL Validation
- Validate ACL syntax
  - Migration Scenarios
    - Oracle to OpenLDAP Migration
- Parse Oracle ACLs from existing directory
- Convert to OpenLDAP format
  - OpenLDAP to 389 DS Migration
- Parse OpenLDAP slapd.conf ACLs
- Convert to ACI format for 389 DS
  - Advanced Features
    - ACL with Conditions
- Create ACL with time and IP restrictions
  - Permission Mapping
- Standard permissions across formats
  - Subject Types
- Different subject types
  - Error Handling
- All operations return FlextResult for safe error handling
  - Integration with client-a OUD Migration
- Example: Convert Oracle OUD ACLs to OpenLDAP format
- Read Oracle ACLs from OUD
- Convert each ACL
- Write to OpenLDAP configuration
  - Best Practices
  - API Reference
    - FlextLdap ACL Methods
    - FlextLdapAclManager Methods
  - See Also

## Overview

The FLEXT LDAP ACL Management system provides comprehensive ACL (Access Control List) management capabilities across different LDAP server types including:

- **OpenLDAP** - `access to` syntax
- **Oracle Directory** - `orclaci` format
- **389 DS / Apache DS** - ACI (Access Control Instruction) format
- **Active Directory** - SDDL (future support)

## Architecture

The ACL system follows Clean Architecture principles with:

1. **Unified ACL Model** - Intermediate representation for all ACL formats
1. **Format-specific Parsers** - Parse ACLs from different LDAP servers
1. **Bidirectional Converters** - Convert between any supported formats
1. **AclManager** - Orchestration layer for ACL operations

## Quick Start

### Basic Usage

```python
from flext_ldap import FlextLdap
from flext_ldap.acl import FlextLdapConstants

# Initialize API
api = FlextLdap()

# Parse an OpenLDAP ACL
openldap_acl = "access to attrs=userPassword by self write"
result = api.parse(openldap_acl, FlextLdapConstants.AclFormat.OPENLDAP)

if result.is_success:
    unified_acl = result.unwrap()
    print(f"Parsed ACL: {unified_acl.name}")
```

### Converting ACL Formats

```python
# Convert OpenLDAP to Oracle format
openldap_acl = "access to attrs=mail by users read"

conversion_result = api.convert_acl(
    openldap_acl,
    source_format=FlextLdapConstants.AclFormat.OPENLDAP,
    target_format=FlextLdapConstants.AclFormat.ORACLE
)

if conversion_result.is_success:
    conv = conversion_result.unwrap()
    print(f"Oracle ACL: {conv.converted_acl}")
    # Output: access to attr=(mail) by group="*" (read)
```

### Batch Conversion

```python
# Convert multiple ACLs at once
acl_list = [
    "access to attrs=cn by self write",
    "access to attrs=mail by users read",
    "access to attrs=telephoneNumber by self write"
]

batch_result = api.batch_convert_acls(
    acl_list,
    source_format=FlextLdapConstants.AclFormat.OPENLDAP,
    target_format=FlextLdapConstants.AclFormat.ACI
)

if batch_result.is_success:
    for conv in batch_result.unwrap():
        print(f"Converted: {conv.converted_acl}")
```

## ACL Format Examples

### OpenLDAP Format

```python
# Simple attribute ACL
"access to attrs=userPassword by self write"

# DN-based ACL
'access to dn.exact="ou=users,dc=example,dc=com" by users read'

# Multiple attributes
"access to attrs=cn,sn,mail by authenticated read"
```

### Oracle Directory Format

```python
# Attribute ACL
'access to attr=(userPassword) by group="cn=REDACTED_LDAP_BIND_PASSWORDs" (write)'

# Entry-level ACL
'access to entry by user="cn=REDACTED_LDAP_BIND_PASSWORD" (read,write,delete)'

# Multiple attributes
'access to attr=(cn, sn, mail) by group="cn=users" (read)'
```

### ACI Format (389 DS / Apache DS)

```python
# Simple ACI
'(target="ldap:///ou=users,dc=example,dc=com")(version 3.0; acl "User Read"; allow (read) userdn="ldap:///anyone";)'

# Deny ACL
'(target="ldap:///dc=example,dc=com")(version 3.0; acl "Deny Delete"; deny (delete) userdn="ldap:///anyone";)'

# Group-based ACI
'(target="ldap:///ou=data,dc=example,dc=com")(version 3.0; acl "Admin Access"; allow (read,
    write) groupdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com";)'
```

## Creating Custom ACLs

### Using the Unified Model

```python
from flext_ldap.acl import FlextLdapModels, FlextLdapConstants

# Create ACL components
target_result = FlextLdapModels.AclTarget.create(
    target_type=FlextLdapConstants.TargetType.ATTRIBUTES,
    attributes=["userPassword"],
    dn_pattern="ou=users,dc=example,dc=com"
)

subject_result = FlextLdapModels.AclSubject.create(
    subject_type=FlextLdapConstants.SubjectType.SELF,
    identifier="self"
)

permissions_result = FlextLdapModels.AclPermissions.create(
    permissions=[FlextLdapConstants.Permission.WRITE],
    grant_type="allow"
)

# Create unified ACL
unified_result = FlextLdapModels.Acl.create(
    name="Allow self password write",
    target=target_result.unwrap(),
    subject=subject_result.unwrap(),
    permissions=permissions_result.unwrap(),
    priority=100
)

# Convert to any format
api.convert_to_openldap(unified_result.unwrap())
api.convert_to_oracle(unified_result.unwrap())
api.convert_to_aci(unified_result.unwrap())
```

## ACL Validation

```python
# Validate ACL syntax
acl_string = "access to attrs=mail by self write"

validation_result = api.validate_acl_syntax(
    acl_string,
    FlextLdapConstants.AclFormat.OPENLDAP
)

if validation_result.is_success:
    print("ACL syntax is valid")
else:
    print(f"Invalid ACL: {validation_result.error}")
```

## Migration Scenarios

### Oracle to OpenLDAP Migration

```python
# Parse Oracle ACLs from existing directory
oracle_acls = [
    'access to attr=(cn, sn) by group="cn=users" (read)',
    'access to attr=(userPassword) by group="cn=REDACTED_LDAP_BIND_PASSWORDs" (write)',
    'access to entry by user="cn=REDACTED_LDAP_BIND_PASSWORD" (read,write,delete)'
]

# Convert to OpenLDAP format
for oracle_acl in oracle_acls:
    result = api.convert_acl(
        oracle_acl,
        FlextLdapConstants.AclFormat.ORACLE,
        FlextLdapConstants.AclFormat.OPENLDAP
    )

    if result.is_success:
        conv = result.unwrap()
        print(f"OpenLDAP ACL: {conv.converted_acl}")
        if conv.warnings:
            print(f"Warnings: {conv.warnings}")
```

### OpenLDAP to 389 DS Migration

```python
# Parse OpenLDAP slapd.conf ACLs
openldap_acls = [
    "access to attrs=userPassword by self write by anonymous auth",
    'access to dn.exact="ou=users,dc=example,dc=com" by users read'
]

# Convert to ACI format for 389 DS
for acl in openldap_acls:
    result = api.convert_acl(
        acl,
        FlextLdapConstants.AclFormat.OPENLDAP,
        FlextLdapConstants.AclFormat.ACI
    )

    if result.is_success:
        conv = result.unwrap()
        print(f"389 DS ACI: {conv.converted_acl}")
```

## Advanced Features

### ACL with Conditions

```python
# Create ACL with time and IP restrictions
unified_result = FlextLdapModels.Acl.create(
    name="Time and IP restricted access",
    target=target,
    subject=subject,
    permissions=permissions,
    conditions={
        "time": "09:00-17:00",
        "ip": "192.168.1.0/24",
        "day_of_week": "Mon-Fri"
    }
)
```

### Permission Mapping

```python
# Standard permissions across formats
FlextLdapConstants.Permission.READ      # Read access
FlextLdapConstants.Permission.WRITE     # Write access
FlextLdapConstants.Permission.ADD       # Add entries
FlextLdapConstants.Permission.DELETE    # Delete entries
FlextLdapConstants.Permission.SEARCH    # Search directory
FlextLdapConstants.Permission.COMPARE   # Compare attributes
FlextLdapConstants.Permission.AUTH      # Authenticate
```

### Subject Types

```python
# Different subject types
FlextLdapConstants.SubjectType.SELF         # Self (user modifying own entry)
FlextLdapConstants.SubjectType.USER         # Specific user
FlextLdapConstants.SubjectType.GROUP        # Group membership
FlextLdapConstants.SubjectType.DN           # Distinguished Name
FlextLdapConstants.SubjectType.ANONYMOUS    # Anonymous users
FlextLdapConstants.SubjectType.AUTHENTICATED # Authenticated users
FlextLdapConstants.SubjectType.ANYONE       # Anyone
```

## Error Handling

```python
# All operations return FlextResult for safe error handling
result = api.parse(acl_string, format_type)

if result.is_failure:
    print(f"Error: {result.error}")
    # Handle error appropriately
else:
    unified_acl = result.unwrap()
    # Process successful result
```

## Integration with client-a OUD Migration

```python
# Example: Convert Oracle OUD ACLs to OpenLDAP format
from flext_ldap import FlextLdap
from flext_ldap.acl import FlextLdapConstants

api = FlextLdap()

# Read Oracle ACLs from OUD
oracle_acls = read_oracle_acls()  # Your existing function

# Convert each ACL
converted_acls = []
for acl in oracle_acls:
    result = api.convert_acl(
        acl,
        FlextLdapConstants.AclFormat.ORACLE,
        FlextLdapConstants.AclFormat.OPENLDAP
    )

    if result.is_success:
        converted_acls.append(result.unwrap().converted_acl)
    else:
        print(f"Conversion failed for: {acl} - {result.error}")

# Write to OpenLDAP configuration
write_openldap_acls(converted_acls)
```

## Best Practices

1. **Always validate ACL syntax** before applying to production directory
1. **Test conversions** with sample ACLs before bulk migration
1. **Review conversion warnings** to understand potential feature loss
1. **Use unified model** for complex ACL manipulation
1. **Batch operations** for better performance with multiple ACLs

## API Reference

### FlextLdap ACL Methods

- `parse(acl_string, format_type)` - Parse ACL to unified model
- `convert_acl(acl_string, source_format, target_format)` - Convert ACL between formats
- `batch_convert_acls(acl_list, source_format, target_format)` - Batch conversion
- `validate_acl_syntax(acl_string, format_type)` - Validate ACL syntax

### FlextLdapAclManager Methods

- `parse()` - Parse ACL to unified format
- `convert_acl()` - Convert between formats
- `batch_convert()` - Batch conversion
- `validate_acl_syntax()` - Syntax validation
- `create_unified_acl()` - Create from components

## See Also

- FLEXT LDAP API Documentation
- client-a OUD Migration Guide
- Clean Architecture Patterns
