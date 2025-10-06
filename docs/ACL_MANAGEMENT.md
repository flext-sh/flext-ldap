# ACL Management System

## Overview

The FLEXT LDAP ACL Management system provides comprehensive ACL (Access Control List) management capabilities across different LDAP server types including:

- **OpenLDAP** - `access to` syntax
- **Oracle Directory** - `orclaci` format
- **389 DS / Apache DS** - ACI (Access Control Instruction) format
- **Active Directory** - SDDL (future support)

## Architecture

The ACL system follows Clean Architecture principles with:

1. **Unified ACL Model** - Intermediate representation for all ACL formats
2. **Format-specific Parsers** - Parse ACLs from different LDAP servers
3. **Bidirectional Converters** - Convert between any supported formats
4. **AclManager** - Orchestration layer for ACL operations

## Quick Start

### Basic Usage

```python
from flext_ldap import FlextLDAP
from flext_ldap.acl import FlextLDAPConstants

# Initialize API
api = FlextLDAP()

# Parse an OpenLDAP ACL
openldap_acl = "access to attrs=userPassword by self write"
result = api.parse_acl(openldap_acl, FlextLDAPConstants.AclFormat.OPENLDAP)

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
    source_format=FlextLDAPConstants.AclFormat.OPENLDAP,
    target_format=FlextLDAPConstants.AclFormat.ORACLE
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
    source_format=FlextLDAPConstants.AclFormat.OPENLDAP,
    target_format=FlextLDAPConstants.AclFormat.ACI
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
'(target="ldap:///ou=data,dc=example,dc=com")(version 3.0; acl "Admin Access"; allow (read,write) groupdn="ldap:///cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com";)'
```

## Creating Custom ACLs

### Using the Unified Model

```python
from flext_ldap.acl import FlextLDAPModels, FlextLDAPConstants

# Create ACL components
target_result = FlextLDAPModels.AclTarget.create(
    target_type=FlextLDAPConstants.TargetType.ATTRIBUTES,
    attributes=["userPassword"],
    dn_pattern="ou=users,dc=example,dc=com"
)

subject_result = FlextLDAPModels.AclSubject.create(
    subject_type=FlextLDAPConstants.SubjectType.SELF,
    identifier="self"
)

permissions_result = FlextLDAPModels.AclPermissions.create(
    permissions=[FlextLDAPConstants.Permission.WRITE],
    grant_type="allow"
)

# Create unified ACL
unified_result = FlextLDAPModels.UnifiedAcl.create(
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
    FlextLDAPConstants.AclFormat.OPENLDAP
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
        FlextLDAPConstants.AclFormat.ORACLE,
        FlextLDAPConstants.AclFormat.OPENLDAP
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
        FlextLDAPConstants.AclFormat.OPENLDAP,
        FlextLDAPConstants.AclFormat.ACI
    )

    if result.is_success:
        conv = result.unwrap()
        print(f"389 DS ACI: {conv.converted_acl}")
```

## Advanced Features

### ACL with Conditions

```python
# Create ACL with time and IP restrictions
unified_result = FlextLDAPModels.UnifiedAcl.create(
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
FlextLDAPConstants.Permission.READ      # Read access
FlextLDAPConstants.Permission.WRITE     # Write access
FlextLDAPConstants.Permission.ADD       # Add entries
FlextLDAPConstants.Permission.DELETE    # Delete entries
FlextLDAPConstants.Permission.SEARCH    # Search directory
FlextLDAPConstants.Permission.COMPARE   # Compare attributes
FlextLDAPConstants.Permission.AUTH      # Authenticate
```

### Subject Types

```python
# Different subject types
FlextLDAPConstants.SubjectType.SELF         # Self (user modifying own entry)
FlextLDAPConstants.SubjectType.USER         # Specific user
FlextLDAPConstants.SubjectType.GROUP        # Group membership
FlextLDAPConstants.SubjectType.DN           # Distinguished Name
FlextLDAPConstants.SubjectType.ANONYMOUS    # Anonymous users
FlextLDAPConstants.SubjectType.AUTHENTICATED # Authenticated users
FlextLDAPConstants.SubjectType.ANYONE       # Anyone
```

## Error Handling

```python
# All operations return FlextResult for safe error handling
result = api.parse_acl(acl_string, format_type)

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
from flext_ldap import FlextLDAP
from flext_ldap.acl import FlextLDAPConstants

api = FlextLDAP()

# Read Oracle ACLs from OUD
oracle_acls = read_oracle_acls()  # Your existing function

# Convert each ACL
converted_acls = []
for acl in oracle_acls:
    result = api.convert_acl(
        acl,
        FlextLDAPConstants.AclFormat.ORACLE,
        FlextLDAPConstants.AclFormat.OPENLDAP
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
2. **Test conversions** with sample ACLs before bulk migration
3. **Review conversion warnings** to understand potential feature loss
4. **Use unified model** for complex ACL manipulation
5. **Batch operations** for better performance with multiple ACLs

## API Reference

### FlextLDAP ACL Methods

- `parse_acl(acl_string, format_type)` - Parse ACL to unified model
- `convert_acl(acl_string, source_format, target_format)` - Convert ACL between formats
- `batch_convert_acls(acl_list, source_format, target_format)` - Batch conversion
- `validate_acl_syntax(acl_string, format_type)` - Validate ACL syntax

### FlextLDAPAclManager Methods

- `parse_acl()` - Parse ACL to unified format
- `convert_acl()` - Convert between formats
- `batch_convert()` - Batch conversion
- `validate_acl_syntax()` - Syntax validation
- `create_unified_acl()` - Create from components

## See Also

- [FLEXT LDAP API Documentation](README.md)
- [client-a OUD Migration Guide](../client-a-oud-mig/README.md)
- [Clean Architecture Patterns](ARCHITECTURE.md)
