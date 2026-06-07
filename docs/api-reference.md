# API Reference

<!-- TOC START -->
- [Table of Contents](#table-of-contents)
- [🚀 Main API](#main-api)
  - [`flext_ldap.api.ldap`](#flextldapapildap)
- [🏗️ FlextLdapClients](#flextldapclients)
  - [`search_entries(request: SearchRequest) -> p.Result[List[LdapEntry]]`](#searchentriesrequest-searchrequest-presultlistldapentry)
  - [`authenticate_user(username: str, password: str) -> p.Result[FlextLdapUser]`](#authenticateuserusername-str-password-str-presultflextldapuser)
  - [`create_user(request: CreateUserRequest) -> p.Result[FlextLdapUser]`](#createuserrequest-createuserrequest-presultflextldapuser)
  - [`test_connection() -> p.Result[str]`](#testconnection-presultstr)
- [📊 Domain Entities](#domain-entities)
  - [FlextLdapEntities](#flextldapentities)
- [🎯 Value Objects](#value-objects)
  - [FlextLdapModels.Values](#flextldapmodelsvalues)
- [⚙️ Configuration](#configuration)
  - [FlextLdapSettings](#flextldapsettings)
- [🔧 Utilities](#utilities)
  - [FlextLdapTypeGuards](#flextldaptypeguards)
  - [FlextLdapConstants](#flextldapconstants)
- [🚨 Exceptions](#exceptions)
  - [e](#e)
- [🔄 r Usage](#r-usage)
  - [Success Handling](#success-handling)
  - [Error Handling](#error-handling)
  - [Chaining Operations](#chaining-operations)
- [🔄 Universal LDAP Interface](#universal-ldap-interface)
  - [FlextLdapEntryAdapter](#flextldapentryadapter)
  - [FlextLdapServersAdapter](#flextldapserversadapter)
- [🏗️ Server Operations](#server-operations)
  - [BaseServerOperations](#baseserveroperations)
  - [Server-Specific Implementations](#server-specific-implementations)
- [📝 Type Annotations](#type-annotations)
- [🔗 Complete Usage Example](#complete-usage-example)
- [Related Documentation](#related-documentation)
<!-- TOC END -->

## Table of Contents

- API Reference
  - 🚀 Main API
    - `flext_ldap.api.ldap`
  - 🏗️ FlextLdapClients - [`search_entries(request: SearchRequest) -> p.Result[List[LdapEntry]]`](#search_entriesrequest-searchrequest---flextresultlistldapentry) - [`authenticate_user(username: str, password: str) -> p.Result[FlextLdapUser]`](#authenticate_userusername-str-password-str---flextresultflextldapuser) - [`create_user(request: CreateUserRequest) -> p.Result[FlextLdapUser]`](#create_userrequest-createuserrequest---flextresultflextldapuser) - [`test_connection() -> p.Result[str]`](#test_connection---flextresultstr)
  - 📊 Domain Entities
    - FlextLdapEntities
      - SearchRequest
      - CreateUserRequest
      - FlextLdapUser
      - FlextLdapGroup
  - 🎯 Value Objects
    - FlextLdapModels.Values
      - DN
      - LdapFilter
- Create filters
- Combine filters - LdapScope
  - ⚙️ Configuration
    - FlextLdapSettings
  - 🔧 Utilities
    - FlextLdapTypeGuards
      - `is_valid_dn(value: str) -> bool`
      - `is_ldap_entry(obj) -> bool`
    - FlextLdapConstants
  - 🚨 Exceptions
    - e
      - ConnectionError
      - AuthenticationError
      - SearchError
  - 🔄 r Usage
    - Success Handling
- Check success
- Alternative: direct access (raises if failure)
  - Error Handling
  - Chaining Operations
  - 🔄 Universal LDAP Interface
    - FlextLdapEntryAdapter
      - [`ldap3_to_ldif_entry(ldap3_entry) -> p.Result[FlextLdifModels.Entry]`](#ldap3_to_ldif_entryldap3_entry---flextresultflextldifmodelsentry)
- Search with ldap3 - [`ldap3_entries_to_ldif_entries(ldap3_entries) -> p.Result[List[FlextLdifModels.Entry]]`](#ldap3_entries_to_ldif_entriesldap3_entries---flextresultlistflextldifmodelsentry) - [`ldif_entry_to_ldap3_attributes(ldif_entry) -> p.Result[Mapping[str, t.List]]`](#ldif_entry_to_ldap3_attributesldif_entry---flextresultdictstr-flexttypeslist)
- Create ldif entry
- Convert to ldap3 attributes - [`convert_ldif_file_to_entries(ldif_file_path) -> p.Result[List[FlextLdifModels.Entry]]`](#convert_ldif_file_to_entriesldif_file_path---flextresultlistflextldifmodelsentry) - [`write_entries_to_ldif_file(entries, output_path) -> p.Result[bool]`](#write_entries_to_ldif_fileentries-output_path---flextresultbool)
  - FlextLdapServersAdapter
    - [`detect_server_type_from_entries(entries) -> p.Result[str]`](#detect_server_type_from_entriesentries---flextresultstr)
- Detect from entries - [`get_acl_attribute_name(server_type=None) -> p.Result[str]`](#get_acl_attribute_nameserver_typenone---flextresultstr) - [`get_acl_format(server_type=None) -> p.Result[str]`](#get_acl_formatserver_typenone---flextresultstr) - [`get_schema_subentry(server_type=None) -> p.Result[str]`](#get_schema_subentryserver_typenone---flextresultstr) - [`get_max_page_size(server_type=None) -> p.Result[int]`](#get_max_page_sizeserver_typenone---flextresultint) - [`normalize_entry_for_server(entry, server_type=None) -> p.Result[FlextLdifModels.Entry]`](#normalize_entry_for_serverentry-server_typenone---flextresultflextldifmodelsentry)
  - 🏗️ Server Operations
    - BaseServerOperations
      - Connection Operations
        - `get_default_port(use_ssl=False) -> int`
        - `supports_start_tls() -> bool`
        - `get_bind_mechanisms() -> t.StringList`
      - Schema Operations
        - `get_schema_dn() -> str`
        - [`discover_schema(connection) -> p.Result[m.Dict]`](#discover_schemaconnection---flextresultflexttypesdict)
        - [`parse_object_class(object_class_def) -> p.Result[m.Dict]`](#parse_object_classobject_class_def---flextresultflexttypesdict)
        - [`parse_attribute_type(attribute_def) -> p.Result[m.Dict]`](#parse_attribute_typeattribute_def---flextresultflexttypesdict)
      - ACL Operations
        - `get_acl_attribute_name() -> str`
        - `get_acl_format() -> str`
        - [`get_acls(connection, dn) -> p.Result[Sequence[m.Dict]]`](#get_aclsconnection-dn---flextresultlistflexttypesdict)
- Get ACLs from cn=settings entry - [`set_acls(connection, dn, acls) -> p.Result[bool]`](#set_aclsconnection-dn-acls---flextresultbool) - [`parse(acl_string) -> p.Result[m.Dict]`](#parseacl_string---flextresultflexttypesdict) - [`format_acl(acl_dict) -> p.Result[str]`](#format_aclacl_dict---flextresultstr) - Entry Operations - [`add_entry(connection, entry) -> p.Result[bool]`](#add_entryconnection-entry---flextresultbool) - [`modify_entry(connection, dn, modifications) -> p.Result[bool]`](#modify_entryconnection-dn-modifications---flextresultbool) - [`delete_entry(connection, dn) -> p.Result[bool]`](#delete_entryconnection-dn---flextresultbool) - [`normalize_entry(entry) -> p.Result[FlextLdifModels.Entry]`](#normalize_entryentry---flextresultflextldifmodelsentry) - Search Operations - `get_max_page_size() -> int` - `supports_paged_results() -> bool` - `supports_vlv() -> bool` - [`search_with_paging(connection, base_dn, search_filter, attributes=None, page_size=100) -> p.Result[Sequence[FlextLdifModels.Entry]]`](#search_with_pagingconnection-base_dn-search_filter-attributesnone-page_size100---flextresultlistflextldifmodelsentry)
  - Server-Specific Implementations
    - OpenLDAP2Operations
- Schema discovery
- ACL management - OracleOIDOperations - OracleOUDOperations - GenericServerOperations
  - 📝 Type Annotations
- Server operations with ldif integration
  - 🔗 Complete Usage Example

**Complete API documentation for flext-ldap**

This document provides comprehensive API reference for all public interfaces in flext-ldap.

**Version**: 0.9.9 | **Test Coverage**: 35% | **Phase 2**: ✅ Complete
**Architecture**: Clean Architecture + DDD + Railway-oriented programming

______________________________________________________________________

## 🚀 Main API

### `flext_ldap.api.ldap`

Default LDAP API instance (FlextLdapClients).

**Example:**

```python
from flext_ldap.api import ldap

api = ldap
```

______________________________________________________________________

## 🏗️ FlextLdapClients

Main API facade providing high-level LDAP operations.

### `search_entries(request: SearchRequest) -> p.Result[List[LdapEntry]]`

Search LDAP directory entries.

**Parameters:**

- `request`: SearchRequest t.JsonValue with search criteria

**Returns:** r containing list of matching entries

**Example:**

```python notest
search_request = FlextLdapEntities.SearchRequest(
    base_dn="dc=example,dc=com",
    filter_str="(objectClass=person)",
    scope="subtree",
    attributes=["uid", "cn", "mail"],
)

result = api.search_entries(search_request)
if result.success:
    entries = result.unwrap()
```

### `authenticate_user(username: str, password: str) -> p.Result[FlextLdapUser]`

Authenticate user credentials against LDAP directory.

**Parameters:**

- `username` (str): User identifier
- `password` (str): User password

**Returns:** r containing authenticated user t.JsonValue

**Example:**

```python notest
result = api.authenticate_user("john.doe", "password123")
if result.success:
    user = result.unwrap()
    print(f"Authenticated: {user.cn}")
```

### `create_user(request: CreateUserRequest) -> p.Result[FlextLdapUser]`

Create a new user in LDAP directory.

**Parameters:**

- `request`: CreateUserRequest with user details

**Returns:** r containing created user t.JsonValue

**Example:**

```python notest
user_request = FlextLdapEntities.CreateUserRequest(
    dn="cn=jane.doe,ou=users,dc=example,dc=com",
    uid="jane.doe",
    cn="Jane Doe",
    sn="Doe",
    mail="jane.doe@example.com",
)

result = api.create_user(user_request)
```

### `test_connection() -> p.Result[str]`

Test LDAP server connectivity.

**Returns:** r with connection status message

**Example:**

```python notest
result = api.test_connection()
if result.success:
    print("Connection successful")
```

______________________________________________________________________

## 📊 Domain Entities

### FlextLdapEntities

Container for domain entities and request objects.

#### SearchRequest

Search criteria for LDAP operations.

**Attributes:**

- `base_dn` (str): Base distinguished name for search
- `filter_str` (str): LDAP search filter
- `scope` (str): Search scope ("base", "onelevel", "subtree")
- `attributes` (t.StringList): Attributes to retrieve
- `size_limit` (int, optional): Maximum results to return
- `time_limit` (int, optional): Search timeout in seconds

#### CreateUserRequest

User creation request data.

**Attributes:**

- `dn` (str): Distinguished name for new user
- `uid` (str): User identifier
- `cn` (str): Common name
- `sn` (str): Surname
- `mail` (str, optional): Email address
- `object_classes` (t.StringList, optional): LDAP object classes

#### FlextLdapUser

LDAP user entity.

**Attributes:**

- `dn` (str): Distinguished name
- `uid` (str): User identifier
- `cn` (str): Common name
- `sn` (str): Surname
- `given_name` (str, optional): First name
- `mail` (str, optional): Email address
- `member_of` (t.StringList, optional): Group memberships

**Methods:**

- `is_valid() -> bool`: Validate user data
- `get_display_name() -> str`: Get display name

#### FlextLdapGroup

LDAP group entity.

**Attributes:**

- `dn` (str): Distinguished name
- `cn` (str): Common name
- `members` (t.StringList): Member distinguished names
- `description` (str, optional): Group description

**Methods:**

- `add_member(member_dn: str) -> None`: Add group member
- `remove_member(member_dn: str) -> None`: Remove group member

______________________________________________________________________

## 🎯 Value Objects

### FlextLdapModels.Values

Container for value objects.

#### DN

RFC 4514 compliant distinguished name.

**Attributes:**

- `value` (str): DN string value

**Methods:**

- `rdn() -> str`: Get relative distinguished name
- `parent_dn() -> str`: Get parent DN

**Example:**

```python notest
dn = FlextLdapModels.Values.DN("cn=user,ou=people,dc=example,dc=com")
print(dn.rdn)  # "cn=user"
print(dn.parent_dn)  # "ou=people,dc=example,dc=com"
```

#### LdapFilter

LDAP search filter with validation.

**Attributes:**

- `expression` (str): Filter expression

**Class Methods:**

- `equals(attribute: str, value: str) -> LdapFilter`: Create equality filter
- `object_class(object_class: str) -> LdapFilter`: Create objectClass filter
- `and_filters(*filters) -> LdapFilter`: Combine filters with AND
- `or_filters(*filters) -> LdapFilter`: Combine filters with OR

**Example:**

```python notest
# Create filters
user_filter = FlextLdapModels.Values.LdapFilter.equals("uid", "john.doe")
person_filter = FlextLdapModels.Values.LdapFilter.object_class("person")

# Combine filters
combined = FlextLdapModels.Values.LdapFilter.and_filters(user_filter, person_filter)
```

#### LdapScope

Search scope enumeration.

**Values:**

- `BASE`: Search base t.JsonValue only
- `ONELEVEL`: Search immediate children
- `SUBTREE`: Search entire subtree

______________________________________________________________________

## ⚙️ Configuration

### FlextLdapSettings

LDAP connection configuration.

**Attributes:**

- `host` (str): LDAP server hostname
- `port` (int): LDAP server port (default: 389)
- `use_ssl` (bool): Use SSL connection (default: False)
- `bind_dn` (str): Bind distinguished name
- `bind_password` (str): Bind password
- `base_dn` (str): Base distinguished name
- `timeout` (int): Connection timeout in seconds (default: 30)
- `pool_size` (int): Connection pool size (default: 5)

**Example:**

```python notest
from Flext_ldap import FlextLdapSettings, set_flext_ldap.settings

settings = FlextLdapSettings(
    host="ldap.example.com",
    port=636,
    use_ssl=True,
    bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    bind_password="REDACTED_LDAP_BIND_PASSWORD-password",
    base_dn="dc=example,dc=com"
)

set_flext_ldap.settings(settings)
```

______________________________________________________________________

## 🔧 Utilities

### FlextLdapTypeGuards

Type guard functions for runtime type checking.

#### `is_valid_dn(value: str) -> bool`

Check if string is a valid distinguished name.

**Example:**

```python notest
from flext_ldap import FlextLdapTypeGuards

if FlextLdapTypeGuards.is_valid_dn("cn=user,dc=example,dc=com"):
    print("Valid DN")
```

#### `is_ldap_entry(obj) -> bool`

Check if t.JsonValue is a valid LDAP entry.

### FlextLdapConstants

LDAP protocol constants.

**Attributes:**

- `DEFAULT_PORT`: Default LDAP port (389)
- `DEFAULT_SSL_PORT`: Default LDAPS port (636)
- `SCOPE_BASE`: Base search scope
- `SCOPE_ONELEVEL`: One-level search scope
- `SCOPE_SUBTREE`: Subtree search scope

______________________________________________________________________

## 🚨 Exceptions

### e

LDAP-specific exception classes.

#### ConnectionError

Connection-related errors.

**Attributes:**

- `message` (str): Error description
- `server` (str, optional): LDAP server address

#### AuthenticationError

Authentication failures.

**Attributes:**

- `message` (str): Error description
- `username` (str, optional): Failed username

#### SearchError

Search operation errors.

**Attributes:**

- `message` (str): Error description
- `base_dn` (str, optional): Search base DN
- `filter_str` (str, optional): Search filter

**Example:**

```python notest
from flext_ldap import e

try:
    result = api.search_entries(request)
    if result.failure:
        # Handle r error
        print(f"Search failed: {result.error}")
except e.ConnectionError as e:
    print(f"Connection error: {e.message}")
```

______________________________________________________________________

## 🔄 r Usage

All API methods return `r[T]` for consistent error handling.

### Success Handling

```python notest
result = api.search_entries(request)

# Check success
if result.success:
    data = result.unwrap()

# Alternative: direct access (raises if failure)
try:
    data = result.unwrap()
except rError:
    print("Operation failed")
```

### Error Handling

```python notest
result = api.authenticate_user(username, password)

if result.failure:
    error_message = result.error
    print(f"Authentication failed: {error_message}")
```

### Chaining Operations

```python notest
search_result = api.search_entries(request)
if search_result.success:
    entries = search_result.unwrap()
    # Process entries...
else:
    # Handle search failure
    return r.fail(f"Search failed: {search_result.error}")
```

______________________________________________________________________

## 🔄 Universal LDAP Interface

### FlextLdapEntryAdapter

Bidirectional converter between ldap3 entries and ldif entries.

**Import:**

```python
from flext_ldap import FlextLdapEntryAdapter
```

#### `ldap3_to_ldif_entry(ldap3_entry) -> p.Result[FlextLdifModels.Entry]`

Convert ldap3.Entry to ldif entry.

**Parameters:**

- `ldap3_entry`: ldap3.Entry t.JsonValue from search results

**Returns:** r containing FlextLdifModels.Entry

**Example:**

```python notest
from flext_ldap import FlextLdapEntryAdapter
import ldap3

adapter = FlextLdapEntryAdapter()

# Search with ldap3
connection.search("dc=example,dc=com", "(objectClass=person)")

for ldap3_entry in connection.entries:
    # Convert to ldif
    result = adapter.ldap3_to_ldif_entry(ldap3_entry)
    if result.success:
        ldif_entry = result.unwrap()
        print(f"DN: {ldif_entry.dn}")
```

#### `ldap3_entries_to_ldif_entries(ldap3_entries) -> p.Result[List[FlextLdifModels.Entry]]`

Batch convert multiple ldap3 entries to ldif entries.

**Parameters:**

- `ldap3_entries`: List of ldap3.Entry objects

**Returns:** r containing list of FlextLdifModels.Entry

#### `ldif_entry_to_ldap3_attributes(ldif_entry) -> p.Result[Mapping[str, t.List]]`

Convert ldif entry to ldap3 attributes dictionary.

**Parameters:**

- `ldif_entry`: FlextLdifModels.Entry to convert

**Returns:** r containing attributes t.JsonMapping for ldap3 operations

**Example:**

```python notest
from flext_ldif import FlextLdifModels
from flext_ldap import FlextLdapEntryAdapter

adapter = FlextLdapEntryAdapter()

# Create ldif entry
ldif_entry = FlextLdifModels.Entry(
    dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
    attributes=FlextLdifModels.Attributes(
        attributes={
            "objectClass": ["person", "organizationalPerson"],
            "cn": ["test"],
            "sn": ["Test User"],
        }
    ),
)

# Convert to ldap3 attributes
result = adapter.ldif_entry_to_ldap3_attributes(ldif_entry)
if result.success:
    attributes = result.unwrap()
    connection.add(str(ldif_entry.dn), attributes=attributes)
```

#### `convert_ldif_file_to_entries(ldif_file_path) -> p.Result[List[FlextLdifModels.Entry]]`

Load and convert LDIF file to ldif entries.

**Parameters:**

- `ldif_file_path` (str): Path to LDIF file

**Returns:** r containing list of entries

#### `write_entries_to_ldif_file(entries, output_path) -> p.Result[bool]`

Write ldif entries to LDIF file.

**Parameters:**

- `entries`: List of FlextLdifModels.Entry
- `output_path` (str): Output file path

**Returns:** r indicating success

______________________________________________________________________

### FlextLdapServersAdapter

Server detection and servers system integration using ldif.

**Import:**

```python notest
from flext_ldap import FlextLdapServersAdapter
```

#### `detect_server_type_from_entries(entries) -> p.Result[str]`

Detect LDAP server type from entry analysis.

**Parameters:**

- `entries`: List of FlextLdifModels.Entry objects

**Returns:** r containing server type string

**Server Types:**

- `"openldap2"` - OpenLDAP 2.x (cn=settings)
- `"openldap1"` - OpenLDAP 1.x (legacy)
- `"oid"` - Oracle Internet Directory
- `"oud"` - Oracle Unified Directory
- `"ad"` - Active Directory
- `"generic"` - Generic LDAP server

**Example:**

```python notest
from flext_ldap import FlextLdapServersAdapter
from flext_ldap import OpenLDAP2Operations, OracleOIDOperations, OracleOUDOperations

servers = FlextLdapServersAdapter()

# Detect from entries
entries = [...]  # ldif entries from search
result = servers.detect_server_type_from_entries(entries)

if result.success:
    server_type = result.unwrap()

    # Select appropriate server operations
    if server_type == "openldap2":
        ops = OpenLDAP2Operations()
    elif server_type == "oid":
        ops = OracleOIDOperations()
    elif server_type == "oud":
        ops = OracleOUDOperations()
```

#### `get_acl_attribute_name(server_type=None) -> p.Result[str]`

Get server-specific ACL attribute name.

**Parameters:**

- `server_type` (str, optional): Server type (uses detected if None)

**Returns:** r containing ACL attribute name

**ACL Attributes:**

- OpenLDAP 2.x: `"olcAccess"`
- OpenLDAP 1.x: `"access"`
- Oracle OID: `"orclaci"`
- Oracle OUD: `"ds-privilege-name"`
- Active Directory: `"nTSecurityDescriptor"`
- Generic: `"aci"`

#### `get_acl_format(server_type=None) -> p.Result[str]`

Get server-specific ACL format identifier.

#### `get_schema_subentry(server_type=None) -> p.Result[str]`

Get server-specific schema DN.

**Schema DNs:**

- OpenLDAP: `"cn=subschema"`
- Oracle OID: `"cn=subschemasubentry"`
- Oracle OUD: `"cn=schema"`
- Active Directory: `"cn=schema,cn=configuration"`

#### `get_max_page_size(server_type=None) -> p.Result[int]`

Get server-specific maximum page size for paged searches.

#### `normalize_entry_for_server(entry, server_type=None) -> p.Result[FlextLdifModels.Entry]`

Normalize entry for server-specific requirements.

______________________________________________________________________

## 🏗️ Server Operations

### BaseServerOperations

Abstract base class defining complete server operations interface.

**Import:**

```python notest
from flext_ldap import BaseServerOperations
```

**Server Implementations:**

- `OpenLDAP2Operations` - OpenLDAP 2.x (cn=settings, olcAccess ACLs)
- `OpenLDAP1Operations` - OpenLDAP 1.x (slapd.conf, access ACLs)
- `OracleOIDOperations` - Oracle Internet Directory (orclaci ACLs)
- `OracleOUDOperations` - Oracle Unified Directory (ds-privilege-name ACLs)
- `ActiveDirectoryOperations` - Active Directory (stub implementation)
- `GenericServerOperations` - Generic RFC-compliant LDAP server

#### Connection Operations

##### `get_default_port(use_ssl=False) -> int`

Get default port for server type.

**Returns:**

- 389 for standard LDAP
- 636 for LDAPS

##### `supports_start_tls() -> bool`

Check if server supports START_TLS.

##### `get_bind_mechanisms() -> t.StringList`

Get supported BIND mechanisms (SIMPLE, SASL/EXTERNAL, etc.).

#### Schema Operations

##### `get_schema_dn() -> str`

Get schema discovery DN for server type.

##### `discover_schema(connection) -> p.Result[m.Dict]`

Discover schema from server.

**Returns:** r containing schema data:

- `object_classes`: List of objectClass definitions
- `attribute_types`: List of attributeType definitions
- `syntaxes`: List of LDAP syntax definitions
- `server_type`: Detected server type

**Example:**

```python notest
from flext_ldap import OpenLDAP2Operations
import ldap3

ops = OpenLDAP2Operations()

connection = ldap3.Connection(
    ldap3.Server("ldap://server:389"),
    user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    password="password",
    auto_bind=True,
)

schema_result = ops.discover_schema(connection)
if schema_result.success:
    schema = schema_result.unwrap()
    print(f"Object classes: {len(schema['object_classes'])}")
    print(f"Attribute types: {len(schema['attribute_types'])}")
```

##### `parse_object_class(object_class_def) -> p.Result[m.Dict]`

Parse objectClass definition string.

##### `parse_attribute_type(attribute_def) -> p.Result[m.Dict]`

Parse attributeType definition string.

#### ACL Operations

##### `get_acl_attribute_name() -> str`

Get ACL attribute name for server type.

##### `get_acl_format() -> str`

Get ACL format identifier.

##### `get_acls(connection, dn) -> p.Result[Sequence[m.Dict]]`

Retrieve ACLs from entry.

**Example:**

```python notest
from flext_ldap import OpenLDAP2Operations

ops = OpenLDAP2Operations()

# Get ACLs from cn=settings entry
result = ops.get_acls(connection, dn="olcDatabase={1}mdb,cn=settings")

if result.success:
    acls = result.unwrap()
    for acl in acls:
        print(f"ACL: {acl.get('raw')}")
```

##### `set_acls(connection, dn, acls) -> p.Result[bool]`

Set ACLs on entry.

**Example:**

```python notest
new_acls = [
    {"raw": '{0}to * by dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" write'},
    {"raw": "{1}to * by self write by anonymous auth"},
]

result = ops.set_acls(connection, dn, acls=new_acls)
```

##### `parse(acl_string) -> p.Result[m.Dict]`

Parse server-specific ACL string to dictionary.

##### `format_acl(acl_dict) -> p.Result[str]`

Format ACL dictionary to server-specific string.

#### Entry Operations

##### `add_entry(connection, entry) -> p.Result[bool]`

Add ldif entry to directory.

**Example:**

```python notest
from flext_ldif import FlextLdifModels
from flext_ldap import OpenLDAP2Operations

ops = OpenLDAP2Operations()

entry = FlextLdifModels.Entry(
    dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
    attributes=FlextLdifModels.Attributes(
        attributes={
            "objectClass": ["person", "organizationalPerson"],
            "cn": ["test"],
            "sn": ["Test User"],
            "mail": ["test@example.com"],
        }
    ),
)

result = ops.add_entry(connection, entry)
if result.success:
    print("Entry added successfully")
```

##### `modify_entry(connection, dn, modifications) -> p.Result[bool]`

Modify entry attributes.

**Example:**

```python notest
modifications = {"mail": ["newemail@example.com"], "telephoneNumber": ["+1-555-0100"]}

result = ops.modify_entry(
    connection, dn="cn=test,dc=example,dc=com", modifications=modifications
)
```

##### `delete_entry(connection, dn) -> p.Result[bool]`

Delete entry from directory.

##### `normalize_entry(entry) -> p.Result[FlextLdifModels.Entry]`

Normalize entry for server-specific requirements.

#### Search Operations

##### `get_max_page_size() -> int`

Get maximum page size for paged searches.

##### `supports_paged_results() -> bool`

Check if server supports paged results control.

##### `supports_vlv() -> bool`

Check if server supports Virtual List View (VLV).

##### `search_with_paging(connection, base_dn, search_filter, attributes=None, page_size=100) -> p.Result[Sequence[FlextLdifModels.Entry]]`

Execute paged search with automatic pagination.

**Example:**

```python notest
from flext_ldap import OpenLDAP2Operations

ops = OpenLDAP2Operations()

result = ops.search_with_paging(
    connection,
    base_dn="ou=users,dc=example,dc=com",
    search_filter="(objectClass=person)",
    attributes=["uid", "cn", "mail"],
    page_size=100,
)

if result.success:
    entries = result.unwrap()
    print(f"Found {len(entries)} entries")
    for entry in entries:
        print(f"DN: {entry.dn}")
```

______________________________________________________________________

### Server-Specific Implementations

#### OpenLDAP2Operations

Complete implementation for OpenLDAP 2.x (cn=settings style).

**Import:**

```python notest
from flext_ldap import OpenLDAP2Operations
```

**Features:**

- olcAccess ACL format
- cn=subschema schema discovery
- Paged results support
- VLV support (limited)
- START_TLS support

**Example:**

```python notest
from flext_ldap import OpenLDAP2Operations
import ldap3

ops = OpenLDAP2Operations()

connection = ldap3.Connection(
    ldap3.Server("ldap://openldap-server:389"),
    user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    password="password",
    auto_bind=True,
)

# Schema discovery
schema = ops.discover_schema(connection)

# ACL management
acls = ops.get_acls(connection, "olcDatabase={1}mdb,cn=settings")
```

#### OracleOIDOperations

Complete implementation for Oracle Internet Directory.

**Import:**

```python notest
from flext_ldap import OracleOIDOperations
```

**Features:**

- orclaci ACL format
- cn=subschemasubentry schema discovery
- Oracle-specific object classes (orclUserV2, orclContainer)
- VLV support
- Paged results support

#### OracleOUDOperations

Complete implementation for Oracle Unified Directory.

**Import:**

```python notest
from flext_ldap import OracleOUDOperations
```

**Features:**

- ds-privilege-name ACL format
- cn=schema schema discovery
- 389 Directory Server base with Oracle extensions
- Full VLV support
- Advanced paging

#### GenericServerOperations

RFC-compliant fallback for unknown servers.

**Import:**

```python notest
from flext_ldap import GenericServerOperations
```

**Features:**

- aci ACL attribute (generic)
- cn=subschema schema discovery (RFC 4512)
- Basic paged results
- Standard LDAP operations

______________________________________________________________________

## 📝 Type Annotations

All public APIs include comprehensive type annotations for IDE support and static analysis:

```python notest
def search_entries(
    self, request: FlextLdapEntities.SearchRequest
) -> p.Result[List[FlextLdapEntities.LdapEntry]]:
    """Search LDAP entries with full type safety."""


# Server operations with ldif integration
def add_entry(self, connection, entry: FlextLdifModels.Entry) -> p.Result[bool]:
    """Add entry with type safety."""
```

Use mypy or similar tools for static type checking:

```bash
mypy --strict your_code.py
```

______________________________________________________________________

## 🔗 Complete Usage Example

```python notest
import ldap3
from flext_ldap import FlextLdapEntryAdapter
from flext_ldap import FlextLdapServersAdapter
from flext_ldap import OpenLDAP2Operations, OracleOIDOperations, OracleOUDOperations
from flext_ldif import FlextLdifModels


def universal_ldap_example():
    """Complete example using universal LDAP interface."""

    # Setup connection
    connection = ldap3.Connection(
        ldap3.Server("ldap://server:389"),
        user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password",
        auto_bind=True,
    )

    # Initialize adapters
    adapter = FlextLdapEntryAdapter()
    servers = FlextLdapServersAdapter()

    # Search for entries
    connection.search("dc=example,dc=com", "(objectClass=*)", attributes=["*"])

    # Convert to ldif
    entries = []
    for ldap3_entry in connection.entries:
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        if result.success:
            entries.append(result.unwrap())

    # Detect server type
    server_type_result = servers.detect_server_type_from_entries(entries)
    if server_type_result.success:
        server_type = server_type_result.unwrap()
        print(f"Detected server: {server_type}")

        # Select appropriate operations
        if server_type == "openldap2":
            ops = OpenLDAP2Operations()
        elif server_type == "oid":
            ops = OracleOIDOperations()
        elif server_type == "oud":
            ops = OracleOUDOperations()
        else:
            from flext_ldap import GenericServerOperations

            ops = GenericServerOperations()

        # Discover schema
        schema_result = ops.discover_schema(connection)
        if schema_result.success:
            schema = schema_result.unwrap()
            print(f"Schema: {len(schema['object_classes'])} object classes")

        # Get ACLs
        acl_attr = servers.get_acl_attribute_name(server_type).unwrap()
        print(f"ACL attribute: {acl_attr}")

        # Paged search
        paged_result = ops.search_with_paging(
            connection,
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            page_size=100,
        )
        if paged_result.success:
            paged_entries = paged_result.unwrap()
            print(f"Paged search: {len(paged_entries)} entries")


run(universal_ldap_example())
```

______________________________________________________________________

For more examples and advanced usage patterns, see:

- **Examples** - Working code examples
- **Server Operations Guide** - Server-specific usage
- **Integration Guide** - FLEXT ecosystem integration
- **Architecture Guide** - Understanding the design

## Related Documentation

**Within Project**:

- Getting Started - Installation and basic usage
- Architecture - Architecture and design patterns
- Configuration - Configuration options
- Examples - Working code examples

**Across Projects**:

- [flext-core Foundation](https://github.com/organization/flext/tree/main/flext-core/docs/api-reference/foundation.md) - Core APIs and patterns
- [flext-ldif Processing](https://github.com/organization/flext/tree/main/flext-ldif/docs/api-reference.md) - LDIF processing API
- [flext-meltano Pipelines](https://github.com/organization/flext/tree/main/flext-meltano/AGENTS.md) - Data integration and ELT orchestration

**External Resources**:

- [RFC 4511 - LDAP: The Protocol](https://www.rfc-editor.org/rfc/rfc4511.html)
- [RFC 4512 - LDAP: Technical Specification Road Map](https://www.rfc-editor.org/rfc/rfc4512.html)

______________________________________________________________________

**Next:** Configuration Guide →
