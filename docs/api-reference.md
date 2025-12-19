# API Reference

## Table of Contents

- [API Reference](#api-reference)
  - [🚀 Main API](#-main-api)
    - [`get_flext_ldap_api(config=None)`](#get_flext_ldap_apiconfignone)
  - [🏗️ FlextLdapClients](#-flextldapclients) - [`search_entries(request: SearchRequest) -> FlextResult[List[LdapEntry]]`](#search_entriesrequest-searchrequest---flextresultlistldapentry) - [`authenticate_user(username: str,
password: str) -> FlextResult[FlextLdapUser]`](#authenticate_userusername-str-password-str---flextresultflextldapuser) - [`create_user(request: CreateUserRequest) -> FlextResult[FlextLdapUser]`](#create_userrequest-createuserrequest---flextresultflextldapuser) - [`test_connection() -> FlextResult[str]`](#test_connection---flextresultstr)
  - [📊 Domain Entities](#-domain-entities)
    - [FlextLdapEntities](#flextldapentities)
      - [SearchRequest](#searchrequest)
      - [CreateUserRequest](#createuserrequest)
      - [FlextLdapUser](#flextldapuser)
      - [FlextLdapGroup](#flextldapgroup)
  - [🎯 Value Objects](#-value-objects)
    - [FlextLdapModels.ValueObjects](#flextldapmodelsvalueobjects)
      - [DN](#distinguishedname)
      - [LdapFilter](#ldapfilter)
- [Create filters](#create-filters)
- [Combine filters](#combine-filters) - [LdapScope](#ldapscope)
  - [⚙️ Configuration](#-configuration)
    - [FlextLdapSettings](#flextldapconfig)
  - [🔧 Utilities](#-utilities)
    - [FlextLdapTypeGuards](#flextldaptypeguards)
      - [`is_valid_dn(value: str) -> bool`](#is_valid_dnvalue-str---bool)
      - [`is_ldap_entry(obj: object) -> bool`](#is_ldap_entryobj-object---bool)
    - [FlextLdapConstants](#flextldapconstants)
  - [🚨 Exceptions](#-exceptions)
    - [FlextExceptions](#flextexceptions)
      - [ConnectionError](#connectionerror)
      - [AuthenticationError](#authenticationerror)
      - [SearchError](#searcherror)
  - [🔄 FlextResult Usage](#-flextresult-usage)
    - [Success Handling](#success-handling)
- [Check success](#check-success)
- [Alternative: direct access (raises if failure)](#alternative-direct-access-raises-if-failure)
  - [Error Handling](#error-handling)
  - [Chaining Operations](#chaining-operations)
  - [🔄 Universal LDAP Interface](#-universal-ldap-interface)
    - [FlextLdapEntryAdapter](#flextldapentryadapter)
      - [`ldap3_to_ldif_entry(ldap3_entry) -> FlextResult[FlextLdifModels.Entry]`](#ldap3_to_ldif_entryldap3_entry---flextresultflextldifmodelsentry)
- [Search with ldap3](#search-with-ldap3) - [`ldap3_entries_to_ldif_entries(ldap3_entries) -> FlextResult[List[FlextLdifModels.Entry]]`](#ldap3_entries_to_ldif_entriesldap3_entries---flextresultlistflextldifmodelsentry) - [`ldif_entry_to_ldap3_attributes(ldif_entry) -> FlextResult[dict[str,
t.List]]`](#ldif_entry_to_ldap3_attributesldif_entry---flextresultdictstr-flexttypeslist)
- [Create FlextLdif entry](#create-flextldif-entry)
- [Convert to ldap3 attributes](#convert-to-ldap3-attributes) - [`convert_ldif_file_to_entries(ldif_file_path) -> FlextResult[List[FlextLdifModels.Entry]]`](#convert_ldif_file_to_entriesldif_file_path---flextresultlistflextldifmodelsentry) - [`write_entries_to_ldif_file(entries,
output_path) -> FlextResult[bool]`](#write_entries_to_ldif_fileentries-output_path---flextresultbool)
  - [FlextLdapQuirksAdapter](#flextldapquirksadapter)
    - [`detect_server_type_from_entries(entries) -> FlextResult[str]`](#detect_server_type_from_entriesentries---flextresultstr)
- [Detect from entries](#detect-from-entries) - [`get_acl_attribute_name(server_type=None) -> FlextResult[str]`](#get_acl_attribute_nameserver_typenone---flextresultstr) - [`get_acl_format(server_type=None) -> FlextResult[str]`](#get_acl_formatserver_typenone---flextresultstr) - [`get_schema_subentry(server_type=None) -> FlextResult[str]`](#get_schema_subentryserver_typenone---flextresultstr) - [`get_max_page_size(server_type=None) -> FlextResult[int]`](#get_max_page_sizeserver_typenone---flextresultint) - [`normalize_entry_for_server(entry,
server_type=None) -> FlextResult[FlextLdifModels.Entry]`](#normalize_entry_for_serverentry-server_typenone---flextresultflextldifmodelsentry)
  - [🏗️ Server Operations](#-server-operations)
    - [BaseServerOperations](#baseserveroperations)
      - [Connection Operations](#connection-operations)
        - [`get_default_port(use_ssl=False) -> int`](#get_default_portuse_sslfalse---int)
        - [`supports_start_tls() -> bool`](#supports_start_tls---bool)
        - [`get_bind_mechanisms() -> t.StringList`](#get_bind_mechanisms---flexttypesstringlist)
      - [Schema Operations](#schema-operations)
        - [`get_schema_dn() -> str`](#get_schema_dn---str)
        - [`discover_schema(connection) -> FlextResult[t.Dict]`](#discover_schemaconnection---flextresultflexttypesdict)
        - [`parse_object_class(object_class_def) -> FlextResult[t.Dict]`](#parse_object_classobject_class_def---flextresultflexttypesdict)
        - [`parse_attribute_type(attribute_def) -> FlextResult[t.Dict]`](#parse_attribute_typeattribute_def---flextresultflexttypesdict)
      - [ACL Operations](#acl-operations)
        - [`get_acl_attribute_name() -> str`](#get_acl_attribute_name---str)
        - [`get_acl_format() -> str`](#get_acl_format---str)
        - [`get_acls(connection, dn) -> FlextResult[list[t.Dict]]`](#get_aclsconnection-dn---flextresultlistflexttypesdict)
- [Get ACLs from cn=config entry](#get-acls-from-cnconfig-entry) - [`set_acls(connection, dn, acls) -> FlextResult[bool]`](#set_aclsconnection-dn-acls---flextresultbool) - [`parse(acl_string) -> FlextResult[t.Dict]`](#parseacl_string---flextresultflexttypesdict) - [`format_acl(acl_dict) -> FlextResult[str]`](#format_aclacl_dict---flextresultstr) - [Entry Operations](#entry-operations) - [`add_entry(connection, entry) -> FlextResult[bool]`](#add_entryconnection-entry---flextresultbool) - [`modify_entry(connection, dn, modifications) -> FlextResult[bool]`](#modify_entryconnection-dn-modifications---flextresultbool) - [`delete_entry(connection, dn) -> FlextResult[bool]`](#delete_entryconnection-dn---flextresultbool) - [`normalize_entry(entry) -> FlextResult[FlextLdifModels.Entry]`](#normalize_entryentry---flextresultflextldifmodelsentry) - [Search Operations](#search-operations) - [`get_max_page_size() -> int`](#get_max_page_size---int) - [`supports_paged_results() -> bool`](#supports_paged_results---bool) - [`supports_vlv() -> bool`](#supports_vlv---bool) - [`search_with_paging(connection, base_dn, search_filter, attributes=None,
page_size=100) -> FlextResult[list[FlextLdifModels.Entry]]`](#search_with_pagingconnection-base_dn-search_filter-attributesnone-page_size100---flextresultlistflextldifmodelsentry)
  - [Server-Specific Implementations](#server-specific-implementations)
    - [OpenLDAP2Operations](#openldap2operations)
- [Schema discovery](#schema-discovery)
- [ACL management](#acl-management) - [OracleOIDOperations](#oracleoidoperations) - [OracleOUDOperations](#oracleoudoperations) - [GenericServerOperations](#genericserveroperations)
  - [📝 Type Annotations](#-type-annotations)
- [Server operations with FlextLdif integration](#server-operations-with-flextldif-integration)
  - [🔗 Complete Usage Example](#-complete-usage-example)

**Complete API documentation for flext-ldap**

This document provides comprehensive API reference for all public interfaces in flext-ldap.

**Version**: 0.9.9 | **Test Coverage**: 35% | **Phase 2**: ✅ Complete
**Architecture**: Clean Architecture + DDD + Railway-oriented programming

---

## 🚀 Main API

### `get_flext_ldap_api(config=None)`

Factory function to get the main LDAP API instance.

**Parameters:**

- `config` (FlextLdapSettings, optional): Configuration object. If None, uses default config.

**Returns:** FlextLdapClients instance

**Example:**

```python
from flext_ldap import get_flext_ldap_api

api = get_flext_ldap_api()
```

---

## 🏗️ FlextLdapClients

Main API facade providing high-level LDAP operations.

### `search_entries(request: SearchRequest) -> FlextResult[List[LdapEntry]]`

Search LDAP directory entries.

**Parameters:**

- `request`: SearchRequest object with search criteria

**Returns:** FlextResult containing list of matching entries

**Example:**

```python
search_request = FlextLdapEntities.SearchRequest(
    base_dn="dc=example,dc=com",
    filter_str="(objectClass=person)",
    scope="subtree",
    attributes=["uid", "cn", "mail"]
)

result = api.search_entries(search_request)
if result.is_success:
    entries = result.unwrap()
```

### `authenticate_user(username: str, password: str) -> FlextResult[FlextLdapUser]`

Authenticate user credentials against LDAP directory.

**Parameters:**

- `username` (str): User identifier
- `password` (str): User password

**Returns:** FlextResult containing authenticated user object

**Example:**

```python
result = api.authenticate_user("john.doe", "password123")
if result.is_success:
    user = result.unwrap()
    print(f"Authenticated: {user.cn}")
```

### `create_user(request: CreateUserRequest) -> FlextResult[FlextLdapUser]`

Create a new user in LDAP directory.

**Parameters:**

- `request`: CreateUserRequest with user details

**Returns:** FlextResult containing created user object

**Example:**

```python
user_request = FlextLdapEntities.CreateUserRequest(
    dn="cn=jane.doe,ou=users,dc=example,dc=com",
    uid="jane.doe",
    cn="Jane Doe",
    sn="Doe",
    mail="jane.doe@example.com"
)

result = api.create_user(user_request)
```

### `test_connection() -> FlextResult[str]`

Test LDAP server connectivity.

**Returns:** FlextResult with connection status message

**Example:**

```python
result = api.test_connection()
if result.is_success:
    print("Connection successful")
```

---

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

---

## 🎯 Value Objects

### FlextLdapModels.ValueObjects

Container for value objects.

#### DN

RFC 4514 compliant distinguished name.

**Attributes:**

- `value` (str): DN string value

**Methods:**

- `rdn() -> str`: Get relative distinguished name
- `parent_dn() -> str`: Get parent DN

**Example:**

```python
dn = FlextLdapModels.ValueObjects.DN("cn=user,ou=people,dc=example,dc=com")
print(dn.rdn)       # "cn=user"
print(dn.parent_dn) # "ou=people,dc=example,dc=com"
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

```python
# Create filters
user_filter = FlextLdapModels.ValueObjects.LdapFilter.equals("uid", "john.doe")
person_filter = FlextLdapModels.ValueObjects.LdapFilter.object_class("person")

# Combine filters
combined = FlextLdapModels.ValueObjects.LdapFilter.and_filters(user_filter, person_filter)
```

#### LdapScope

Search scope enumeration.

**Values:**

- `BASE`: Search base object only
- `ONELEVEL`: Search immediate children
- `SUBTREE`: Search entire subtree

---

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

```python
from Flext_ldap import FlextLdapSettings, set_flext_ldap.settings

config = FlextLdapSettings(
    host="ldap.example.com",
    port=636,
    use_ssl=True,
    bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    bind_password="REDACTED_LDAP_BIND_PASSWORD-password",
    base_dn="dc=example,dc=com"
)

set_flext_ldap.settings(config)
```

---

## 🔧 Utilities

### FlextLdapTypeGuards

Type guard functions for runtime type checking.

#### `is_valid_dn(value: str) -> bool`

Check if string is a valid distinguished name.

**Example:**

```python
from flext_ldap import FlextLdapTypeGuards

if FlextLdapTypeGuards.is_valid_dn("cn=user,dc=example,dc=com"):
    print("Valid DN")
```

#### `is_ldap_entry(obj: object) -> bool`

Check if object is a valid LDAP entry.

### FlextLdapConstants

LDAP protocol constants.

**Attributes:**

- `DEFAULT_PORT`: Default LDAP port (389)
- `DEFAULT_SSL_PORT`: Default LDAPS port (636)
- `SCOPE_BASE`: Base search scope
- `SCOPE_ONELEVEL`: One-level search scope
- `SCOPE_SUBTREE`: Subtree search scope

---

## 🚨 Exceptions

### FlextExceptions

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

```python
from flext_ldap import FlextExceptions

try:
    result = api.search_entries(request)
    if result.is_failure:
        # Handle FlextResult error
        print(f"Search failed: {result.error}")
except FlextExceptions.ConnectionError as e:
    print(f"Connection error: {e.message}")
```

---

## 🔄 FlextResult Usage

All API methods return `FlextResult[T]` for consistent error handling.

### Success Handling

```python
result = api.search_entries(request)

# Check success
if result.is_success:
    data = result.unwrap()

# Alternative: direct access (raises if failure)
try:
    data = result.unwrap()
except FlextResultError:
    print("Operation failed")
```

### Error Handling

```python
result = api.authenticate_user(username, password)

if result.is_failure:
    error_message = result.error
    print(f"Authentication failed: {error_message}")
```

### Chaining Operations

```python
search_result = api.search_entries(request)
if search_result.is_success:
    entries = search_result.unwrap()
    # Process entries...
else:
    # Handle search failure
    return FlextResult.fail(f"Search failed: {search_result.error}")
```

---

## 🔄 Universal LDAP Interface

### FlextLdapEntryAdapter

Bidirectional converter between ldap3 entries and FlextLdif entries.

**Import:**

```python
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
```

#### `ldap3_to_ldif_entry(ldap3_entry) -> FlextResult[FlextLdifModels.Entry]`

Convert ldap3.Entry to FlextLdif entry.

**Parameters:**

- `ldap3_entry`: ldap3.Entry object from search results

**Returns:** FlextResult containing FlextLdifModels.Entry

**Example:**

```python
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
import ldap3

adapter = FlextLdapEntryAdapter()

# Search with ldap3
connection.search('dc=example,dc=com', '(objectClass=person)')

for ldap3_entry in connection.entries:
    # Convert to FlextLdif
    result = adapter.ldap3_to_ldif_entry(ldap3_entry)
    if result.is_success:
        ldif_entry = result.unwrap()
        print(f"DN: {ldif_entry.dn}")
```

#### `ldap3_entries_to_ldif_entries(ldap3_entries) -> FlextResult[List[FlextLdifModels.Entry]]`

Batch convert multiple ldap3 entries to FlextLdif entries.

**Parameters:**

- `ldap3_entries`: List of ldap3.Entry objects

**Returns:** FlextResult containing list of FlextLdifModels.Entry

#### `ldif_entry_to_ldap3_attributes(ldif_entry) -> FlextResult[dict[str, t.List]]`

Convert FlextLdif entry to ldap3 attributes dictionary.

**Parameters:**

- `ldif_entry`: FlextLdifModels.Entry to convert

**Returns:** FlextResult containing attributes dict[str, object] for ldap3 operations

**Example:**

```python
from flext_ldif import FlextLdifModels
from flext_ldap.entry_adapter import FlextLdapEntryAdapter

adapter = FlextLdapEntryAdapter()

# Create FlextLdif entry
ldif_entry = FlextLdifModels.Entry(
    dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
    attributes=FlextLdifModels.Attributes(attributes={
        "objectClass": ["person", "organizationalPerson"],
        "cn": ["test"],
        "sn": ["Test User"]
    })
)

# Convert to ldap3 attributes
result = adapter.ldif_entry_to_ldap3_attributes(ldif_entry)
if result.is_success:
    attributes = result.unwrap()
    connection.add(str(ldif_entry.dn), attributes=attributes)
```

#### `convert_ldif_file_to_entries(ldif_file_path) -> FlextResult[List[FlextLdifModels.Entry]]`

Load and convert LDIF file to FlextLdif entries.

**Parameters:**

- `ldif_file_path` (str): Path to LDIF file

**Returns:** FlextResult containing list of entries

#### `write_entries_to_ldif_file(entries, output_path) -> FlextResult[bool]`

Write FlextLdif entries to LDIF file.

**Parameters:**

- `entries`: List of FlextLdifModels.Entry
- `output_path` (str): Output file path

**Returns:** FlextResult indicating success

---

### FlextLdapQuirksAdapter

Server detection and quirks system integration using FlextLdif.

**Import:**

```python
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter
```

#### `detect_server_type_from_entries(entries) -> FlextResult[str]`

Detect LDAP server type from entry analysis.

**Parameters:**

- `entries`: List of FlextLdifModels.Entry objects

**Returns:** FlextResult containing server type string

**Server Types:**

- `"openldap2"` - OpenLDAP 2.x (cn=config)
- `"openldap1"` - OpenLDAP 1.x (legacy)
- `"oid"` - Oracle Internet Directory
- `"oud"` - Oracle Unified Directory
- `"ad"` - Active Directory
- `"generic"` - Generic LDAP server

**Example:**

```python
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter
from flext_ldap.servers import (
    OpenLDAP2Operations, OracleOIDOperations, OracleOUDOperations
)

quirks = FlextLdapQuirksAdapter()

# Detect from entries
entries = [...]  # FlextLdif entries from search
result = quirks.detect_server_type_from_entries(entries)

if result.is_success:
    server_type = result.unwrap()

    # Select appropriate server operations
    if server_type == "openldap2":
        ops = OpenLDAP2Operations()
    elif server_type == "oid":
        ops = OracleOIDOperations()
    elif server_type == "oud":
        ops = OracleOUDOperations()
```

#### `get_acl_attribute_name(server_type=None) -> FlextResult[str]`

Get server-specific ACL attribute name.

**Parameters:**

- `server_type` (str, optional): Server type (uses detected if None)

**Returns:** FlextResult containing ACL attribute name

**ACL Attributes:**

- OpenLDAP 2.x: `"olcAccess"`
- OpenLDAP 1.x: `"access"`
- Oracle OID: `"orclaci"`
- Oracle OUD: `"ds-privilege-name"`
- Active Directory: `"nTSecurityDescriptor"`
- Generic: `"aci"`

#### `get_acl_format(server_type=None) -> FlextResult[str]`

Get server-specific ACL format identifier.

#### `get_schema_subentry(server_type=None) -> FlextResult[str]`

Get server-specific schema DN.

**Schema DNs:**

- OpenLDAP: `"cn=subschema"`
- Oracle OID: `"cn=subschemasubentry"`
- Oracle OUD: `"cn=schema"`
- Active Directory: `"cn=schema,cn=configuration"`

#### `get_max_page_size(server_type=None) -> FlextResult[int]`

Get server-specific maximum page size for paged searches.

#### `normalize_entry_for_server(entry, server_type=None) -> FlextResult[FlextLdifModels.Entry]`

Normalize entry for server-specific requirements.

---

## 🏗️ Server Operations

### BaseServerOperations

Abstract base class defining complete server operations interface.

**Import:**

```python
from flext_ldap.servers import BaseServerOperations
```

**Server Implementations:**

- `OpenLDAP2Operations` - OpenLDAP 2.x (cn=config, olcAccess ACLs)
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

##### `discover_schema(connection) -> FlextResult[t.Dict]`

Discover schema from server.

**Returns:** FlextResult containing schema data:

- `object_classes`: List of objectClass definitions
- `attribute_types`: List of attributeType definitions
- `syntaxes`: List of LDAP syntax definitions
- `server_type`: Detected server type

**Example:**

```python
from flext_ldap.servers import OpenLDAP2Operations
import ldap3

ops = OpenLDAP2Operations()

connection = ldap3.Connection(
    ldap3.Server('ldap://server:389'),
    user='cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com',
    password='password',
    auto_bind=True
)

schema_result = ops.discover_schema(connection)
if schema_result.is_success:
    schema = schema_result.unwrap()
    print(f"Object classes: {len(schema['object_classes'])}")
    print(f"Attribute types: {len(schema['attribute_types'])}")
```

##### `parse_object_class(object_class_def) -> FlextResult[t.Dict]`

Parse objectClass definition string.

##### `parse_attribute_type(attribute_def) -> FlextResult[t.Dict]`

Parse attributeType definition string.

#### ACL Operations

##### `get_acl_attribute_name() -> str`

Get ACL attribute name for server type.

##### `get_acl_format() -> str`

Get ACL format identifier.

##### `get_acls(connection, dn) -> FlextResult[list[t.Dict]]`

Retrieve ACLs from entry.

**Example:**

```python
from flext_ldap.servers import OpenLDAP2Operations

ops = OpenLDAP2Operations()

# Get ACLs from cn=config entry
result = ops.get_acls(
    connection,
    dn='olcDatabase={1}mdb,cn=config'
)

if result.is_success:
    acls = result.unwrap()
    for acl in acls:
        print(f"ACL: {acl.get('raw')}")
```

##### `set_acls(connection, dn, acls) -> FlextResult[bool]`

Set ACLs on entry.

**Example:**

```python
new_acls = [
    {"raw": "{0}to * by dn=\"cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com\" write"},
    {"raw": "{1}to * by self write by anonymous auth"}
]

result = ops.set_acls(connection, dn, acls=new_acls)
```

##### `parse(acl_string) -> FlextResult[t.Dict]`

Parse server-specific ACL string to dictionary.

##### `format_acl(acl_dict) -> FlextResult[str]`

Format ACL dictionary to server-specific string.

#### Entry Operations

##### `add_entry(connection, entry) -> FlextResult[bool]`

Add FlextLdif entry to directory.

**Example:**

```python
from flext_ldif import FlextLdifModels
from flext_ldap.servers import OpenLDAP2Operations

ops = OpenLDAP2Operations()

entry = FlextLdifModels.Entry(
    dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
    attributes=FlextLdifModels.Attributes(attributes={
        "objectClass": ["person", "organizationalPerson"],
        "cn": ["test"],
        "sn": ["Test User"],
        "mail": ["test@example.com"]
    })
)

result = ops.add_entry(connection, entry)
if result.is_success:
    print("Entry added successfully")
```

##### `modify_entry(connection, dn, modifications) -> FlextResult[bool]`

Modify entry attributes.

**Example:**

```python
modifications = {
    "mail": ["newemail@example.com"],
    "telephoneNumber": ["+1-555-0100"]
}

result = ops.modify_entry(
    connection,
    dn="cn=test,dc=example,dc=com",
    modifications=modifications
)
```

##### `delete_entry(connection, dn) -> FlextResult[bool]`

Delete entry from directory.

##### `normalize_entry(entry) -> FlextResult[FlextLdifModels.Entry]`

Normalize entry for server-specific requirements.

#### Search Operations

##### `get_max_page_size() -> int`

Get maximum page size for paged searches.

##### `supports_paged_results() -> bool`

Check if server supports paged results control.

##### `supports_vlv() -> bool`

Check if server supports Virtual List View (VLV).

##### `search_with_paging(connection, base_dn, search_filter, attributes=None, page_size=100) -> FlextResult[list[FlextLdifModels.Entry]]`

Execute paged search with automatic pagination.

**Example:**

```python
from flext_ldap.servers import OpenLDAP2Operations

ops = OpenLDAP2Operations()

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
        print(f"DN: {entry.dn}")
```

---

### Server-Specific Implementations

#### OpenLDAP2Operations

Complete implementation for OpenLDAP 2.x (cn=config style).

**Import:**

```python
from flext_ldap.servers import OpenLDAP2Operations
```

**Features:**

- olcAccess ACL format
- cn=subschema schema discovery
- Paged results support
- VLV support (limited)
- START_TLS support

**Example:**

```python
from flext_ldap.servers import OpenLDAP2Operations
import ldap3

ops = OpenLDAP2Operations()

connection = ldap3.Connection(
    ldap3.Server('ldap://openldap-server:389'),
    user='cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com',
    password='password',
    auto_bind=True
)

# Schema discovery
schema = ops.discover_schema(connection)

# ACL management
acls = ops.get_acls(connection, 'olcDatabase={1}mdb,cn=config')
```

#### OracleOIDOperations

Complete implementation for Oracle Internet Directory.

**Import:**

```python
from flext_ldap.servers import OracleOIDOperations
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

```python
from flext_ldap.servers import OracleOUDOperations
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

```python
from flext_ldap.servers import GenericServerOperations
```

**Features:**

- aci ACL attribute (generic)
- cn=subschema schema discovery (RFC 4512)
- Basic paged results
- Standard LDAP operations

---

## 📝 Type Annotations

All public APIs include comprehensive type annotations for IDE support and static analysis:

```python
def search_entries(
    self,
    request: FlextLdapEntities.SearchRequest
) -> FlextResult[List[FlextLdapEntities.LdapEntry]]:
    """Search LDAP entries with full type safety."""

# Server operations with FlextLdif integration
def add_entry(
    self,
    connection: object,
    entry: FlextLdifModels.Entry
) -> FlextResult[bool]:
    """Add entry with type safety."""
```

Use mypy or similar tools for static type checking:

```bash
mypy --strict your_code.py
```

---

## 🔗 Complete Usage Example

```python
import ldap3
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter
from flext_ldap.servers import (
    OpenLDAP2Operations, OracleOIDOperations, OracleOUDOperations
)
from flext_ldif import FlextLdifModels

def universal_ldap_example():
    """Complete example using universal LDAP interface."""

    # Setup connection
    connection = ldap3.Connection(
        ldap3.Server('ldap://server:389'),
        user='cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com',
        password='password',
        auto_bind=True
    )

    # Initialize adapters
    adapter = FlextLdapEntryAdapter()
    quirks = FlextLdapQuirksAdapter()

    # Search for entries
    connection.search(
        'dc=example,dc=com',
        '(objectClass=*)',
        attributes=['*']
    )

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
        elif server_type == "oud":
            ops = OracleOUDOperations()
        else:
            from flext_ldap.servers import GenericServerOperations
            ops = GenericServerOperations()

        # Discover schema
        schema_result = ops.discover_schema(connection)
        if schema_result.is_success:
            schema = schema_result.unwrap()
            print(f"Schema: {len(schema['object_classes'])} object classes")

        # Get ACLs
        acl_attr = quirks.get_acl_attribute_name(server_type).unwrap()
        print(f"ACL attribute: {acl_attr}")

        # Paged search
        paged_result = ops.search_with_paging(
            connection,
            base_dn='dc=example,dc=com',
            search_filter='(objectClass=person)',
            page_size=100
        )
        if paged_result.is_success:
            paged_entries = paged_result.unwrap()
            print(f"Paged search: {len(paged_entries)} entries")

run(universal_ldap_example())
```

---

For more examples and advanced usage patterns, see:

- **[Examples](examples/)** - Working code examples
- **[Server Operations Guide](server-operations.md)** - Server-specific usage
- **[Integration Guide](integration.md)** - FLEXT ecosystem integration
- **[Architecture Guide](architecture.md)** - Understanding the design

## Related Documentation

**Within Project**:

- [Getting Started](getting-started.md) - Installation and basic usage
- [Architecture](architecture.md) - Architecture and design patterns
- [Configuration](configuration.md) - Configuration options
- [Examples](examples/) - Working code examples

**Across Projects**:

- [flext-core Foundation](https://github.com/organization/flext/tree/main/flext-core/docs/api-reference/foundation.md) - Core APIs and patterns
- [flext-ldif Processing](https://github.com/organization/flext/tree/main/flext-ldif/docs/api-reference.md) - LDIF processing API
- [flext-meltano Pipelines](https://github.com/organization/flext/tree/main/flext-meltano/CLAUDE.md) - Data integration and ELT orchestration

**External Resources**:

- [RFC 4511 - LDAP: The Protocol](https://www.rfc-editor.org/rfc/rfc4511.html)
- [RFC 4512 - LDAP: Technical Specification Road Map](https://www.rfc-editor.org/rfc/rfc4512.html)

---

**Next:** [Configuration Guide](configuration.md) →
