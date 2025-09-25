# API Reference

**Complete API documentation for flext-ldap**

This document provides comprehensive API reference for all public interfaces in flext-ldap.

---

## 🚀 Main API

### `get_flext_ldap_api(config=None)`

Factory function to get the main LDAP API instance.

**Parameters:**

- `config` (FlextLdapConfig, optional): Configuration object. If None, uses default config.

**Returns:** FlextLdapClient instance

**Example:**

```python
from flext_ldap import get_flext_ldap_api

api = get_flext_ldap_api()
```

---

## 🏗️ FlextLdapClient

Main API facade providing high-level LDAP operations.

### `async search_entries(request: SearchRequest) -> FlextResult[List[LdapEntry]]`

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

result = await api.search_entries(search_request)
if result.is_success:
    entries = result.unwrap()
```

### `async authenticate_user(username: str, password: str) -> FlextResult[FlextLdapUser]`

Authenticate user credentials against LDAP directory.

**Parameters:**

- `username` (str): User identifier
- `password` (str): User password

**Returns:** FlextResult containing authenticated user object

**Example:**

```python
result = await api.authenticate_user("john.doe", "password123")
if result.is_success:
    user = result.unwrap()
    print(f"Authenticated: {user.cn}")
```

### `async create_user(request: CreateUserRequest) -> FlextResult[FlextLdapUser]`

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

result = await api.create_user(user_request)
```

### `async test_connection() -> FlextResult[str]`

Test LDAP server connectivity.

**Returns:** FlextResult with connection status message

**Example:**

```python
result = await api.test_connection()
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
- `attributes` (List[str]): Attributes to retrieve
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
- `object_classes` (List[str], optional): LDAP object classes

#### FlextLdapUser

LDAP user entity.

**Attributes:**

- `dn` (str): Distinguished name
- `uid` (str): User identifier
- `cn` (str): Common name
- `sn` (str): Surname
- `given_name` (str, optional): First name
- `mail` (str, optional): Email address
- `member_of` (List[str], optional): Group memberships

**Methods:**

- `is_valid() -> bool`: Validate user data
- `get_display_name() -> str`: Get display name

#### FlextLdapGroup

LDAP group entity.

**Attributes:**

- `dn` (str): Distinguished name
- `cn` (str): Common name
- `members` (List[str]): Member distinguished names
- `description` (str, optional): Group description

**Methods:**

- `add_member(member_dn: str) -> None`: Add group member
- `remove_member(member_dn: str) -> None`: Remove group member

---

## 🎯 Value Objects

### FlextLdapModels.ValueObjects

Container for value objects.

#### DistinguishedName

RFC 4514 compliant distinguished name.

**Attributes:**

- `value` (str): DN string value

**Methods:**

- `rdn() -> str`: Get relative distinguished name
- `parent_dn() -> str`: Get parent DN

**Example:**

```python
dn = FlextLdapModels.ValueObjects.DistinguishedName("cn=user,ou=people,dc=example,dc=com")
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

### FlextLdapConfig

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
from Flext_ldap import FlextLdapConfig, set_flext_ldap_config

config = FlextLdapConfig(
    host="ldap.example.com",
    port=636,
    use_ssl=True,
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="admin-password",
    base_dn="dc=example,dc=com"
)

set_flext_ldap_config(config)
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

### FlextLdapExceptions

LDAP-specific exception classes.

#### FlextLdapConnectionError

Connection-related errors.

**Attributes:**

- `message` (str): Error description
- `server` (str, optional): LDAP server address

#### FlextLdapAuthenticationError

Authentication failures.

**Attributes:**

- `message` (str): Error description
- `username` (str, optional): Failed username

#### FlextLdapSearchError

Search operation errors.

**Attributes:**

- `message` (str): Error description
- `base_dn` (str, optional): Search base DN
- `filter_str` (str, optional): Search filter

**Example:**

```python
from flext_ldap import FlextLdapExceptions

try:
    result = await api.search_entries(request)
    if result.is_failure:
        # Handle FlextResult error
        print(f"Search failed: {result.error}")
except FlextLdapExceptions.FlextLdapConnectionError as e:
    print(f"Connection error: {e.message}")
```

---

## 🔄 FlextResult Usage

All API methods return `FlextResult[T]` for consistent error handling.

### Success Handling

```python
result = await api.search_entries(request)

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
result = await api.authenticate_user(username, password)

if result.is_failure:
    error_message = result.error
    print(f"Authentication failed: {error_message}")
```

### Chaining Operations

```python
search_result = await api.search_entries(request)
if search_result.is_success:
    entries = search_result.unwrap()
    # Process entries...
else:
    # Handle search failure
    return FlextResult.fail(f"Search failed: {search_result.error}")
```

---

## 📝 Type Annotations

All public APIs include comprehensive type annotations for IDE support and static analysis:

```python
async def search_entries(
    self,
    request: FlextLdapEntities.SearchRequest
) -> FlextResult[List[FlextLdapEntities.LdapEntry]]:
    """Search LDAP entries with full type safety."""
```

Use mypy or similar tools for static type checking:

```bash
mypy --strict your_code.py
```

---

For more examples and advanced usage patterns, see:

- **[Examples](examples/)** - Working code examples
- **[Integration Guide](integration.md)** - FLEXT ecosystem integration
- **[Architecture Guide](architecture.md)** - Understanding the design

---

**Next:** [Configuration Guide](configuration.md) →
