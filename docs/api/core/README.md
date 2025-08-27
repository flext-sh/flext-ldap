# FLEXT-LDAP Core API Reference

**Comprehensive API documentation for FLEXT-LDAP core functionality**

This document provides complete API reference for FLEXT-LDAP core components, including the main API classes, domain entities, and integration patterns.

---

## 📚 API Overview

### Core Components

- **[FlextLdapApi](#flextldapapi)**: Main API entry point with unified LDAP operations
- **[Domain Entities](#domain-entities)**: Business entities (User, Group, Entry)
- **[Value Objects](#value-objects)**: Immutable value objects (DN, Filter, Scope)
- **[Configuration](#configuration)**: Settings and configuration management
- **[Result Types](#result-types)**: FlextResult pattern for error handling

### Architecture Integration

All APIs follow FLEXT-Core patterns:

- **FlextResult[T]**: Type-safe error handling
- **FlextContainer**: Dependency injection
- **FlextLogger**: Structured logging
- **FlextLDAPConfig**: Centralized configuration

---

## 🔧 FlextLdapApi

### Class Definition

```python
class FlextLdapApi:
    \"\"\"Unified LDAP API using flext-core patterns.

    Single interface that consolidates all LDAP operations with:
    - Type-safe error handling via FlextResult
    - Domain-driven design with rich entities
    - Enterprise dependency injection via flext-core
    - Connection pooling and management
    \"\"\"
```

### Constructor

```python
def __init__(self, config: FlextLdapSettings | None = None) -> None:
    \"\"\"Initialize LDAP API with flext-core centralized configuration.

    Args:
        config: Optional LDAP settings. If None, uses default configuration
                from environment variables and FlextLDAPConfig.

    Example:
        # Use default configuration
        api = FlextLdapApi()

        # Use custom configuration
        settings = FlextLdapSettings(
            server_url=\"ldap://custom.example.com\",
            port=389,
            use_ssl=False
        )
        api = FlextLdapApi(config=settings)
    \"\"\"
```

### Connection Management

#### connection()

```python
@asynccontextmanager
async def connection(
    self,
    server_url: str,
    bind_dn: str,
    password: str,
    use_ssl: bool = False,
    timeout: int = 30
) -> AsyncIterator[str]:
    \"\"\"Create managed LDAP connection with automatic cleanup.

    Args:
        server_url: LDAP server URL (e.g., \"ldap://directory.company.com\")
        bind_dn: Bind distinguished name for authentication
        password: Bind password
        use_ssl: Enable SSL/TLS connection (default: False)
        timeout: Connection timeout in seconds (default: 30)

    Yields:
        str: Session ID for use with other operations

    Raises:
        FlextLdapConnectionError: If connection fails
        FlextLdapAuthenticationError: If authentication fails

    Example:
        async with api.connection(
            \"ldap://directory.company.com\",
            \"cn=admin,dc=company,dc=com\",
            \"admin_password\"
        ) as session:
            result = await api.search(session, \"ou=users,dc=company,dc=com\", \"(uid=*)\")
    \"\"\"
```

#### connect()

```python
async def connect(
    self,
    server_url: str,
    bind_dn: str,
    password: str,
    use_ssl: bool = False,
    timeout: int = 30
) -> FlextResult[str]:
    \"\"\"Establish LDAP connection.

    Args:
        server_url: LDAP server URL
        bind_dn: Bind distinguished name
        password: Bind password
        use_ssl: Enable SSL/TLS connection
        timeout: Connection timeout in seconds

    Returns:
        FlextResult[str]: Success with session ID, or failure with error

    Example:
        result = await api.connect(
            \"ldap://directory.company.com\",
            \"cn=admin,dc=company,dc=com\",
            \"admin_password\"
        )

        if result.success:
            session_id = result.data
            # Use session_id for subsequent operations
        else:
            print(f\"Connection failed: {result.error}\")
    \"\"\"
```

#### disconnect()

```python
async def disconnect(self, session_id: str) -> FlextResult[bool]:
    \"\"\"Disconnect from LDAP server.

    Args:
        session_id: Session ID from connect() operation

    Returns:
        FlextResult[bool]: Success or failure result

    Example:
        result = await api.disconnect(session_id)
        if result.success:
            print(\"Disconnected successfully\")
    \"\"\"
```

### Search Operations

#### search()

```python
async def search(
    self,
    session_id: str,
    base_dn: str,
    filter_expr: str,
    attributes: List[str] | None = None,
    scope: str = \"subtree\"
) -> FlextResult[List[FlextLdapEntry]]:
    \"\"\"Search LDAP directory.

    Args:
        session_id: Active session ID
        base_dn: Search base distinguished name
        filter_expr: LDAP search filter (RFC 4515)
        attributes: List of attributes to return (None = all attributes)
        scope: Search scope (\"base\", \"onelevel\", \"subtree\")

    Returns:
        FlextResult[List[FlextLdapEntry]]: Search results or error

    Example:
        # Search all users
        result = await api.search(
            session,
            \"ou=users,dc=company,dc=com\",
            \"(objectClass=person)\",
            attributes=[\"uid\", \"cn\", \"mail\"]
        )

        if result.success:
            for entry in result.data:
                print(f\"User: {entry.get_attribute('cn')}\")

        # Search specific user
        result = await api.search(
            session,
            \"ou=users,dc=company,dc=com\",
            \"(uid=john.doe)\",
            scope=\"onelevel\"
        )
    \"\"\"
```

#### search_users()

```python
async def search_users(
    self,
    session_id: str,
    base_dn: str | None = None,
    filter_expr: str | None = None
) -> FlextResult[List[FlextLdapUser]]:
    \"\"\"Search for LDAP users with domain entity conversion.

    Args:
        session_id: Active session ID
        base_dn: Search base (default: ou=users from config)
        filter_expr: Search filter (default: \"(objectClass=person)\")

    Returns:
        FlextResult[List[FlextLdapUser]]: User domain entities

    Example:
        result = await api.search_users(session)

        if result.success:
            for user in result.data:
                print(f\"User: {user.display_name} ({user.email})\")
    \"\"\"
```

### User Management

#### create_user()

```python
async def create_user(
    self,
    session_id: str,
    request: FlextLdapCreateUserRequest
) -> FlextResult[FlextLdapUser]:
    \"\"\"Create new LDAP user.

    Args:
        session_id: Active session ID
        request: User creation request with validation

    Returns:
        FlextResult[FlextLdapUser]: Created user entity or error

    Example:
        request = FlextLdapCreateUserRequest(
            dn=\"uid=jane.doe,ou=users,dc=company,dc=com\",
            uid=\"jane.doe\",
            cn=\"Jane Doe\",
            sn=\"Doe\",
            mail=\"jane.doe@company.com\"
        )

        result = await api.create_user(session, request)

        if result.success:
            user = result.data
            print(f\"Created user: {user.dn}\")
        else:
            print(f\"Failed to create user: {result.error}\")
    \"\"\"
```

#### update_user()

```python
async def update_user(
    self,
    session_id: str,
    user_dn: str,
    updates: Dict[str, Any]
) -> FlextResult[bool]:
    \"\"\"Update existing LDAP user.

    Args:
        session_id: Active session ID
        user_dn: Distinguished name of user to update
        updates: Dictionary of attribute updates

    Returns:
        FlextResult[bool]: Success or failure result

    Example:
        updates = {
            \"mail\": \"new.email@company.com\",
            \"telephoneNumber\": \"+1-555-123-4567\",
            \"title\": \"Senior Developer\"
        }

        result = await api.update_user(
            session,
            \"uid=jane.doe,ou=users,dc=company,dc=com\",
            updates
        )
    \"\"\"
```

#### delete_user()

```python
async def delete_user(
    self,
    session_id: str,
    user_dn: str
) -> FlextResult[bool]:
    \"\"\"Delete LDAP user.

    Args:
        session_id: Active session ID
        user_dn: Distinguished name of user to delete

    Returns:
        FlextResult[bool]: Success or failure result

    Example:
        result = await api.delete_user(
            session,
            \"uid=jane.doe,ou=users,dc=company,dc=com\"
        )

        if result.success:
            print(\"User deleted successfully\")
    \"\"\"
```

#### get_user()

```python
async def get_user(
    self,
    session_id: str,
    user_dn: str
) -> FlextResult[FlextLdapUser]:
    \"\"\"Get LDAP user by distinguished name.

    Args:
        session_id: Active session ID
        user_dn: Distinguished name of user

    Returns:
        FlextResult[FlextLdapUser]: User entity or error

    Example:
        result = await api.get_user(
            session,
            \"uid=jane.doe,ou=users,dc=company,dc=com\"
        )

        if result.success:
            user = result.data
            print(f\"Found user: {user.display_name}\")
    \"\"\"
```

#### find_user_by_uid()

```python
async def find_user_by_uid(
    self,
    session_id: str,
    uid: str,
    base_dn: str | None = None
) -> FlextResult[FlextLdapUser]:
    \"\"\"Find user by UID attribute.

    Args:
        session_id: Active session ID
        uid: User identifier (uid attribute)
        base_dn: Search base (default: from configuration)

    Returns:
        FlextResult[FlextLdapUser]: User entity or error

    Example:
        result = await api.find_user_by_uid(session, \"jane.doe\")

        if result.success:
            user = result.data
            print(f\"Found user: {user.dn}\")
        else:
            print(f\"User not found: {result.error}\")
    \"\"\"
```

### Group Management

#### create_group()

```python
async def create_group(
    self,
    session_id: str,
    request: FlextLdapCreateGroupRequest
) -> FlextResult[FlextLdapGroup]:
    \"\"\"Create new LDAP group.

    Args:
        session_id: Active session ID
        request: Group creation request

    Returns:
        FlextResult[FlextLdapGroup]: Created group entity

    Example:
        request = FlextLdapCreateGroupRequest(
            dn=\"cn=developers,ou=groups,dc=company,dc=com\",
            cn=\"developers\",
            description=\"Software Development Team\"
        )

        result = await api.create_group(session, request)
    \"\"\"
```

#### add_group_member()

```python
async def add_group_member(
    self,
    session_id: str,
    group_dn: str,
    member_dn: str
) -> FlextResult[bool]:
    \"\"\"Add member to LDAP group.

    Args:
        session_id: Active session ID
        group_dn: Group distinguished name
        member_dn: Member distinguished name to add

    Returns:
        FlextResult[bool]: Success or failure result

    Example:
        result = await api.add_group_member(
            session,
            \"cn=developers,ou=groups,dc=company,dc=com\",
            \"uid=jane.doe,ou=users,dc=company,dc=com\"
        )
    \"\"\"
```

#### remove_group_member()

```python
async def remove_group_member(
    self,
    session_id: str,
    group_dn: str,
    member_dn: str
) -> FlextResult[bool]:
    \"\"\"Remove member from LDAP group.

    Args:
        session_id: Active session ID
        group_dn: Group distinguished name
        member_dn: Member distinguished name to remove

    Returns:
        FlextResult[bool]: Success or failure result
    \"\"\"
```

### Entry Operations

#### create_entry()

```python
async def create_entry(
    self,
    session_id: str,
    entry: FlextLdapEntry
) -> FlextResult[bool]:
    \"\"\"Create generic LDAP entry.

    Args:
        session_id: Active session ID
        entry: LDAP entry to create

    Returns:
        FlextResult[bool]: Success or failure result

    Example:
        entry = FlextLdapEntry(
            dn=\"ou=newdept,ou=departments,dc=company,dc=com\",
            object_classes=[\"organizationalUnit\"],
            attributes={
                \"ou\": [\"newdept\"],
                \"description\": [\"New Department\"]
            }
        )

        result = await api.create_entry(session, entry)
    \"\"\"
```

#### modify_entry()

```python
async def modify_entry(
    self,
    session_id: str,
    dn: str,
    modifications: Dict[str, Any]
) -> FlextResult[bool]:
    \"\"\"Modify existing LDAP entry.

    Args:
        session_id: Active session ID
        dn: Distinguished name of entry to modify
        modifications: Dictionary of attribute modifications

    Returns:
        FlextResult[bool]: Success or failure result
    \"\"\"
```

#### delete_entry()

```python
async def delete_entry(
    self,
    session_id: str,
    dn: str
) -> FlextResult[bool]:
    \"\"\"Delete LDAP entry.

    Args:
        session_id: Active session ID
        dn: Distinguished name of entry to delete

    Returns:
        FlextResult[bool]: Success or failure result
    \"\"\"
```

---

## 🏗️ Factory Function

### get_ldap_api()

```python
def get_ldap_api(config: FlextLdapSettings | None = None) -> FlextLdapApi:
    \"\"\"Factory function to create FlextLdapApi instance.

    Args:
        config: Optional configuration. Uses default if None.

    Returns:
        FlextLdapApi: Configured API instance

    Example:
        # Use default configuration
        api = get_ldap_api()

        # Use custom configuration
        settings = FlextLdapSettings(server_url=\"ldap://custom.com\")
        api = get_ldap_api(config=settings)
    \"\"\"
```

---

## 🎯 Domain Entities

### FlextLdapUser

```python
@dataclass
class FlextLdapUser:
    \"\"\"LDAP user domain entity with business logic.

    Attributes:
        id: Unique identifier
        dn: Distinguished name
        uid: User identifier
        cn: Common name (full name)
        sn: Surname (last name)
        mail: Email address (optional)
        attributes: Additional LDAP attributes
        object_classes: LDAP object classes
    \"\"\"

    id: str
    dn: str
    uid: str
    cn: str
    sn: str
    mail: str | None = None
    attributes: Dict[str, List[str]] = field(default_factory=dict)
    object_classes: List[str] = field(default_factory=lambda: [\"person\", \"organizationalPerson\", \"inetOrgPerson\"])

    @property
    def display_name(self) -> str:
        \"\"\"Get display name for user.\"\"\"
        return self.cn or f\"{self.uid}\"

    @property
    def email(self) -> str | None:
        \"\"\"Get email address.\"\"\"
        return self.mail

    def is_valid(self) -> bool:
        \"\"\"Validate user data according to business rules.\"\"\"
        return bool(self.dn and self.uid and self.cn and self.sn)

    def get_attribute(self, name: str) -> List[str]:
        \"\"\"Get LDAP attribute values.\"\"\"
        return self.attributes.get(name, [])

    def set_attribute(self, name: str, values: List[str]) -> None:
        \"\"\"Set LDAP attribute values.\"\"\"
        self.attributes[name] = values
```

### FlextLdapGroup

```python
@dataclass
class FlextLdapGroup:
    \"\"\"LDAP group domain entity with membership management.

    Attributes:
        id: Unique identifier
        dn: Distinguished name
        cn: Common name (group name)
        members: List of member DNs
        description: Group description (optional)
        attributes: Additional LDAP attributes
        object_classes: LDAP object classes
    \"\"\"

    id: str
    dn: str
    cn: str
    members: List[str] = field(default_factory=list)
    description: str | None = None
    attributes: Dict[str, List[str]] = field(default_factory=dict)
    object_classes: List[str] = field(default_factory=lambda: [\"group\"])

    def add_member(self, member_dn: str) -> None:
        \"\"\"Add member to group with business rules.\"\"\"
        if member_dn not in self.members:
            self.members.append(member_dn)

    def remove_member(self, member_dn: str) -> None:
        \"\"\"Remove member from group with business rules.\"\"\"
        if member_dn in self.members:
            self.members.remove(member_dn)

    def has_member(self, member_dn: str) -> bool:
        \"\"\"Check if DN is a member of this group.\"\"\"
        return member_dn in self.members

    @property
    def member_count(self) -> int:
        \"\"\"Get number of group members.\"\"\"
        return len(self.members)
```

### FlextLdapEntry

```python
@dataclass
class FlextLdapEntry:
    \"\"\"Generic LDAP entry entity.

    Attributes:
        dn: Distinguished name
        object_classes: LDAP object classes
        attributes: LDAP attributes dictionary
    \"\"\"

    dn: str
    object_classes: List[str]
    attributes: Dict[str, List[str]] = field(default_factory=dict)

    def get_attribute(self, name: str) -> List[str]:
        \"\"\"Get attribute values.\"\"\"
        return self.attributes.get(name, [])

    def get_single_attribute(self, name: str) -> str | None:
        \"\"\"Get single attribute value (first value).\"\"\"
        values = self.get_attribute(name)
        return values[0] if values else None

    def set_attribute(self, name: str, values: List[str]) -> None:
        \"\"\"Set attribute values.\"\"\"
        self.attributes[name] = values

    def add_attribute_value(self, name: str, value: str) -> None:
        \"\"\"Add value to existing attribute.\"\"\"
        if name not in self.attributes:
            self.attributes[name] = []
        if value not in self.attributes[name]:
            self.attributes[name].append(value)
```

---

## 💎 Value Objects

### FlextLdapDistinguishedName

```python
@dataclass(frozen=True)
class FlextLdapDistinguishedName:
    \"\"\"Distinguished Name value object with RFC 4514 validation.

    Attributes:
        value: DN string value
    \"\"\"

    value: str

    def __post_init__(self) -> None:
        if not self._is_valid_dn(self.value):
            raise ValueError(f\"Invalid DN format: {self.value}\")

    def _is_valid_dn(self, dn: str) -> bool:
        \"\"\"Validate DN format according to RFC 4514.\"\"\"
        return bool(dn and '=' in dn and len(dn.strip()) > 0)

    @property
    def rdn(self) -> str:
        \"\"\"Get Relative Distinguished Name (first component).\"\"\"
        return self.value.split(',')[0].strip()

    @property
    def parent_dn(self) -> str | None:
        \"\"\"Get parent DN (all components except first).\"\"\"
        components = self.value.split(',')
        if len(components) <= 1:
            return None
        return ','.join(components[1:]).strip()

    def is_child_of(self, parent_dn: str) -> bool:
        \"\"\"Check if this DN is a child of parent DN.\"\"\"
        return self.value.lower().endswith(parent_dn.lower())
```

### FlextLdapFilterValue

```python
@dataclass(frozen=True)
class FlextLdapFilterValue:
    \"\"\"LDAP filter value object with RFC 4515 validation.

    Attributes:
        value: Filter string value
    \"\"\"

    value: str

    def __post_init__(self) -> None:
        if not self._is_valid_filter(self.value):
            raise ValueError(f\"Invalid LDAP filter: {self.value}\")

    def _is_valid_filter(self, filter_str: str) -> bool:
        \"\"\"Basic LDAP filter validation.\"\"\"
        return bool(
            filter_str and
            filter_str.startswith('(') and
            filter_str.endswith(')')
        )

    @classmethod
    def equals(cls, attribute: str, value: str) -> 'FlextLdapFilterValue':
        \"\"\"Create equality filter.\"\"\"
        return cls(f\"({attribute}={value})\")

    @classmethod
    def present(cls, attribute: str) -> 'FlextLdapFilterValue':
        \"\"\"Create presence filter.\"\"\"
        return cls(f\"({attribute}=*)\")

    @classmethod
    def and_filters(cls, *filters: 'FlextLdapFilterValue') -> 'FlextLdapFilterValue':
        \"\"\"Combine filters with AND logic.\"\"\"
        filter_strings = [f.value for f in filters]
        return cls(f\"(&{''.join(filter_strings)})\")

    @classmethod
    def or_filters(cls, *filters: 'FlextLdapFilterValue') -> 'FlextLdapFilterValue':
        \"\"\"Combine filters with OR logic.\"\"\"
        filter_strings = [f.value for f in filters]
        return cls(f\"(|{''.join(filter_strings)})\")
```

### FlextLdapScopeEnum

```python
class FlextLdapScopeEnum(Enum):
    \"\"\"LDAP search scope enumeration.

    Values:
        BASE: Search only the base entry
        ONELEVEL: Search immediate children only
        SUBTREE: Search entire subtree
    \"\"\"

    BASE = \"base\"
    ONELEVEL = \"onelevel\"
    SUBTREE = \"subtree\"
```

---

## 📝 Request/Response Objects

### FlextLdapCreateUserRequest

```python
@dataclass
class FlextLdapCreateUserRequest:
    \"\"\"Request object for user creation with validation.

    Attributes:
        dn: Distinguished name for new user
        uid: User identifier
        cn: Common name (full name)
        sn: Surname (last name)
        mail: Email address (optional)
        additional_attributes: Extra LDAP attributes
    \"\"\"

    dn: str
    uid: str
    cn: str
    sn: str
    mail: str | None = None
    additional_attributes: Dict[str, List[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        \"\"\"Validate request data.\"\"\"
        if not self.dn:
            raise ValueError(\"DN is required for user creation\")
        if not self.uid:
            raise ValueError(\"UID is required for user creation\")
        if not self.cn:
            raise ValueError(\"Common name is required for user creation\")
        if not self.sn:
            raise ValueError(\"Surname is required for user creation\")
```

### FlextLdapCreateGroupRequest

```python
@dataclass
class FlextLdapCreateGroupRequest:
    \"\"\"Request object for group creation with validation.

    Attributes:
        dn: Distinguished name for new group
        cn: Common name (group name)
        description: Group description (optional)
        members: Initial group members (optional)
        additional_attributes: Extra LDAP attributes
    \"\"\"

    dn: str
    cn: str
    description: str | None = None
    members: List[str] = field(default_factory=list)
    additional_attributes: Dict[str, List[str]] = field(default_factory=dict)
```

---

## ⚙️ Configuration

### FlextLdapSettings

```python
class FlextLdapSettings(FlextConfig):
    \"\"\"FLEXT-LDAP configuration with environment variable support.

    All settings can be overridden via environment variables with
    FLEXT_LDAP_ prefix (e.g., FLEXT_LDAP_SERVER_URL).
    \"\"\"

    # Connection settings
    server_url: str = \"ldap://localhost\"
    port: int = 389
    use_ssl: bool = False
    bind_dn: str = \"\"
    bind_password: SecretStr = SecretStr(\"\")

    # Search settings
    base_dn: str = \"dc=example,dc=com\"
    timeout: int = 30
    page_size: int = 1000

    # Connection pool settings
    pool_size: int = 10
    max_connections: int = 20
    connection_timeout: int = 30

    # Integration settings
    enable_metrics: bool = True
    enable_tracing: bool = True
    enable_connection_logging: bool = False

    class Config:
        env_prefix = \"FLEXT_LDAP_\"
        env_file = \".env\"
        case_sensitive = False
```

---

## 🔄 Result Types

### FlextResult Pattern

All API operations return `FlextResult<T>` for type-safe error handling:

```python
# Success case
result: FlextResult[FlextLdapUser] = await api.get_user(session, dn)

if result.success:
    user: FlextLdapUser = result.data
    print(f\"Found user: {user.display_name}\")
else:
    error: str = result.error
    print(f\"Error: {error}\")

# Chaining operations
result = await api.find_user_by_uid(session, \"jane.doe\")
if result.success:
    user = result.data
    update_result = await api.update_user(session, user.dn, {\"title\": \"Senior Developer\"})
    if update_result.success:
        print(\"User updated successfully\")
```

### Error Handling

Common error types returned in FlextResult.error:

- **Connection Errors**: \"Failed to connect to LDAP server\"
- **Authentication Errors**: \"LDAP bind failed\"
- **Not Found Errors**: \"User with UID 'john.doe' not found\"
- **Validation Errors**: \"Invalid DN format\"
- **Permission Errors**: \"Insufficient privileges for operation\"
- **Infrastructure Errors**: \"LDAP server unavailable\"

---

## 📋 Usage Examples

### Complete User Management Example

```python
from flext_ldap import get_ldap_api, FlextLdapCreateUserRequest

async def complete_user_management_example():
    \"\"\"Complete example of user management operations.\"\"\"

    api = get_ldap_api()

    # Establish connection
    async with api.connection(
        \"ldap://directory.company.com\",
        \"cn=admin,dc=company,dc=com\",
        \"admin_password\"
    ) as session:

        # 1. Create new user
        user_request = FlextLdapCreateUserRequest(
            dn=\"uid=jane.doe,ou=users,dc=company,dc=com\",
            uid=\"jane.doe\",
            cn=\"Jane Doe\",
            sn=\"Doe\",
            mail=\"jane.doe@company.com\"
        )

        create_result = await api.create_user(session, user_request)
        if not create_result.success:
            print(f\"Failed to create user: {create_result.error}\")
            return

        print(f\"Created user: {create_result.data.dn}\")

        # 2. Search for users
        search_result = await api.search_users(
            session,
            \"ou=users,dc=company,dc=com\",
            \"(cn=*Doe*)\"
        )

        if search_result.success:
            print(f\"Found {len(search_result.data)} users with 'Doe' in name\")

        # 3. Update user
        update_result = await api.update_user(
            session,
            \"uid=jane.doe,ou=users,dc=company,dc=com\",
            {
                \"title\": \"Senior Software Developer\",
                \"telephoneNumber\": \"+1-555-123-4567\"
            }
        )

        if update_result.success:
            print(\"User updated successfully\")

        # 4. Find user by UID
        find_result = await api.find_user_by_uid(session, \"jane.doe\")
        if find_result.success:
            user = find_result.data
            print(f\"Found user: {user.display_name} ({user.email})\")
```

### Group Management Example

```python
async def group_management_example():
    \"\"\"Example of group management operations.\"\"\"

    api = get_ldap_api()

    async with api.connection(...) as session:

        # Create group
        group_request = FlextLdapCreateGroupRequest(
            dn=\"cn=developers,ou=groups,dc=company,dc=com\",
            cn=\"developers\",
            description=\"Software Development Team\"
        )

        result = await api.create_group(session, group_request)

        # Add members to group
        await api.add_group_member(
            session,
            \"cn=developers,ou=groups,dc=company,dc=com\",
            \"uid=jane.doe,ou=users,dc=company,dc=com\"
        )
```

---

_This API reference is part of the FLEXT-LDAP documentation and follows FLEXT Framework API documentation standards._
