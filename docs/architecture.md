# FLEXT-LDAP Architecture

**Clean Architecture + Domain-Driven Design implementation for LDAP directory services**

This document describes the architectural patterns and design decisions in flext-ldap.

---

## 🏗️ Clean Architecture Overview

FLEXT-LDAP implements Clean Architecture principles with clear separation of concerns:

```
┌─────────────────────────────────────────────────┐
│                 Infrastructure                  │
│  ┌─────────────────────────────────────────┐    │
│  │              Application                │    │
│  │  ┌─────────────────────────────────┐    │    │
│  │  │            Domain               │    │    │
│  │  │  ┌─────────────────────────┐    │    │    │
│  │  │  │      Entities           │    │    │    │
│  │  │  │   Value Objects         │    │    │    │
│  │  │  └─────────────────────────┘    │    │    │
│  │  └─────────────────────────────────┘    │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

### **Layer Responsibilities**

**Domain Layer** (innermost):

- Entities: User, Group, Entry
- Value Objects: DistinguishedName, Filter, Scope
- Domain Services: Business logic and rules

**Application Layer**:

- Use Cases: LDAP operation orchestration
- Services: Application-specific logic
- DTOs: Data transfer objects

**Infrastructure Layer** (outermost):

- Repositories: Data access implementations
- Clients: External LDAP server communication
- Adapters: Framework and library integrations

---

## 🎯 Domain Model

### **Core Entities**

#### FlextLdapUser

```python
@dataclass
class FlextLdapUser:
    """LDAP user entity with business logic."""
    dn: str                    # Distinguished Name
    uid: str                   # User ID
    cn: str                    # Common Name
    sn: str                    # Surname
    mail: Optional[str]        # Email address
    member_of: List[str]       # Group memberships

    def is_valid(self) -> bool:
        """Validate user data according to business rules."""
        return bool(self.dn and self.uid and self.cn and self.sn)

    def get_groups(self) -> List[str]:
        """Extract group names from member_of DNs."""
        return [self._extract_cn_from_dn(dn) for dn in self.member_of]
```

#### FlextLdapGroup

```python
@dataclass
class FlextLdapGroup:
    """LDAP group entity with membership management."""
    dn: str                    # Distinguished Name
    cn: str                    # Common Name
    members: List[str]         # Member DNs
    description: Optional[str] # Group description

    def add_member(self, member_dn: str) -> None:
        """Add member with duplicate checking."""
        if member_dn not in self.members:
            self.members.append(member_dn)

    def remove_member(self, member_dn: str) -> None:
        """Remove member if present."""
        if member_dn in self.members:
            self.members.remove(member_dn)
```

### **Value Objects**

#### DistinguishedName

```python
@dataclass(frozen=True)
class DistinguishedName:
    """RFC 4514 compliant Distinguished Name."""
    value: str

    def __post_init__(self) -> None:
        if not self._is_valid_dn():
            raise ValueError(f"Invalid DN: {self.value}")

    @property
    def rdn(self) -> str:
        """Get Relative Distinguished Name (first component)."""
        return self.value.split(',')[0].strip()

    @property
    def parent_dn(self) -> str:
        """Get parent DN (all components except first)."""
        parts = self.value.split(',')[1:]
        return ','.join(part.strip() for part in parts)
```

#### LdapFilter

```python
@dataclass(frozen=True)
class LdapFilter:
    """LDAP search filter with validation."""
    expression: str

    def __post_init__(self) -> None:
        if not self._is_valid_filter():
            raise ValueError(f"Invalid LDAP filter: {self.expression}")

    @classmethod
    def equals(cls, attribute: str, value: str) -> 'LdapFilter':
        """Create equality filter."""
        return cls(f"({attribute}={value})")

    @classmethod
    def object_class(cls, object_class: str) -> 'LdapFilter':
        """Create objectClass filter."""
        return cls(f"(objectClass={object_class})")
```

---

## 🔄 Application Layer

### **API Facade**

The `FlextLdapClient` serves as the main entry point:

```python
class FlextLdapClient:
    """High-level LDAP API facade."""

    def __init__(self, config: FlextLdapConfig | None = None):
        self._config = config or get_flext_ldap_config()
        self._container = FlextLdapContainer().get_container()
        self._service = FlextLdapServices(self._container)

    async def search_entries(
        self,
        request: SearchRequest
    ) -> FlextResult[List[LdapEntry]]:
        """Search LDAP entries with FlextResult error handling."""
        return await self._service.search_entries(request)

    async def authenticate_user(
        self,
        username: str,
        password: str
    ) -> FlextResult[FlextLdapUser]:
        """Authenticate user credentials."""
        return await self._service.authenticate_user(username, password)
```

### **Application Services**

#### FlextLdapServices

Orchestrates domain operations:

```python
class FlextLdapServices:
    """Application services for LDAP operations."""

    def __init__(self, container: FlextContainer):
        self._container = container
        self._user_repo = container.resolve(FlextLdapUserRepository)
        self._group_repo = container.resolve(FlextLdapGroupRepository)

    async def create_user(
        self,
        request: CreateUserRequest
    ) -> FlextResult[FlextLdapUser]:
        """Create user with business validation."""
        # Domain validation
        user = self._create_user_entity(request)
        if not user.is_valid():
            return FlextResult.fail("Invalid user data")

        # Persistence
        return await self._user_repo.save(user)
```

---

## 🛠️ Infrastructure Layer

### **Repository Pattern**

Abstract repositories define contracts:

```python
class FlextLdapUserRepository(ABC):
    """Abstract user repository."""

    @abstractmethod
    async def find_by_uid(self, uid: str) -> FlextResult[FlextLdapUser]:
        """Find user by UID."""

    @abstractmethod
    async def save(self, user: FlextLdapUser) -> FlextResult[FlextLdapUser]:
        """Save user to directory."""
```

Concrete implementations handle LDAP specifics:

```python
class FlextLdapUserRepositoryImpl(FlextLdapUserRepository):
    """LDAP user repository implementation."""

    def __init__(self, client: FlextLdapClient):
        self._client = client

    async def find_by_uid(self, uid: str) -> FlextResult[FlextLdapUser]:
        """Find user by UID with error handling."""
        search_result = await self._client.search(
            base_dn=self._get_users_base_dn(),
            filter_str=f"(uid={uid})",
            attributes=["uid", "cn", "sn", "mail", "memberOf"]
        )

        if search_result.is_failure:
            return FlextResult.fail(search_result.error)

        entries = search_result.unwrap()
        if not entries:
            return FlextResult.fail(f"User {uid} not found")

        user = self._map_to_entity(entries[0])
        return FlextResult.ok(user)
```

### **LDAP Client Abstraction**

The `FlextLdapClient` abstracts ldap3 operations:

```python
class FlextLdapClient:
    """LDAP client abstraction over ldap3."""

    def __init__(self, config: FlextLdapConfig):
        self._config = config
        self._connection: Optional[Connection] = None

    async def connect(self) -> FlextResult[None]:
        """Establish LDAP connection."""
        try:
            server = Server(
                self._config.host,
                port=self._config.port,
                use_ssl=self._config.use_ssl
            )

            self._connection = Connection(
                server,
                user=self._config.bind_dn,
                password=self._config.bind_password,
                auto_bind=AUTO_BIND_TLS_BEFORE_BIND
            )

            return FlextResult.ok(None)
        except LDAPException as e:
            return FlextResult.fail(f"Connection failed: {e}")

    async def search(
        self,
        base_dn: str,
        filter_str: str,
        attributes: List[str]
    ) -> FlextResult[List[Dict]]:
        """Perform LDAP search operation."""
        if not self._connection or not self._connection.bound:
            connect_result = await self.connect()
            if connect_result.is_failure:
                return connect_result

        try:
            self._connection.search(
                search_base=base_dn,
                search_filter=filter_str,
                attributes=attributes
            )

            results = [entry.entry_attributes_as_dict
                      for entry in self._connection.entries]
            return FlextResult.ok(results)
        except LDAPException as e:
            return FlextResult.fail(f"Search failed: {e}")
```

---

## 🔗 FLEXT-Core Integration

### **FlextResult Pattern**

All operations use FlextResult for error handling:

```python
# Success case
user_result = await api.get_user("john.doe")
if user_result.is_success:
    user = user_result.unwrap()
    print(f"Found user: {user.cn}")

# Failure case
if user_result.is_failure:
    print(f"Error: {user_result.error}")
```

### **Dependency Injection**

Uses FlextContainer for service resolution:

```python
# Container configuration
container = FlextContainer()
container.register(FlextLdapClient, FlextLdapClient)
container.register(FlextLdapUserRepository, FlextLdapUserRepositoryImpl)

# Service resolution
user_service = container.resolve(FlextLdapUserService)
```

### **Configuration Management**

Centralized configuration via FlextLdapConfig:

```python
@dataclass
class FlextLdapConfig:
    """LDAP configuration with validation."""
    host: str
    port: int = 389
    use_ssl: bool = False
    bind_dn: str
    bind_password: str
    base_dn: str
    timeout: int = 30
    pool_size: int = 5
```

---

## 📊 Quality Attributes

### **Maintainability**

- Clear layer separation prevents tight coupling
- Domain logic isolated from infrastructure concerns
- Dependency injection enables easy testing and modification

### **Testability**

- Repository abstractions enable mock implementations
- Domain entities can be tested in isolation
- Clean boundaries facilitate unit testing

### **Scalability**

- Connection pooling for concurrent operations
- Async/await support for non-blocking I/O
- Stateless design enables horizontal scaling

### **Reliability**

- FlextResult pattern ensures explicit error handling
- Input validation at domain boundaries
- Connection retry and recovery mechanisms

---

## 🔮 Future Enhancements

### **Planned Improvements**

1. **Event Sourcing**: Add domain events for audit and integration
2. **CQRS**: Separate read/write models for performance
3. **Caching**: Redis integration for frequently accessed data
4. **Metrics**: Prometheus metrics for monitoring and alerting

### **Migration Strategy**

- Maintain backward compatibility during changes
- Use feature flags for gradual rollout
- Comprehensive integration tests for stability

---

**Next:** [API Reference](api-reference.md) →
