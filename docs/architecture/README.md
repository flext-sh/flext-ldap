# FLEXT-LDAP Architecture Overview

**Clean Architecture + Domain-Driven Design Implementation**

FLEXT-LDAP implements Clean Architecture principles with Domain-Driven Design patterns, built on the FLEXT-Core foundation. This document provides an overview of the system architecture, design decisions, and integration patterns.

---

## 🏛️ Architectural Principles

### Clean Architecture Foundation

FLEXT-LDAP follows Clean Architecture principles with clear separation of concerns:

1. **Independence of Frameworks**: Business logic doesn't depend on external frameworks
2. **Testability**: Business rules can be tested without UI, database, or external elements
3. **Independence of UI**: UI layer can change without affecting business rules
4. **Independence of Database**: Business rules don't know about persistence mechanisms
5. **Independence of External Agencies**: Business rules don't know about external interfaces

### Domain-Driven Design Integration

- **Ubiquitous Language**: Consistent terminology across all layers
- **Bounded Contexts**: Clear boundaries between different business domains
- **Domain Events**: Business events that drive system behavior
- **Aggregates**: Consistency boundaries for business operations

---

## 🏗️ System Architecture

### Layer Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                        Application Layer                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   FLEXT-LDAP   │  │   flext-auth    │  │  flext-meltano  │ │
│  │      API       │  │  Integration    │  │  Integration    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                      Interface Adapters                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Directory     │  │    Singer       │  │      CLI        │ │
│  │    Adapter      │  │    Adapter      │  │    Interface    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                       Application Layer                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   LDAP Service  │  │  Command/Query  │  │   Event         │ │
│  │   Orchestration │  │    Handlers     │  │   Handlers      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                         Domain Layer                           │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │    Entities     │  │  Value Objects  │  │   Domain        │ │
│  │   Aggregates    │  │  Specifications │  │   Services      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                     Infrastructure Layer                       │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   LDAP Client   │  │   Repositories  │  │   External      │ │
│  │   (ldap3)       │  │ Implementation  │  │   Services      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                          FLEXT-Core                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   FlextResult   │  │  FlextContainer │  │ FlextLDAPConfig │ │
│  │    Pattern      │  │  (DI Container) │  │  (Centralized)  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Domain Model

### Core Entities

#### FlextLDAPUser

```python
@dataclass
class FlextLDAPUser:
    \"\"\"LDAP user entity with business logic.\"\"\"
    id: str
    dn: str  # Distinguished Name
    uid: str
    cn: str  # Common Name
    sn: str  # Surname
    mail: Optional[str]

    def is_valid(self) -> bool:
        \"\"\"Domain validation logic.\"\"\"
        return bool(self.dn and self.uid and self.cn and self.sn)

    def get_display_name(self) -> str:
        \"\"\"Business logic for display name.\"\"\"
        return self.cn or f\"{self.uid}\"
```

#### FlextLDAPGroup

```python
@dataclass
class FlextLDAPGroup:
    \"\"\"LDAP group aggregate with membership management.\"\"\"
    id: str
    dn: str
    cn: str
    members: List[str]  # DNs of members

    def add_member(self, member_dn: str) -> None:
        \"\"\"Add member with business rules.\"\"\"
        if member_dn not in self.members:
            self.members.append(member_dn)

    def remove_member(self, member_dn: str) -> None:
        \"\"\"Remove member with business rules.\"\"\"
        if member_dn in self.members:
            self.members.remove(member_dn)
```

### Value Objects

#### FlextLDAPDistinguishedName

```python
@dataclass(frozen=True)
class FlextLDAPDistinguishedName:
    \"\"\"Distinguished Name value object with validation.\"\"\"
    value: str

    def __post_init__(self) -> None:
        if not self._is_valid_dn(self.value):
            raise ValueError(f\"Invalid DN format: {self.value}\")

    def _is_valid_dn(self, dn: str) -> bool:
        \"\"\"Validate DN format according to RFC 4514.\"\"\"
        # Implementation of DN validation logic
        return bool(dn and '=' in dn)
```

### Domain Services

#### FlextLDAPUserValidator

```python
class FlextLDAPUserValidator:
    \"\"\"Domain service for complex user validation.\"\"\"

    def validate_user_creation(self, user: FlextLDAPUser) -> FlextResult[bool]:
        \"\"\"Validate user creation according to business rules.\"\"\"
        if not user.is_valid():
            return FlextResult[None].fail(\"User data is invalid\")

        if self._is_duplicate_uid(user.uid):
            return FlextResult[None].fail(f\"UID {user.uid} already exists\")

        return FlextResult[None].ok(data=True)
```

---

## 🔄 Application Layer

### Application Services

#### FlextLDAPService

```python
class FlextLDAPService:
    \"\"\"Application service orchestrating LDAP operations.\"\"\"

    def __init__(
        self,
        user_repository: FlextLDAPUserRepository,
        validator: FlextLDAPUserValidator,
        event_publisher: FlextEventPublisher
    ):
        self._user_repository = user_repository
        self._validator = validator
        self._event_publisher = event_publisher

    async def create_user(
        self,
        request: CreateUserRequest
    ) -> FlextResult[FlextLDAPUser]:
        \"\"\"Create user with complete business logic.\"\"\"

        # 1. Create domain entity
        user = FlextLDAPUser.from_request(request)

        # 2. Domain validation
        validation_result = self._validator.validate_user_creation(user)
        if validation_result.is_failure:
            return FlextResult[None].fail(validation_result.error)

        # 3. Persist entity
        save_result = await self._user_repository.save(user)
        if save_result.is_failure:
            return FlextResult[None].fail(save_result.error)

        # 4. Publish domain event
        await self._event_publisher.publish(
            UserCreatedEvent(user_id=user.id, dn=user.dn)
        )

        return FlextResult[None].ok(user)
```

### Command/Query Handlers (CQRS)

#### Commands

```python
@dataclass
class CreateUserCommand:
    \"\"\"Command to create a new user.\"\"\"
    dn: str
    uid: str
    cn: str
    sn: str
    mail: Optional[str] = None

class CreateUserHandler:
    \"\"\"Handler for user creation command.\"\"\"

    def __init__(self, ldap_service: FlextLDAPService):
        self._ldap_service = ldap_service

    async def handle(self, command: CreateUserCommand) -> FlextResult[FlextLDAPUser]:
        return await self._ldap_service.create_user(command)
```

#### Queries

```python
@dataclass
class FindUserByUidQuery:
    \"\"\"Query to find user by UID.\"\"\"
    uid: str

class FindUserByUidHandler:
    \"\"\"Handler for user lookup query.\"\"\"

    def __init__(self, user_repository: FlextLDAPUserRepository):
        self._user_repository = user_repository

    async def handle(self, query: FindUserByUidQuery) -> FlextResult[FlextLDAPUser]:
        return await self._user_repository.get_by_uid(query.uid)
```

---

## 🔌 Infrastructure Layer

### Repository Implementation

```python
class FlextLDAPUserRepositoryImpl(FlextLDAPUserRepository):
    \"\"\"Infrastructure implementation of user repository.\"\"\"

    def __init__(self, ldap_client: FlextLDAPClient):
        self._ldap_client = ldap_client

    async def save(self, user: FlextLDAPUser) -> FlextResult[FlextLDAPUser]:
        \"\"\"Save user to LDAP directory.\"\"\"
        try:
            # Convert domain entity to LDAP entry
            entry_data = self._to_ldap_entry(user)

            # Use infrastructure client
            result = await self._ldap_client.add_entry(
                dn=user.dn,
                attributes=entry_data
            )

            if result.success:
                return FlextResult[None].ok(user)
            else:
                return FlextResult[None].fail(f\"Failed to save user: {result.error}\")

        except Exception as e:
            return FlextResult[None].fail(f\"Infrastructure error: {str(e)}\")

    def _to_ldap_entry(self, user: FlextLDAPUser) -> Dict[str, object]:
        \"\"\"Convert domain entity to LDAP entry format.\"\"\"
        return {
            \"objectClass\": [\"person\", \"organizationalPerson\", \"inetOrgPerson\"],
            \"uid\": user.uid,
            \"cn\": user.cn,
            \"sn\": user.sn,
            \"mail\": user.mail
        }
```

### LDAP Client Implementation

```python
class FlextLDAPClient:
    \"\"\"Infrastructure LDAP client using ldap3.\"\"\"

    def __init__(self, connection_config: FlextLDAPConnectionConfig):
        self._config = connection_config
        self._connection: Optional[Connection] = None

    async def connect(self) -> FlextResult[str]:
        \"\"\"Establish LDAP connection.\"\"\"
        try:
            server = Server(
                self._config.server_url,
                port=self._config.port,
                use_ssl=self._config.use_ssl
            )

            self._connection = Connection(
                server,
                user=self._config.bind_dn,
                password=self._config.bind_password.get_secret_value(),
                auto_bind=AUTO_BIND_NONE
            )

            if self._connection.bind():
                connection_id = str(uuid4())
                return FlextResult[None].ok(connection_id)
            else:
                return FlextResult[None].fail(\"LDAP bind failed\")

        except LDAPException as e:
            return FlextResult[None].fail(f\"LDAP connection error: {str(e)}\")
```

---

## 🎨 Design Patterns

### Repository Pattern

- **Interface**: Abstract repository definitions in domain layer
- **Implementation**: Concrete implementations in infrastructure layer
- **Benefits**: Testability, flexibility, separation of concerns

### Factory Pattern

```python
class FlextLDAPUserFactory:
    \"\"\"Factory for creating user entities with validation.\"\"\"

    @staticmethod
    def create_from_ldap_entry(entry: Dict[str, object]) -> FlextResult[FlextLDAPUser]:
        \"\"\"Create user entity from LDAP entry data.\"\"\"
        try:
            user = FlextLDAPUser(
                id=str(uuid4()),
                dn=entry.get(\"dn\", \"\"),
                uid=entry.get(\"uid\", [\"\"])[0],
                cn=entry.get(\"cn\", [\"\"])[0],
                sn=entry.get(\"sn\", [\"\"])[0],
                mail=entry.get(\"mail\", [None])[0]
            )

            if user.is_valid():
                return FlextResult[None].ok(user)
            else:
                return FlextResult[None].fail(\"Invalid user data from LDAP entry\")

        except Exception as e:
            return FlextResult[None].fail(f\"Factory error: {str(e)}\")
```

### Service Pattern

- **Domain Services**: Complex business logic that doesn't fit in entities
- **Application Services**: Orchestrate use cases and coordinate domain objects
- **Infrastructure Services**: Handle external system integration

---

## 🔗 FLEXT-Core Integration

### FlextResult Pattern

All operations return `FlextResult<T>` for type-safe error handling:

```python
# Success case
result = FlextResult[None].ok(user)
if result.success:
    user = result.data

# Failure case
result = FlextResult[None].fail(\"User not found\")
if result.is_failure:
    error = result.error
```

### Dependency Injection

Uses FlextContainer for service orchestration:

```python
# Container configuration
container = FlextContainer.get_global()
container.register(FlextLDAPUserRepository, FlextLDAPUserRepositoryImpl)
container.register(FlextLDAPUserValidator, FlextLDAPUserValidator)

# Service resolution
user_service = container.resolve(FlextLDAPService)
```

### Configuration Management

Centralized configuration via FlextLDAPConfig:

```python
# Configuration class
@dataclass
class FlextLDAPSettings(FlextConfig):
    \"\"\"LDAP configuration with validation.\"\"\"
    server_url: str
    port: int = 389
    use_ssl: bool = False
    bind_dn: str
    bind_password: SecretStr

    class Config:
        env_prefix = \"FLEXT_LDAP_\"
```

---

## 📊 Quality Attributes

### Performance

- **Async Operations**: Non-blocking I/O with asyncio
- **Connection Pooling**: Efficient LDAP connection management
- **Caching**: Strategic caching of frequently accessed data
- **Lazy Loading**: Load data only when needed

### Scalability

- **Stateless Design**: No server-side state for horizontal scaling
- **Resource Management**: Proper connection and memory management
- **Load Distribution**: Support for multiple LDAP servers

### Reliability

- **Error Handling**: Comprehensive error handling with FlextResult
- **Retry Logic**: Automatic retry for transient failures
- **Circuit Breaker**: Prevent cascade failures
- **Health Checks**: Built-in health monitoring

### Security

- **Secure Connections**: TLS/SSL support for LDAP connections
- **Credential Management**: Secure handling of authentication credentials
- **Input Validation**: Comprehensive input validation and sanitization
- **Audit Logging**: Security event logging and monitoring

---

## 🔄 Event-Driven Architecture

### Domain Events

```python
@dataclass
class UserCreatedEvent:
    \"\"\"Domain event for user creation.\"\"\"
    user_id: str
    dn: str
    timestamp: datetime

@dataclass
class UserModifiedEvent:
    \"\"\"Domain event for user modification.\"\"\"
    user_id: str
    dn: str
    changes: Dict[str, object]
    timestamp: datetime
```

### Event Handlers

```python
class UserCreatedHandler:
    \"\"\"Handle user creation events.\"\"\"

    async def handle(self, event: UserCreatedEvent) -> None:
        # Send notification
        # Update audit log
        # Trigger downstream processes
        pass
```

---

## 📈 Future Architecture Evolution

### Planned Enhancements

1. **Event Sourcing**: Complete event sourcing for audit and replay
2. **CQRS Optimization**: Separate read/write models for performance
3. **Microservices**: Break into smaller, focused services
4. **GraphQL**: Add GraphQL layer for flexible querying
5. **Real-time**: WebSocket support for real-time updates

### Migration Strategy

- **Incremental**: Gradual migration maintaining backward compatibility
- **Feature Flags**: Use feature flags for safe rollout
- **Parallel Systems**: Run old and new systems in parallel during transition
- **Data Migration**: Automated data migration with validation

---

_This architecture documentation is part of the FLEXT-LDAP project and follows FLEXT Framework architectural standards._
