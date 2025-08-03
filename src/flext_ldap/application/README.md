# Application Layer - FLEXT-LDAP

The application layer orchestrates domain objects and coordinates use cases, implementing Command Query Responsibility Segregation (CQRS) patterns and application services.

## Architecture Principles

This layer serves as the orchestration hub:
- **Use case implementation**: Business workflow coordination
- **Domain orchestration**: Coordinates multiple domain entities
- **Infrastructure coordination**: Manages external system interactions
- **Transaction boundaries**: Defines consistency and transaction scopes

## Module Structure

```
application/
├── __init__.py           # Application layer exports
├── ldap_service.py       # Main LDAP application service
├── handlers/             # Command and query handlers (CQRS)
│   ├── __init__.py
│   ├── user_handlers.py  # User-specific command handlers
│   └── group_handlers.py # Group-specific command handlers
└── commands/             # Application command definitions
    ├── __init__.py
    ├── user_commands.py  # User management commands
    └── group_commands.py # Group management commands
```

## Application Services

### FlextLdapService
Main application service coordinating LDAP operations:

```python
class FlextLdapService:
    """Application service orchestrating LDAP operations."""
    
    async def create_user(self, request: FlextLdapCreateUserRequest) -> FlextResult[FlextLdapUser]:
        """Create user with complete business logic validation."""
        
    async def find_user_by_uid(self, uid: str) -> FlextResult[FlextLdapUser]:
        """Find user by UID with domain entity conversion."""
        
    async def update_user(self, user_id: str, updates: dict) -> FlextResult[FlextLdapUser]:
        """Update user with business rule validation."""
```

Key responsibilities:
- **Connection management**: LDAP session lifecycle
- **Domain coordination**: Orchestrates domain entities and business rules
- **Error handling**: Converts infrastructure errors to domain errors
- **Transaction management**: Ensures data consistency

## CQRS Implementation

### Command Pattern
Commands represent user intentions to change system state:

```python
@dataclass
class CreateUserCommand(FlextLdapCommand):
    """Command to create new LDAP user."""
    uid: str
    cn: str
    sn: str
    mail: Optional[str] = None
    department: Optional[str] = None
```

### Command Handlers
Process commands and coordinate domain operations:

```python
class CreateUserHandler(FlextLdapCommandHandler[CreateUserCommand, FlextLdapUser]):
    """Handler for user creation commands."""
    
    async def handle(self, command: CreateUserCommand) -> FlextResult[FlextLdapUser]:
        """Process user creation with domain validation."""
```

### Query Handlers
Handle read operations and data retrieval:

```python
class FindUserByUidHandler(FlextLdapQueryHandler[FindUserByUidQuery, FlextLdapUser]):
    """Handler for user lookup queries."""
    
    async def handle(self, query: FindUserByUidQuery) -> FlextResult[FlextLdapUser]:
        """Process user lookup with optimization."""
```

## Use Case Patterns

### Railway-Oriented Programming
All operations use FlextResult for consistent error handling:

```python
async def create_user_workflow(self, command: CreateUserCommand) -> FlextResult[FlextLdapUser]:
    """Complete user creation workflow."""
    return (
        self._validate_user_data(command)
        .flat_map(lambda data: self._check_user_uniqueness(data))
        .flat_map_async(lambda data: self._create_domain_user(data))
        .flat_map_async(lambda user: self._save_user(user))
        .map_async(lambda user: self._notify_user_created(user))
    )
```

### Transaction Management
Application services define transaction boundaries:

```python
async def transfer_user_between_groups(
    self, 
    user_id: str, 
    from_group: str, 
    to_group: str
) -> FlextResult[bool]:
    """Transfer user between groups as single transaction."""
    async with self._transaction_scope():
        return (
            self._remove_user_from_group(user_id, from_group)
            .flat_map_async(lambda _: self._add_user_to_group(user_id, to_group))
        )
```

## Integration Patterns

### Domain Layer Integration
Application services coordinate domain entities:

```python
async def activate_user_with_email_notification(
    self, 
    user_id: str
) -> FlextResult[FlextLdapUser]:
    """Activate user and send notification."""
    
    # Get domain entity
    user_result = await self._user_repository.find_by_id(user_id)
    if user_result.is_failure:
        return user_result
    
    # Execute domain logic
    activation_result = user_result.data.activate()
    if activation_result.is_failure:
        return FlextResult.fail(activation_result.error)
    
    # Persist changes
    save_result = await self._user_repository.save(user_result.data)
    if save_result.is_failure:
        return save_result
    
    # Handle side effects
    await self._notification_service.send_activation_email(user_result.data)
    
    return save_result
```

### Infrastructure Integration
Application services abstract infrastructure complexity:

```python
async def search_users_with_pagination(
    self,
    filter_criteria: dict,
    page_size: int = 100,
    page_token: Optional[str] = None
) -> FlextResult[PaginatedResult[FlextLdapUser]]:
    """Search users with pagination and caching."""
    
    # Convert application request to infrastructure format
    ldap_filter = self._build_ldap_filter(filter_criteria)
    
    # Execute infrastructure operation
    search_result = await self._ldap_client.search_with_pagination(
        base_dn=self._config.base_dn,
        filter_expr=ldap_filter,
        page_size=page_size,
        page_token=page_token
    )
    
    # Convert to domain entities
    return search_result.map(lambda results: self._convert_to_domain_entities(results))
```

## Error Handling Strategy

### Layered Error Mapping
Application services map infrastructure errors to domain errors:

```python
async def _handle_ldap_operation_error(self, error: Exception) -> FlextResult[None]:
    """Map LDAP infrastructure errors to domain errors."""
    if isinstance(error, LDAPConnectionError):
        return FlextResult.fail("LDAP server unavailable")
    elif isinstance(error, LDAPInvalidDNError):
        return FlextResult.fail("Invalid distinguished name format")
    elif isinstance(error, LDAPEntryAlreadyExistsError):
        return FlextResult.fail("User already exists")
    else:
        logger.exception("Unexpected LDAP error", error=error)
        return FlextResult.fail("Internal LDAP operation failed")
```

### Validation Pipeline
Multi-stage validation with clear error reporting:

```python
def _validate_user_creation_request(
    self, 
    request: CreateUserCommand
) -> FlextResult[CreateUserCommand]:
    """Validate user creation with detailed error reporting."""
    
    errors = []
    
    # Business rule validation
    if not request.uid or len(request.uid) < 3:
        errors.append("User ID must be at least 3 characters")
    
    # Format validation
    if request.mail and '@' not in request.mail:
        errors.append("Invalid email format")
    
    # Domain validation
    if request.department and request.department not in VALID_DEPARTMENTS:
        errors.append(f"Invalid department: {request.department}")
    
    return FlextResult.fail(errors) if errors else FlextResult.ok(request)
```

## Testing Strategies

### Unit Testing
Test application logic in isolation:

```python
@pytest.mark.asyncio
async def test_create_user_success_path():
    """Test successful user creation workflow."""
    # Arrange
    service = FlextLdapService(mock_repositories)
    command = CreateUserCommand(uid="test", cn="Test User", sn="User")
    
    # Act
    result = await service.create_user(command)
    
    # Assert
    assert result.is_success
    assert result.data.uid == "test"
```

### Integration Testing
Test coordination with real infrastructure:

```python
@pytest.mark.integration
async def test_user_creation_with_real_ldap():
    """Test user creation with real LDAP server."""
    async with ldap_test_server():
        service = FlextLdapService(real_repositories)
        result = await service.create_user(valid_command)
        assert result.is_success
```

This application layer provides a clean interface for external consumers while maintaining proper separation of concerns and enabling comprehensive testing strategies.