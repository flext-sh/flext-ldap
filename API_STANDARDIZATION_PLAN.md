# LDAP Core Shared - API Standardization Plan

## 🎯 **Executive Summary**

This document outlines a comprehensive API standardization plan to improve the LDAP Core Shared library's usability while maintaining maximum functionality. The current codebase shows excellent architectural design but needs standardization to achieve optimal simplicity and consistency.

## 🔍 **Current State Analysis**

### **Strengths to Preserve:**

- ✅ Excellent semantic API design in `api.py`
- ✅ Comprehensive exception hierarchy with structured error handling
- ✅ Strong type safety with Pydantic and type hints
- ✅ Well-organized module structure
- ✅ Lazy import system for performance
- ✅ Enterprise-grade features (connection pooling, vectorized operations)

### **Critical Standardization Issues:**

- 🚨 Inconsistent parameter naming across modules
- 🚨 Mixed return type patterns (direct vs wrapped results)
- 🚨 Multiple configuration interfaces for similar purposes
- 🚨 Inconsistent error handling approaches

## 🎯 **Standardization Objectives**

### **Primary Goals:**

1. **Unified API Patterns** - Consistent interfaces across all modules
2. **Simplified Configuration** - Single, intuitive configuration system
3. **Predictable Returns** - Consistent, structured return types
4. **Enhanced Type Safety** - Complete type coverage with validation
5. **Backward Compatibility** - Preserve existing functionality

### **Success Metrics:**

- 🎯 **100% API Consistency** - All operations follow same patterns
- 🎯 **Zero Breaking Changes** - Complete backward compatibility
- 🎯 **<30 Second Learning Curve** - New developers productive immediately
- 🎯 **Universal Error Handling** - Consistent error patterns throughout

## 📋 **Phase 1: Foundation Standardization (Priority: Critical)**

### **1.1 Unified Parameter Naming Convention**

#### **Current Inconsistencies:**

```python
# BEFORE - Inconsistent naming
LDAP.connect_to(server, username, password)           # api.py
LDAPConnectionConfig(host, bind_dn, password)         # domain/models.py
ConnectionInfo(host, port, bind_dn, bind_password)    # core/connection_manager.py
```

#### **Proposed Standard:**

```python
# AFTER - Unified naming convention
class StandardConnectionParams:
    server_url: str              # Always full URL or hostname
    authentication_dn: str       # Always bind DN for authentication
    authentication_password: str # Always password for authentication
    base_search_dn: str         # Always base DN for operations
    use_encryption: bool         # Always SSL/TLS usage
    verify_certificates: bool    # Always certificate validation
    connection_timeout: int      # Always timeout in seconds

class StandardSearchParams:
    search_base: str            # Always base DN for search
    search_filter: str          # Always LDAP filter expression
    search_scope: str           # Always: base, onelevel, subtree
    return_attributes: list     # Always attributes to return
    result_limit: int           # Always max results (0 = unlimited)
```

### **1.2 Unified Return Type Patterns**

#### **Current Inconsistencies:**

```python
# BEFORE - Mixed return patterns
async def find_users() -> list[LDAPEntry]                    # Direct list
async def search() -> LDAPOperationResult[list[LDAPEntry]]   # Wrapped result
def get_config() -> ApplicationConfig                        # Direct object
```

#### **Proposed Standard:**

```python
# AFTER - Consistent operation results
class LDAPOperationResult[T](BaseModel, Generic[T]):
    success: bool
    data: T
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    context: dict[str, Any] = Field(default_factory=dict)
    execution_time_ms: float
    metadata: dict[str, Any] = Field(default_factory=dict)

# ALL operations return structured results
async def find_users() -> LDAPOperationResult[list[LDAPEntry]]
async def test_connection() -> LDAPOperationResult[bool]
async def create_user() -> LDAPOperationResult[str]  # Returns DN
```

### **1.3 Unified Configuration Interface**

#### **Current Multiple Patterns:**

```python
# BEFORE - Three different configuration approaches
ServerConfig(host, port, use_ssl)              # api.py - Semantic
LDAPConnectionConfig(server_url, use_ssl)      # domain/models.py - Traditional
ApplicationConfig(...)                         # core/config.py - Enterprise
```

#### **Proposed Unified Interface:**

```python
# AFTER - Single configuration system with builder pattern
class LDAPConfiguration:
    """Unified configuration interface for all LDAP operations."""

    @classmethod
    def builder() -> 'LDAPConfigurationBuilder':
        """Create configuration builder for fluent interface."""
        return LDAPConfigurationBuilder()

    def for_server(self, url: str) -> 'LDAPConfiguration':
        """Configure server connection."""
        return self

    def with_authentication(self, dn: str, password: str) -> 'LDAPConfiguration':
        """Configure authentication credentials."""
        return self

    def with_search_base(self, base_dn: str) -> 'LDAPConfiguration':
        """Configure default search base."""
        return self

    def with_encryption(self, enabled: bool = True, verify_certs: bool = True) -> 'LDAPConfiguration':
        """Configure encryption settings."""
        return self

    def with_timeout(self, seconds: int) -> 'LDAPConfiguration':
        """Configure connection timeout."""
        return self

    def with_pooling(self, pool_size: int = 5, max_pool_size: int = 20) -> 'LDAPConfiguration':
        """Configure connection pooling."""
        return self

    def build() -> 'LDAPConnectionSettings':
        """Build final configuration object."""
        return LDAPConnectionSettings(...)

# Usage examples
config = (LDAPConfiguration.builder()
    .for_server("ldaps://ldap.company.com:636")
    .with_authentication("cn=admin,dc=company,dc=com", "secret")
    .with_search_base("dc=company,dc=com")
    .with_encryption(enabled=True, verify_certs=True)
    .with_timeout(30)
    .with_pooling(pool_size=10)
    .build())
```

## 📋 **Phase 2: API Harmonization (Priority: High)**

### **2.1 Standardized Method Signatures**

#### **Current Inconsistencies:**

```python
# BEFORE - Inconsistent async/sync patterns
async def find_users(in_location=None, with_filter=None, limit=0)
def search_entries(base_dn, filter_expr, attributes=None)
async def process_ldif(file_path, validate=True, batch_size=1000)
```

#### **Proposed Standard:**

```python
# AFTER - Consistent patterns with keyword-only arguments
class StandardLDAPOperations:
    """Standardized LDAP operations interface."""

    async def search_entries_async(
        self,
        *,
        search_base: str,
        filter_expression: str,
        return_attributes: Optional[list[str]] = None,
        scope: str = "subtree",
        result_limit: int = 0,
        timeout: Optional[int] = None
    ) -> LDAPOperationResult[list[LDAPEntry]]:
        """Asynchronous entry search with standardized parameters."""

    def search_entries_sync(
        self,
        *,
        search_base: str,
        filter_expression: str,
        return_attributes: Optional[list[str]] = None,
        scope: str = "subtree",
        result_limit: int = 0,
        timeout: Optional[int] = None
    ) -> LDAPOperationResult[list[LDAPEntry]]:
        """Synchronous entry search with standardized parameters."""

    async def create_entry_async(
        self,
        *,
        entry_dn: str,
        attributes: dict[str, Union[str, list[str]]],
        validate_schema: bool = True
    ) -> LDAPOperationResult[str]:
        """Asynchronous entry creation."""

    async def modify_entry_async(
        self,
        *,
        entry_dn: str,
        modifications: dict[str, Any],
        create_if_missing: bool = False
    ) -> LDAPOperationResult[bool]:
        """Asynchronous entry modification."""
```

### **2.2 Enhanced Error Handling Standardization**

#### **Current Mixed Approaches:**

```python
# BEFORE - Different exception patterns
raise ConnectionError(f"Failed to connect: {e}")                    # Basic string
raise LDAPCoreError(message, severity=ErrorSeverity.CRITICAL)       # Structured
```

#### **Proposed Standard:**

```python
# AFTER - Consistent structured errors
class StandardLDAPError(LDAPCoreError):
    """Standard LDAP error with consistent structure."""

    def __init__(
        self,
        message: str,
        *,
        error_code: Optional[str] = None,
        operation: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
        original_error: Optional[Exception] = None,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        category: ErrorCategory = ErrorCategory.SYSTEM,
        user_message: Optional[str] = None,
        recovery_suggestions: Optional[list[str]] = None
    ):
        super().__init__(
            message=message,
            error_code=error_code,
            severity=severity,
            category=category,
            context=context,
            cause=original_error,
            user_message=user_message
        )
        self.operation = operation
        self.recovery_suggestions = recovery_suggestions or []

# Consistent error raising pattern
def _handle_operation_error(operation: str, error: Exception) -> NoReturn:
    """Standardized error handling for all operations."""
    raise StandardLDAPError(
        message=f"Operation '{operation}' failed: {error}",
        operation=operation,
        original_error=error,
        context={"timestamp": datetime.now().isoformat()},
        recovery_suggestions=[
            "Check connection parameters",
            "Verify authentication credentials",
            "Ensure server is reachable"
        ]
    )
```

## 📋 **Phase 3: Enhanced API Features (Priority: Medium)**

### **3.1 Fluent Interface Design**

```python
# NEW - Fluent interface for complex operations
class FluentLDAPQuery:
    """Fluent interface for building LDAP queries."""

    def __init__(self, connection: LDAPConnection):
        self._connection = connection
        self._search_base: Optional[str] = None
        self._filter_parts: list[str] = []
        self._attributes: list[str] = []
        self._scope: str = "subtree"
        self._limit: int = 0

    def in_location(self, base_dn: str) -> 'FluentLDAPQuery':
        """Set search base location."""
        self._search_base = base_dn
        return self

    def where(self, filter_expr: str) -> 'FluentLDAPQuery':
        """Add filter condition."""
        self._filter_parts.append(filter_expr)
        return self

    def and_where(self, filter_expr: str) -> 'FluentLDAPQuery':
        """Add AND filter condition."""
        return self.where(filter_expr)

    def or_where(self, filter_expr: str) -> 'FluentLDAPQuery':
        """Add OR filter condition (requires grouping)."""
        # Implementation handles OR logic properly
        return self

    def select(self, *attributes: str) -> 'FluentLDAPQuery':
        """Specify attributes to return."""
        self._attributes.extend(attributes)
        return self

    def limit(self, count: int) -> 'FluentLDAPQuery':
        """Limit results count."""
        self._limit = count
        return self

    def scope(self, search_scope: str) -> 'FluentLDAPQuery':
        """Set search scope."""
        self._scope = search_scope
        return self

    async def execute(self) -> LDAPOperationResult[list[LDAPEntry]]:
        """Execute the query."""
        # Build final filter from parts
        final_filter = "(&" + "".join(self._filter_parts) + ")" if len(self._filter_parts) > 1 else self._filter_parts[0]

        return await self._connection.search_entries_async(
            search_base=self._search_base or await self._connection.get_default_search_base(),
            filter_expression=final_filter,
            return_attributes=self._attributes or None,
            scope=self._scope,
            result_limit=self._limit
        )

# Usage examples
users = await (ldap.query()
    .in_location("ou=users,dc=company,dc=com")
    .where("(objectClass=person)")
    .and_where("(department=IT)")
    .select("cn", "mail", "department")
    .limit(100)
    .execute())

groups = await (ldap.query()
    .in_location("ou=groups,dc=company,dc=com")
    .where("(objectClass=group)")
    .or_where("(objectClass=groupOfNames)")
    .select("cn", "member")
    .execute())
```

### **3.2 Context Manager Enhancements**

```python
# ENHANCED - Context managers for resource management
class LDAPSession:
    """Enhanced context manager for LDAP operations."""

    async def __aenter__(self) -> 'LDAPSession':
        """Enter async context with connection setup."""
        await self._establish_connection()
        await self._setup_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit async context with proper cleanup."""
        await self._cleanup_session()
        await self._close_connection()

    async def _setup_session(self) -> None:
        """Setup session-specific configurations."""
        # Configure session logging
        # Set up performance monitoring
        # Initialize security context

    async def _cleanup_session(self) -> None:
        """Clean up session resources."""
        # Flush any pending operations
        # Log session statistics
        # Clean up temporary resources

# Usage
async with LDAPSession.create(config) as session:
    users = await session.find_users()
    for user in users.data:
        groups = await session.find_groups_for_user(user.get_attribute("cn"))
        # Session automatically manages connections and cleanup
```

### **3.3 Semantic Helper Methods**

```python
# NEW - Domain-specific helper methods
class SemanticLDAPOperations:
    """Semantic, domain-specific LDAP operations."""

    async def find_users_by_department(
        self,
        department: str,
        *,
        include_disabled: bool = False,
        additional_filters: Optional[list[str]] = None
    ) -> LDAPOperationResult[list[LDAPEntry]]:
        """Find users in specific department."""

    async def find_user_by_email(self, email: str) -> LDAPOperationResult[Optional[LDAPEntry]]:
        """Find user by email address."""

    async def get_user_groups(self, username: str) -> LDAPOperationResult[list[LDAPEntry]]:
        """Get all groups for a specific user."""

    async def is_user_in_group(self, username: str, group_name: str) -> LDAPOperationResult[bool]:
        """Check if user is member of specific group."""

    async def find_empty_groups(self) -> LDAPOperationResult[list[LDAPEntry]]:
        """Find groups with no members."""

    async def find_inactive_users(self, days: int = 90) -> LDAPOperationResult[list[LDAPEntry]]:
        """Find users inactive for specified days."""

    async def get_directory_statistics(self) -> LDAPOperationResult[dict[str, int]]:
        """Get comprehensive directory statistics."""
        return LDAPOperationResult(
            success=True,
            data={
                "total_users": await self._count_objects("(objectClass=person)"),
                "total_groups": await self._count_objects("(objectClass=group)"),
                "total_computers": await self._count_objects("(objectClass=computer)"),
                "enabled_users": await self._count_objects("(&(objectClass=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"),
                "empty_groups": len((await self.find_empty_groups()).data)
            },
            execution_time_ms=self._get_execution_time()
        )
```

## 📋 **Phase 4: Implementation Strategy**

### **4.1 Backward Compatibility Approach**

```python
# STRATEGY - Dual interface support during transition
class LDAPConnection:
    """Main LDAP connection class with both old and new interfaces."""

    # NEW standardized interface
    async def search_entries_async(self, *, search_base: str, **kwargs) -> LDAPOperationResult[list[LDAPEntry]]:
        """New standardized search method."""

    # OLD interface with deprecation warning
    async def search(self, base_dn: str, filter_expr: str, **kwargs) -> list[LDAPEntry]:
        """Legacy search method - DEPRECATED."""
        import warnings
        warnings.warn(
            "search() is deprecated, use search_entries_async() instead",
            DeprecationWarning,
            stacklevel=2
        )
        result = await self.search_entries_async(
            search_base=base_dn,
            filter_expression=filter_expr,
            **kwargs
        )
        return result.data if result.success else []
```

### **4.2 Migration Timeline**

#### **Phase 1 (Weeks 1-2): Foundation**

- [ ] Implement unified return types (`LDAPOperationResult`)
- [ ] Create standardized configuration builder
- [ ] Establish consistent parameter naming

#### **Phase 2 (Weeks 3-4): API Harmonization**

- [ ] Update all public methods to use new patterns
- [ ] Implement dual interface support
- [ ] Add deprecation warnings for old patterns

#### **Phase 3 (Weeks 5-6): Enhanced Features**

- [ ] Implement fluent interface
- [ ] Add semantic helper methods
- [ ] Enhanced context managers

#### **Phase 4 (Weeks 7-8): Finalization**

- [ ] Complete documentation updates
- [ ] Comprehensive testing
- [ ] Performance validation

### **4.3 Testing Strategy**

```python
# COMPREHENSIVE - Test both old and new interfaces
class TestAPIStandardization:
    """Test suite ensuring backward compatibility and new functionality."""

    async def test_backward_compatibility(self):
        """Ensure all old interfaces still work."""
        # Test legacy LDAP.connect_to()
        # Test legacy quick_search()
        # Test legacy configuration classes

    async def test_new_standardized_interfaces(self):
        """Validate new standardized interfaces."""
        # Test LDAPOperationResult patterns
        # Test unified configuration builder
        # Test consistent parameter naming

    async def test_fluent_interface(self):
        """Test fluent query building."""
        # Test method chaining
        # Test complex query construction
        # Test query execution

    async def test_semantic_operations(self):
        """Test domain-specific operations."""
        # Test find_users_by_department()
        # Test get_user_groups()
        # Test directory statistics
```

## 🎯 **Expected Outcomes**

### **Immediate Benefits:**

- ✅ **100% API Consistency** - All operations follow identical patterns
- ✅ **Simplified Learning Curve** - New developers productive in minutes
- ✅ **Enhanced Type Safety** - Complete type coverage with validation
- ✅ **Better Error Handling** - Consistent, actionable error information

### **Long-term Benefits:**

- 🚀 **Increased Adoption** - Easier to use APIs drive broader adoption
- 🛡️ **Reduced Support Burden** - Consistent APIs reduce support questions
- ⚡ **Faster Development** - Predictable patterns accelerate development
- 📈 **Enhanced Maintainability** - Standardized code easier to maintain

### **Compatibility Guarantee:**

- ✅ **Zero Breaking Changes** - All existing code continues to work
- ✅ **Gradual Migration Path** - Deprecation warnings guide users to new APIs
- ✅ **Documentation Support** - Complete migration guides and examples

## 📚 **Migration Examples**

### **Example 1: Basic Connection and Search**

```python
# BEFORE - Current API
ldap = LDAP.connect_to("server.com", "admin", "secret")
users = await ldap.find_users(in_location="ou=people")

# AFTER - Standardized API (both work!)
# Option 1: Enhanced semantic API (recommended)
config = (LDAPConfiguration.builder()
    .for_server("ldap://server.com")
    .with_authentication("cn=admin,dc=company,dc=com", "secret")
    .with_search_base("dc=company,dc=com")
    .build())

async with LDAPSession.create(config) as session:
    result = await session.find_users_by_location("ou=people")
    if result.success:
        users = result.data

# Option 2: Fluent interface
users = await (session.query()
    .in_location("ou=people,dc=company,dc=com")
    .where("(objectClass=person)")
    .select("cn", "mail", "department")
    .execute())
```

### **Example 2: Complex Operations**

```python
# BEFORE - Multiple API calls with manual error handling
try:
    ldap = LDAP.connect_to("server.com", "admin", "secret")
    user = await ldap.find_user_by_name("john.doe")
    if user:
        groups = await ldap.find_groups_for_user("john.doe")
except Exception as e:
    print(f"Error: {e}")

# AFTER - Standardized with structured results
async with LDAPSession.create(config) as session:
    user_result = await session.find_user_by_email("john.doe@company.com")
    if user_result.success and user_result.data:
        groups_result = await session.get_user_groups(user_result.data.get_attribute("cn"))
        if groups_result.success:
            print(f"User {user_result.data.dn} is in {len(groups_result.data)} groups")
        else:
            print(f"Failed to get groups: {groups_result.error_message}")
            print(f"Recovery suggestions: {groups_result.metadata.get('recovery_suggestions', [])}")
```

## 🔚 **Conclusion**

This API standardization plan transforms the LDAP Core Shared library from an excellent but complex system into a simple, intuitive, and powerful tool that maintains all enterprise capabilities while dramatically improving usability.

The phased approach ensures zero disruption to existing users while providing a clear migration path to enhanced functionality. The result will be a library that combines maximum functionality with minimum complexity - the ideal combination for widespread adoption and long-term success.
