# Patterns Layer - FLEXT-LDAP

The patterns layer provides reusable design patterns and cross-cutting concerns specifically tailored for LDAP operations, implementing enterprise-grade patterns for authentication, authorization, and operational consistency.

## Architecture Principles

This layer provides reusable patterns:

- **Cross-cutting concerns**: Authentication, authorization, logging, caching
- **Design pattern implementations**: Strategy, Template Method, Chain of Responsibility
- **Operational patterns**: Retry, Circuit Breaker, Bulkhead
- **Security patterns**: Authentication flows, permission checking

## Module Structure

```
patterns/
├── __init__.py           # Pattern exports
├── auth_patterns.py      # Authentication and authorization patterns
├── retry_patterns.py     # Retry and resilience patterns (planned)
├── cache_patterns.py     # Caching strategy patterns (planned)
└── security_patterns.py # Security implementation patterns (planned)
```

## Authentication Patterns

### FlextLdapAuthMixin

Mixin providing authentication capabilities to services:

```python
class FlextLdapAuthMixin:
    """Mixin providing LDAP authentication patterns."""

    async def authenticate_user(
        self,
        username: str,
        password: str,
        base_dn: Optional[str] = None
    ) -> FlextResult[FlextLdapUser]:
        """Authenticate user against LDAP directory."""

    async def validate_session(
        self,
        session_id: str
    ) -> FlextResult[SessionInfo]:
        """Validate active session."""

    def require_authentication(self, operation: str) -> Callable:
        """Decorator requiring authentication for operations."""
```

### Authentication Strategy Pattern

```python
class FlextLdapAuthStrategy(ABC):
    """Abstract base for authentication strategies."""

    @abstractmethod
    async def authenticate(
        self,
        credentials: AuthCredentials
    ) -> FlextResult[AuthResult]:
        """Authenticate using specific strategy."""

class SimpleBindAuthStrategy(FlextLdapAuthStrategy):
    """Simple bind authentication strategy."""

    async def authenticate(
        self,
        credentials: AuthCredentials
    ) -> FlextResult[AuthResult]:
        """Authenticate using simple LDAP bind."""

class SaslAuthStrategy(FlextLdapAuthStrategy):
    """SASL authentication strategy."""

    async def authenticate(
        self,
        credentials: AuthCredentials
    ) -> FlextResult[AuthResult]:
        """Authenticate using SASL mechanism."""
```

### Authentication Context Manager

```python
@asynccontextmanager
async def authenticated_session(
    self,
    credentials: AuthCredentials,
    auth_strategy: FlextLdapAuthStrategy
) -> AsyncIterator[AuthenticatedSession]:
    """Context manager for authenticated LDAP sessions."""

    # Authenticate
    auth_result = await auth_strategy.authenticate(credentials)
    if auth_result.is_failure:
        raise AuthenticationError(auth_result.error)

    session = AuthenticatedSession(
        user=auth_result.data.user,
        permissions=auth_result.data.permissions,
        session_id=str(uuid4())
    )

    try:
        yield session
    finally:
        await self._cleanup_session(session)
```

## Authorization Patterns

### Permission-Based Authorization

```python
class FlextLdapPermissionChecker:
    """Permission checking for LDAP operations."""

    def __init__(self, user: FlextLdapUser):
        self._user = user
        self._permissions = self._load_user_permissions(user)

    def can_read(self, target_dn: str) -> bool:
        """Check if user can read target entry."""

    def can_write(self, target_dn: str) -> bool:
        """Check if user can modify target entry."""

    def can_delete(self, target_dn: str) -> bool:
        """Check if user can delete target entry."""

    def can_search(self, base_dn: str, scope: str) -> bool:
        """Check if user can search in specified scope."""
```

### Role-Based Access Control (RBAC)

```python
class FlextLdapRoleBasedAuth:
    """Role-based access control for LDAP operations."""

    def __init__(self, role_repository: FlextLdapRoleRepository):
        self._role_repository = role_repository

    async def check_role_permission(
        self,
        user: FlextLdapUser,
        operation: str,
        resource: str
    ) -> FlextResult[bool]:
        """Check if user's roles permit operation on resource."""

        user_roles = await self._role_repository.get_user_roles(user.dn)
        if user_roles.is_failure:
            return FlextResult.fail("Failed to retrieve user roles")

        for role in user_roles.data:
            if await self._role_has_permission(role, operation, resource):
                return FlextResult.ok(True)

        return FlextResult.ok(False)
```

### Authorization Decorator Pattern

```python
def require_permission(
    permission: str,
    resource_extractor: Optional[Callable] = None
) -> Callable:
    """Decorator requiring specific permission for operation."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract current user from context
            current_user = get_current_user()
            if not current_user:
                return FlextResult.fail("Authentication required")

            # Extract resource identifier
            resource = resource_extractor(*args, **kwargs) if resource_extractor else None

            # Check permission
            permission_checker = FlextLdapPermissionChecker(current_user)
            if not permission_checker.has_permission(permission, resource):
                return FlextResult.fail(f"Permission denied: {permission}")

            # Execute original function
            return await func(*args, **kwargs)

        return wrapper
    return decorator

# Usage example
class FlextLdapSecureService:
    @require_permission("ldap:user:read", lambda self, user_dn: user_dn)
    async def get_user(self, user_dn: str) -> FlextResult[FlextLdapUser]:
        """Get user with permission checking."""
```

## Retry and Resilience Patterns

### Retry Pattern with Exponential Backoff

```python
class FlextLdapRetryPattern:
    """Retry pattern for LDAP operations."""

    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0
    ):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base

    async def execute_with_retry(
        self,
        operation: Callable[[], Awaitable[FlextResult[T]]],
        should_retry: Callable[[Exception], bool] = None
    ) -> FlextResult[T]:
        """Execute operation with retry logic."""

        last_error = None

        for attempt in range(self.max_attempts):
            try:
                result = await operation()
                if result.is_success:
                    return result

                # Check if we should retry based on error
                if should_retry and not should_retry(Exception(result.error)):
                    return result

                last_error = result.error

            except Exception as e:
                last_error = str(e)

                # Check if we should retry this exception
                if should_retry and not should_retry(e):
                    return FlextResult.fail(str(e))

            # Calculate delay for next attempt
            if attempt < self.max_attempts - 1:  # Don't delay after last attempt
                delay = min(
                    self.base_delay * (self.exponential_base ** attempt),
                    self.max_delay
                )
                await asyncio.sleep(delay)

        return FlextResult.fail(f"Operation failed after {self.max_attempts} attempts: {last_error}")
```

### Circuit Breaker Pattern

```python
class FlextLdapCircuitBreaker:
    """Circuit breaker pattern for LDAP operations."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: Type[Exception] = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception

        self._failure_count = 0
        self._last_failure_time = None
        self._state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    async def call(
        self,
        operation: Callable[[], Awaitable[FlextResult[T]]]
    ) -> FlextResult[T]:
        """Execute operation through circuit breaker."""

        if self._state == "OPEN":
            if self._should_attempt_reset():
                self._state = "HALF_OPEN"
            else:
                return FlextResult.fail("Circuit breaker is OPEN")

        try:
            result = await operation()

            if result.is_success:
                self._on_success()
                return result
            else:
                self._on_failure()
                return result

        except self.expected_exception as e:
            self._on_failure()
            return FlextResult.fail(f"Circuit breaker caught exception: {e}")

    def _should_attempt_reset(self) -> bool:
        """Check if circuit breaker should attempt reset."""
        return (
            self._last_failure_time and
            time.time() - self._last_failure_time >= self.recovery_timeout
        )

    def _on_success(self) -> None:
        """Handle successful operation."""
        self._failure_count = 0
        self._state = "CLOSED"

    def _on_failure(self) -> None:
        """Handle failed operation."""
        self._failure_count += 1
        self._last_failure_time = time.time()

        if self._failure_count >= self.failure_threshold:
            self._state = "OPEN"
```

## Caching Patterns

### Cache-Aside Pattern

```python
class FlextLdapCacheAside:
    """Cache-aside pattern for LDAP operations."""

    def __init__(self, cache: FlextLdapCache, ttl: int = 300):
        self._cache = cache
        self._ttl = ttl

    async def get_or_fetch(
        self,
        key: str,
        fetch_operation: Callable[[], Awaitable[FlextResult[T]]],
        serializer: Optional[Callable[[T], str]] = None,
        deserializer: Optional[Callable[[str], T]] = None
    ) -> FlextResult[T]:
        """Get from cache or fetch from source."""

        # Try cache first
        cached_result = await self._cache.get(key)
        if cached_result.is_success and cached_result.data is not None:
            if deserializer:
                return FlextResult.ok(deserializer(cached_result.data))
            return cached_result

        # Fetch from source
        fetch_result = await fetch_operation()
        if fetch_result.is_failure:
            return fetch_result

        # Cache the result
        cache_value = serializer(fetch_result.data) if serializer else fetch_result.data
        await self._cache.set(key, cache_value, self._ttl)

        return fetch_result
```

## Security Patterns

### Secure Session Management

```python
class FlextLdapSecureSessionManager:
    """Secure session management for LDAP operations."""

    def __init__(self, session_store: SessionStore, crypto: CryptoService):
        self._session_store = session_store
        self._crypto = crypto

    async def create_session(
        self,
        user: FlextLdapUser,
        ip_address: str,
        user_agent: str
    ) -> FlextResult[SecureSession]:
        """Create secure session with tracking."""

        session = SecureSession(
            id=self._generate_secure_session_id(),
            user_dn=user.dn,
            ip_address=ip_address,
            user_agent=user_agent,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=8)
        )

        # Store session securely
        encrypted_session = self._crypto.encrypt(session.to_dict())
        store_result = await self._session_store.store(session.id, encrypted_session)

        if store_result.is_failure:
            return FlextResult.fail("Failed to create session")

        return FlextResult.ok(session)

    async def validate_session(
        self,
        session_id: str,
        ip_address: str
    ) -> FlextResult[SecureSession]:
        """Validate session with security checks."""

        # Retrieve session
        session_result = await self._session_store.get(session_id)
        if session_result.is_failure:
            return FlextResult.fail("Invalid session")

        # Decrypt session
        decrypted_data = self._crypto.decrypt(session_result.data)
        session = SecureSession.from_dict(decrypted_data)

        # Validate session
        validation_result = self._validate_session_security(session, ip_address)
        if validation_result.is_failure:
            await self._session_store.delete(session_id)  # Invalidate compromised session
            return validation_result

        return FlextResult.ok(session)
```

## Usage Examples

### Combining Patterns

```python
class FlextLdapSecureService(FlextLdapAuthMixin):
    """Service combining multiple patterns."""

    def __init__(self, config: FlextLdapConfig):
        self._retry_pattern = FlextLdapRetryPattern(max_attempts=3)
        self._circuit_breaker = FlextLdapCircuitBreaker(failure_threshold=5)
        self._cache = FlextLdapCacheAside(cache=RedisCache(), ttl=300)

    @require_permission("ldap:user:read")
    async def get_user_with_resilience(
        self,
        user_dn: str
    ) -> FlextResult[FlextLdapUser]:
        """Get user with retry, circuit breaker, and caching."""

        cache_key = f"user:{user_dn}"

        return await self._cache.get_or_fetch(
            key=cache_key,
            fetch_operation=lambda: self._circuit_breaker.call(
                lambda: self._retry_pattern.execute_with_retry(
                    lambda: self._fetch_user_from_ldap(user_dn)
                )
            )
        )
```

This patterns layer provides reusable, battle-tested patterns that can be composed together to build robust, secure, and resilient LDAP operations with enterprise-grade reliability and security features.
