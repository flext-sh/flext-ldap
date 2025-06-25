# ADR-004: Comprehensive Error Handling Strategy

**Robust, informative, and actionable error handling for enterprise reliability**

## 📋 Status

**APPROVED** - High priority infrastructure decision

## 🎯 Context

Building on our foundation architecture ([ADR-001](001-foundation-architecture.md)), async design ([ADR-002](002-async-first-design.md)), and connection management ([ADR-003](003-connection-management.md)), we need a comprehensive error handling strategy that provides clear diagnostics, enables recovery, and maintains system stability under all conditions.

### 🔍 **Current Implementation Analysis**

Our existing codebase in `src/ldap_core_shared/` shows:

- ✅ **Good foundation**: `LDAPOperationResult` pattern for structured results
- ✅ **Domain exceptions**: Basic exception handling in domain layer
- ✅ **Performance tracking**: Error tracking in performance monitoring
- ❌ **Needs enhancement**: Comprehensive error taxonomy, recovery strategies, observability

### 🏆 **Error Handling Requirements from Research**

From analyzing enterprise systems and 57+ implementations:

- **Clear Error Taxonomy**: Structured, categorized exception hierarchy
- **Recovery Strategies**: Automatic retry, fallback, and graceful degradation
- **Observability**: Detailed error context and tracing
- **User Experience**: Actionable error messages and suggestions
- **System Stability**: Prevent cascading failures and resource leaks

## 🎯 Decision

**We will implement a comprehensive error handling system with a structured exception hierarchy, intelligent retry mechanisms, detailed error context, and recovery strategies that maintain system stability while providing excellent developer experience.**

### 🏗️ **Error Handling Architecture**

#### 1. **Structured Exception Hierarchy**

```python
from abc import ABC
from typing import Dict, Any, Optional, List
from enum import Enum
import traceback
from datetime import datetime

class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ErrorCategory(Enum):
    """Error categories for classification."""
    CONNECTION = "connection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    PROTOCOL = "protocol"
    TIMEOUT = "timeout"
    RESOURCE = "resource"
    CONFIGURATION = "configuration"
    NETWORK = "network"
    SERVER = "server"
    CLIENT = "client"
    DATA = "data"
    SCHEMA = "schema"
    LDIF = "ldif"

class LDAPError(Exception, ABC):
    """Base exception for all LDAP library errors."""

    def __init__(self,
                 message: str,
                 error_code: str = None,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 category: ErrorCategory = ErrorCategory.CLIENT,
                 details: Dict[str, Any] = None,
                 suggestions: List[str] = None,
                 recoverable: bool = True,
                 retry_after: Optional[float] = None):

        super().__init__(message)
        self.message = message
        self.error_code = error_code or self._generate_error_code()
        self.severity = severity
        self.category = category
        self.details = details or {}
        self.suggestions = suggestions or []
        self.recoverable = recoverable
        self.retry_after = retry_after
        self.timestamp = datetime.now()
        self.stack_trace = traceback.format_exc()

        # Add contextual information
        self.details.update({
            "error_class": self.__class__.__name__,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "category": self.category.value,
            "recoverable": self.recoverable
        })

    def _generate_error_code(self) -> str:
        """Generate unique error code."""
        return f"LDAP_{self.category.value.upper()}_{self.__class__.__name__.upper()}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for serialization."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "severity": self.severity.value,
            "category": self.category.value,
            "details": self.details,
            "suggestions": self.suggestions,
            "recoverable": self.recoverable,
            "retry_after": self.retry_after,
            "timestamp": self.timestamp.isoformat(),
            "stack_trace": self.stack_trace
        }

    def get_user_friendly_message(self) -> str:
        """Get user-friendly error message with suggestions."""
        message = f"{self.message}"

        if self.suggestions:
            message += f"\n\nSuggestions:\n"
            for i, suggestion in enumerate(self.suggestions, 1):
                message += f"{i}. {suggestion}\n"

        return message

# Connection-related errors
class ConnectionError(LDAPError):
    """Base class for connection-related errors."""

    def __init__(self, message: str, server_url: str = None, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.CONNECTION,
            **kwargs
        )
        if server_url:
            self.details["server_url"] = server_url

class ConnectionTimeoutError(ConnectionError):
    """Connection timeout error."""

    def __init__(self, timeout_duration: float, server_url: str = None):
        super().__init__(
            f"Connection timed out after {timeout_duration:.2f} seconds",
            server_url=server_url,
            severity=ErrorSeverity.HIGH,
            suggestions=[
                "Check network connectivity to the LDAP server",
                "Verify firewall settings",
                "Increase connection timeout value",
                "Try connecting to a different server"
            ],
            retry_after=5.0
        )
        self.details["timeout_duration"] = timeout_duration

class ConnectionPoolExhaustedError(ConnectionError):
    """Connection pool exhausted error."""

    def __init__(self, max_pool_size: int, active_connections: int):
        super().__init__(
            f"Connection pool exhausted (max: {max_pool_size}, active: {active_connections})",
            severity=ErrorSeverity.HIGH,
            suggestions=[
                "Increase maximum pool size",
                "Reduce connection acquisition timeout",
                "Check for connection leaks in application code",
                "Implement connection sharing patterns"
            ],
            retry_after=1.0
        )
        self.details.update({
            "max_pool_size": max_pool_size,
            "active_connections": active_connections
        })

class ServerUnavailableError(ConnectionError):
    """Server unavailable error."""

    def __init__(self, server_url: str, last_error: str = None):
        super().__init__(
            f"LDAP server {server_url} is unavailable",
            server_url=server_url,
            severity=ErrorSeverity.CRITICAL,
            suggestions=[
                "Check if LDAP server is running",
                "Verify server URL and port",
                "Check network connectivity",
                "Try failover server if available"
            ],
            retry_after=30.0
        )
        if last_error:
            self.details["last_error"] = last_error

# Authentication and Authorization errors
class AuthenticationError(LDAPError):
    """Base class for authentication errors."""

    def __init__(self, message: str, username: str = None, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.HIGH,
            recoverable=False,  # Usually not recoverable automatically
            **kwargs
        )
        if username:
            self.details["username"] = username

class InvalidCredentialsError(AuthenticationError):
    """Invalid credentials error."""

    def __init__(self, username: str = None):
        super().__init__(
            "Invalid username or password",
            username=username,
            suggestions=[
                "Verify username and password are correct",
                "Check if account is locked or disabled",
                "Verify account exists in LDAP directory",
                "Check password expiration policy"
            ]
        )

class InsufficientPermissionsError(LDAPError):
    """Insufficient permissions error."""

    def __init__(self, operation: str, dn: str = None, required_permission: str = None):
        super().__init__(
            f"Insufficient permissions to perform {operation}",
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.HIGH,
            recoverable=False,
            suggestions=[
                "Contact LDAP administrator for required permissions",
                "Verify user has appropriate access rights",
                "Check LDAP ACLs and permissions",
                "Use account with higher privileges"
            ]
        )
        self.details.update({
            "operation": operation,
            "dn": dn,
            "required_permission": required_permission
        })

# Validation and data errors
class ValidationError(LDAPError):
    """Base class for validation errors."""

    def __init__(self, message: str, field_name: str = None, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.VALIDATION,
            severity=ErrorSeverity.MEDIUM,
            recoverable=False,  # Requires user input correction
            **kwargs
        )
        if field_name:
            self.details["field_name"] = field_name

class InvalidDNError(ValidationError):
    """Invalid Distinguished Name error."""

    def __init__(self, dn: str, reason: str = None):
        super().__init__(
            f"Invalid Distinguished Name: {dn}",
            suggestions=[
                "Check DN syntax according to RFC 4514",
                "Verify attribute names are valid",
                "Ensure proper escaping of special characters",
                "Validate DN components and hierarchy"
            ]
        )
        self.details.update({
            "invalid_dn": dn,
            "reason": reason
        })

class SchemaViolationError(ValidationError):
    """Schema violation error."""

    def __init__(self, attribute: str, object_class: str, violation_type: str):
        super().__init__(
            f"Schema violation: {violation_type} for attribute '{attribute}' in object class '{object_class}'",
            field_name=attribute,
            suggestions=[
                "Check LDAP schema definition",
                "Verify attribute is allowed for object class",
                "Ensure required attributes are present",
                "Validate attribute value syntax"
            ]
        )
        self.details.update({
            "attribute": attribute,
            "object_class": object_class,
            "violation_type": violation_type
        })

# Protocol and server errors
class ProtocolError(LDAPError):
    """Base class for LDAP protocol errors."""

    def __init__(self, message: str, ldap_result_code: int = None, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.PROTOCOL,
            **kwargs
        )
        if ldap_result_code is not None:
            self.details["ldap_result_code"] = ldap_result_code

class SearchError(ProtocolError):
    """Search operation error."""

    def __init__(self, base_dn: str, filter_query: str, error_message: str):
        super().__init__(
            f"Search failed: {error_message}",
            suggestions=[
                "Verify search base DN exists",
                "Check search filter syntax",
                "Ensure user has read permissions",
                "Try with smaller scope or size limit"
            ]
        )
        self.details.update({
            "base_dn": base_dn,
            "filter_query": filter_query
        })

# LDIF processing errors
class LDIFError(LDAPError):
    """Base class for LDIF processing errors."""

    def __init__(self, message: str, line_number: int = None, **kwargs):
        super().__init__(
            message,
            category=ErrorCategory.LDIF,
            **kwargs
        )
        if line_number is not None:
            self.details["line_number"] = line_number

class LDIFParseError(LDIFError):
    """LDIF parsing error."""

    def __init__(self, line_number: int, line_content: str, parse_error: str):
        super().__init__(
            f"LDIF parse error at line {line_number}: {parse_error}",
            line_number=line_number,
            suggestions=[
                "Check LDIF syntax according to RFC 2849",
                "Verify line encoding and special characters",
                "Ensure proper attribute value formatting",
                "Check for missing or extra line breaks"
            ]
        )
        self.details.update({
            "line_content": line_content[:100],  # Truncate for safety
            "parse_error": parse_error
        })
```

#### 2. **Intelligent Retry Strategy**

```python
from typing import Callable, Type, Union
import asyncio
import random
from functools import wraps

class RetryPolicy:
    """Configurable retry policy for operations."""

    def __init__(self,
                 max_attempts: int = 3,
                 base_delay: float = 1.0,
                 max_delay: float = 60.0,
                 exponential_backoff: bool = True,
                 jitter: bool = True,
                 retryable_exceptions: List[Type[Exception]] = None):

        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_backoff = exponential_backoff
        self.jitter = jitter
        self.retryable_exceptions = retryable_exceptions or [
            ConnectionTimeoutError,
            ConnectionPoolExhaustedError,
            ServerUnavailableError
        ]

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt."""
        if self.exponential_backoff:
            delay = self.base_delay * (2 ** (attempt - 1))
        else:
            delay = self.base_delay

        # Apply maximum delay limit
        delay = min(delay, self.max_delay)

        # Add jitter to prevent thundering herd
        if self.jitter:
            delay = delay * (0.5 + random.random() * 0.5)

        return delay

    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Determine if operation should be retried."""
        if attempt >= self.max_attempts:
            return False

        # Check if exception is retryable
        for retryable_type in self.retryable_exceptions:
            if isinstance(exception, retryable_type):
                # Check if exception has specific retry guidance
                if hasattr(exception, 'recoverable') and not exception.recoverable:
                    return False
                return True

        return False

class RetryableOperation:
    """Wrapper for retryable operations with comprehensive error handling."""

    def __init__(self, retry_policy: RetryPolicy = None):
        self.retry_policy = retry_policy or RetryPolicy()
        self.error_history: List[Exception] = []

    async def execute(self, operation: Callable, *args, **kwargs) -> Any:
        """Execute operation with retry logic."""
        last_exception = None

        for attempt in range(1, self.retry_policy.max_attempts + 1):
            try:
                # Clear error history on successful retry
                if attempt > 1:
                    self.error_history.clear()

                result = await operation(*args, **kwargs)

                # Log successful retry if previous attempts failed
                if attempt > 1:
                    logger.info(f"Operation succeeded on attempt {attempt} after {len(self.error_history)} failures")

                return result

            except Exception as e:
                last_exception = e
                self.error_history.append(e)

                # Log the error
                logger.warning(f"Operation failed on attempt {attempt}/{self.retry_policy.max_attempts}: {e}")

                # Check if we should retry
                if not self.retry_policy.should_retry(e, attempt):
                    break

                # Calculate and apply delay
                if attempt < self.retry_policy.max_attempts:
                    delay = self.retry_policy.calculate_delay(attempt)
                    logger.debug(f"Retrying in {delay:.2f} seconds...")
                    await asyncio.sleep(delay)

        # All retries exhausted, raise aggregated error
        raise self._create_aggregated_error(last_exception)

    def _create_aggregated_error(self, last_exception: Exception) -> Exception:
        """Create aggregated error with retry history."""
        if isinstance(last_exception, LDAPError):
            # Enhance LDAP error with retry information
            last_exception.details["retry_attempts"] = len(self.error_history)
            last_exception.details["error_history"] = [
                str(e) for e in self.error_history
            ]
            return last_exception
        else:
            # Wrap non-LDAP errors
            return LDAPError(
                message=f"Operation failed after {len(self.error_history)} attempts: {str(last_exception)}",
                details={
                    "retry_attempts": len(self.error_history),
                    "error_history": [str(e) for e in self.error_history],
                    "original_error": str(last_exception),
                    "original_error_type": type(last_exception).__name__
                }
            )

def retry_on_error(retry_policy: RetryPolicy = None):
    """Decorator for automatic retry on errors."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            retryable_op = RetryableOperation(retry_policy)
            return await retryable_op.execute(func, *args, **kwargs)
        return wrapper
    return decorator
```

#### 3. **Error Context and Observability**

```python
import contextvars
from typing import Optional
import uuid

# Context variables for error tracing
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar('request_id')
operation_stack_var: contextvars.ContextVar[List[str]] = contextvars.ContextVar('operation_stack', default=[])

class ErrorContext:
    """Context manager for tracking error context."""

    def __init__(self, operation_name: str, **context_data):
        self.operation_name = operation_name
        self.context_data = context_data
        self.request_id = request_id_var.get(str(uuid.uuid4()))
        self.start_time = datetime.now()

    def __enter__(self):
        # Set request ID if not already set
        if not request_id_var.get(None):
            request_id_var.set(self.request_id)

        # Add operation to stack
        stack = operation_stack_var.get([])
        stack.append(self.operation_name)
        operation_stack_var.set(stack)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Remove operation from stack
        stack = operation_stack_var.get([])
        if stack and stack[-1] == self.operation_name:
            stack.pop()
            operation_stack_var.set(stack)

        # Enhance exception with context if one occurred
        if exc_val and isinstance(exc_val, LDAPError):
            exc_val.details.update({
                "request_id": self.request_id,
                "operation_stack": operation_stack_var.get([]),
                "operation_duration": (datetime.now() - self.start_time).total_seconds(),
                **self.context_data
            })

        return False  # Don't suppress exceptions

class ErrorReporter:
    """Centralized error reporting and monitoring."""

    def __init__(self):
        self.error_handlers: List[Callable[[Exception], None]] = []
        self.error_stats = ErrorStatistics()

    def add_error_handler(self, handler: Callable[[Exception], None]) -> None:
        """Add custom error handler."""
        self.error_handlers.append(handler)

    def report_error(self, error: Exception, context: Dict[str, Any] = None) -> None:
        """Report error to all registered handlers."""
        # Update statistics
        self.error_stats.record_error(error)

        # Call all error handlers
        for handler in self.error_handlers:
            try:
                handler(error)
            except Exception as e:
                logger.error(f"Error handler failed: {e}")

        # Log the error
        if isinstance(error, LDAPError):
            self._log_ldap_error(error, context)
        else:
            self._log_generic_error(error, context)

    def _log_ldap_error(self, error: LDAPError, context: Dict[str, Any] = None) -> None:
        """Log LDAP-specific error with structured data."""
        log_data = {
            "error_code": error.error_code,
            "severity": error.severity.value,
            "category": error.category.value,
            "recoverable": error.recoverable,
            "request_id": request_id_var.get(None),
            "operation_stack": operation_stack_var.get([]),
            **error.details
        }

        if context:
            log_data.update(context)

        if error.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            logger.error(error.message, extra=log_data)
        else:
            logger.warning(error.message, extra=log_data)

    def _log_generic_error(self, error: Exception, context: Dict[str, Any] = None) -> None:
        """Log generic error with context."""
        log_data = {
            "error_type": type(error).__name__,
            "request_id": request_id_var.get(None),
            "operation_stack": operation_stack_var.get([])
        }

        if context:
            log_data.update(context)

        logger.error(f"Unexpected error: {str(error)}", extra=log_data)

class ErrorStatistics:
    """Track error statistics for monitoring."""

    def __init__(self):
        self.error_counts: Dict[str, int] = {}
        self.error_rates: Dict[str, List[datetime]] = {}
        self.severity_counts: Dict[ErrorSeverity, int] = {
            severity: 0 for severity in ErrorSeverity
        }

    def record_error(self, error: Exception) -> None:
        """Record error occurrence for statistics."""
        error_type = type(error).__name__
        now = datetime.now()

        # Update counts
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1

        # Update rates (last hour)
        if error_type not in self.error_rates:
            self.error_rates[error_type] = []

        self.error_rates[error_type].append(now)

        # Clean old entries (older than 1 hour)
        cutoff = now - timedelta(hours=1)
        self.error_rates[error_type] = [
            ts for ts in self.error_rates[error_type] if ts > cutoff
        ]

        # Update severity counts
        if isinstance(error, LDAPError):
            self.severity_counts[error.severity] += 1

    def get_error_rate(self, error_type: str, window_minutes: int = 60) -> float:
        """Get error rate for specific error type."""
        if error_type not in self.error_rates:
            return 0.0

        cutoff = datetime.now() - timedelta(minutes=window_minutes)
        recent_errors = [
            ts for ts in self.error_rates[error_type] if ts > cutoff
        ]

        return len(recent_errors) / window_minutes  # Errors per minute

    def get_summary(self) -> Dict[str, Any]:
        """Get error statistics summary."""
        return {
            "total_errors": sum(self.error_counts.values()),
            "error_counts": self.error_counts.copy(),
            "severity_distribution": {
                severity.value: count for severity, count in self.severity_counts.items()
            },
            "error_rates_per_minute": {
                error_type: self.get_error_rate(error_type, 60)
                for error_type in self.error_rates.keys()
            }
        }

# Global error reporter instance
error_reporter = ErrorReporter()
```

#### 4. **Integration with Existing Result Pattern**

```python
from typing import TypeVar, Generic, Union

T = TypeVar('T')

class EnhancedLDAPOperationResult(Generic[T]):
    """Enhanced operation result with comprehensive error handling."""

    def __init__(self,
                 success: bool,
                 data: Optional[T] = None,
                 error: Optional[LDAPError] = None,
                 operation: str = "",
                 metadata: Dict[str, Any] = None,
                 warnings: List[str] = None):

        self.success = success
        self.data = data
        self.error = error
        self.operation = operation
        self.metadata = metadata or {}
        self.warnings = warnings or []
        self.request_id = request_id_var.get(None)
        self.operation_stack = operation_stack_var.get([])

    @classmethod
    def success_result(cls, data: T, operation: str = "", **metadata) -> 'EnhancedLDAPOperationResult[T]':
        """Create successful result."""
        return cls(
            success=True,
            data=data,
            operation=operation,
            metadata=metadata
        )

    @classmethod
    def error_result(cls, error: LDAPError, operation: str = "") -> 'EnhancedLDAPOperationResult[T]':
        """Create error result."""
        # Report error for monitoring
        error_reporter.report_error(error)

        return cls(
            success=False,
            error=error,
            operation=operation
        )

    @classmethod
    def from_exception(cls, exception: Exception, operation: str = "") -> 'EnhancedLDAPOperationResult[T]':
        """Create error result from any exception."""
        if isinstance(exception, LDAPError):
            error = exception
        else:
            # Wrap non-LDAP exceptions
            error = LDAPError(
                message=f"Unexpected error in {operation}: {str(exception)}",
                details={
                    "original_error": str(exception),
                    "original_error_type": type(exception).__name__
                }
            )

        return cls.error_result(error, operation)

    def get_error_summary(self) -> Optional[Dict[str, Any]]:
        """Get comprehensive error summary."""
        if not self.error:
            return None

        return {
            "error_code": self.error.error_code,
            "message": self.error.message,
            "severity": self.error.severity.value,
            "category": self.error.category.value,
            "suggestions": self.error.suggestions,
            "recoverable": self.error.recoverable,
            "details": self.error.details,
            "request_id": self.request_id,
            "operation_stack": self.operation_stack
        }
```

## 🎯 Consequences

### ✅ **Positive Outcomes**

1. **🔍 Excellent Diagnostics**: Comprehensive error context and tracing
2. **🔄 Intelligent Recovery**: Automatic retry with backoff strategies
3. **📊 System Observability**: Detailed error monitoring and statistics
4. **👥 Developer Experience**: Clear, actionable error messages
5. **🛡️ System Stability**: Prevents cascading failures and resource leaks
6. **📈 Operational Insights**: Error patterns and trends for optimization

### ⚠️ **Potential Challenges**

1. **📚 Complexity**: Sophisticated error handling logic
2. **📦 Overhead**: Additional metadata and tracking
3. **🔧 Configuration**: Many tunable retry and policy parameters
4. **📖 Learning Curve**: Understanding error taxonomy and handling

### 🛡️ **Risk Mitigation**

1. **📚 Clear Documentation**: Error handling guides and examples
2. **🎯 Sensible Defaults**: Pre-configured policies for common scenarios
3. **🔍 Testing Tools**: Error injection and testing utilities
4. **📊 Monitoring Dashboard**: Real-time error tracking and alerting

## 🚀 Implementation Plan

### 📅 **Phase 1: Core Error Infrastructure (Week 1)**

```python
Core_Tasks = [
    "✅ Implement structured exception hierarchy",
    "✅ Create error context tracking system",
    "✅ Add basic retry mechanism",
    "✅ Integrate with existing result pattern",
    "✅ Add error reporting infrastructure"
]
```

### 📅 **Phase 2: Advanced Error Handling (Week 2)**

```python
Advanced_Tasks = [
    "✅ Implement intelligent retry policies",
    "✅ Add comprehensive error statistics",
    "✅ Create error context managers",
    "✅ Add error handler registration system",
    "✅ Implement error correlation and tracing"
]
```

### 📅 **Phase 3: Integration and Monitoring (Week 3)**

```python
Integration_Tasks = [
    "✅ Integrate with monitoring systems",
    "✅ Add error analytics and reporting",
    "✅ Create operational error tools",
    "✅ Performance optimization",
    "✅ Testing and validation"
]
```

## 🔗 Related ADRs

- **[ADR-001: Core Foundation Architecture](001-foundation-architecture.md)** - Provides architectural patterns
- **[ADR-002: Async-First Design](002-async-first-design.md)** - Async error handling patterns
- **[ADR-003: Connection Management](003-connection-management.md)** - Connection error handling
- **[ADR-019: Performance Monitoring](019-performance-monitoring.md)** - Error monitoring integration

## 📊 Success Metrics

```python
Error_Handling_Targets = {
    "reliability": {
        "error_recovery_rate": "> 90%",
        "mean_time_to_recovery": "< 5 seconds",
        "cascading_failure_prevention": "> 99%"
    },
    "observability": {
        "error_context_completeness": "> 95%",
        "error_correlation_accuracy": "> 90%",
        "diagnostic_information_quality": "> 95%"
    },
    "developer_experience": {
        "error_message_clarity": "> 9/10 rating",
        "suggestion_helpfulness": "> 85%",
        "debug_time_reduction": "> 50%"
    }
}
```

---

**🛡️ This comprehensive error handling strategy establishes the reliability and maintainability foundation for enterprise LDAP operations.** Every error provides actionable information while maintaining system stability and enabling intelligent recovery.

**Decision Maker**: Architecture Team
**Date**: 2025-06-24
**Status**: ✅ APPROVED
**Next Review**: Post Phase 1 implementation and error pattern analysis
