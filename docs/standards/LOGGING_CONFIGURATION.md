# FLEXT-LDAP Centralized Logging Configuration

## 🎯 Overview

The flext-ldap library is fully integrated with flext-core's centralized logging system, supporting enterprise-grade observability with TRACE, DEBUG, INFO, WARNING, ERROR, and CRITICAL levels.

## 🔧 Centralized Configuration

### Environment Variables (Priority Order)

1. **client-a_LOG_LEVEL** - Project-specific (highest priority)
2. **FLEXT_LOG_LEVEL** - Framework-specific
3. **LOG_LEVEL** - Generic (lowest priority)

### Available Log Levels

| Level    | Numeric | Usage                                    |
| -------- | ------- | ---------------------------------------- |
| TRACE    | 5       | Detailed debugging, performance analysis |
| DEBUG    | 10      | General debugging information            |
| INFO     | 20      | General application flow (default)       |
| WARNING  | 30      | Warning conditions                       |
| ERROR    | 40      | Error conditions                         |
| CRITICAL | 50      | Critical conditions                      |

## 🚀 Usage Examples

### 1. Enable TRACE for Development

```bash
# Set TRACE level for all FLEXT libraries
export FLEXT_LOG_LEVEL=TRACE

# Run your application
python your_app.py
```

### 2. Enable DEBUG for Testing

```bash
# Set DEBUG level for framework
export FLEXT_LOG_LEVEL=DEBUG

# Or project-specific (overrides FLEXT_LOG_LEVEL)
export client-a_LOG_LEVEL=DEBUG
```

### 3. Production Configuration

```bash
# Set INFO level for production
export FLEXT_LOG_LEVEL=INFO

# Or WARNING for high-volume systems
export FLEXT_LOG_LEVEL=WARNING
```

## 📊 TRACE Level Examples

When TRACE is enabled, you'll see detailed debugging information:

```bash
FLEXT_LOG_LEVEL=TRACE python -c "
from flext_ldap.config import FlextLdapConnectionConfig
from flext_ldap.ldap_infrastructure import FlextLdapConverter

# Server validation with detailed TRACE logs
config = FlextLdapConnectionConfig(server='test.example.com')

# Type detection with caching information
converter = FlextLdapConverter()
converter.detect_type('test@example.com')  # Shows cache miss, type detection
converter.detect_type('test@example.com')  # Shows cache hit
"
```

Output includes:

- Parameter validation steps
- Cache hit/miss information
- Type detection logic
- Performance metrics
- Operation correlation IDs

## 🎆 Enterprise Features

### Context Binding

```python
from flext_core import FlextLogger

logger = FlextLogger(__name__)

# Operation-specific logger with context
operation_logger = logger.bind(
    operation="ldap_search",
    base_dn="dc=example,dc=com",
    connection_id="conn_123"
)

operation_logger.trace("Starting LDAP search operation")
operation_logger.debug("Search parameters validated")
operation_logger.info("Search completed successfully")
```

### Structured Logging

```python
logger.debug("LDAP connection established", extra={
    "server": "ldap.example.com",
    "port": 389,
    "ssl": False,
    "auth_type": "simple",
    "connection_time_ms": 250
})
```

### Performance-Optimized Logging

The library includes performance checks to avoid expensive operations when not needed:

```python
# Only compute expensive logging data if TRACE is enabled
if hasattr(logger, '_level_value') and logger._level_value <= 5:
    logger.trace("Expensive operation details", extra={
        "complex_data": compute_expensive_debug_info(),
        "cache_stats": get_cache_statistics()
    })
```

## 🔍 Validation Script

Use the included test script to validate your configuration:

```bash
python test_centralized_logging.py
```

This script:

- Shows current environment configuration
- Tests all log levels
- Validates TRACE functionality
- Demonstrates structured logging
- Tests performance optimizations

## 📈 Integration with flext-core Patterns

### Logger Creation

```python
from flext_core import FlextLogger

# Automatically respects centralized configuration
logger = FlextLogger(__name__)
```

### FlextResult Integration

```python
def validate_connection(config):
    if not config.server:
        logger.error("Connection validation failed", extra={"error": "missing_server"})
        return FlextResult[None].fail("Server is required")

    logger.debug("Connection validated", extra={"server": config.server})
    return FlextResult[None].ok(data=True)
```

### Error Correlation

```python
try:
    result = perform_ldap_operation()
    if not result.success:
        logger.error("LDAP operation failed", extra={
            "operation": "search",
            "error": result.error,
            "correlation_id": get_correlation_id()
        })
except Exception as e:
    logger.exception("Unexpected error in LDAP operation", extra={
        "operation": "search",
        "exception_type": type(e).__name__
    })
```

## 🚀 Production Best Practices

### 1. Log Level Strategy

- **Development**: TRACE or DEBUG for detailed diagnostics
- **Testing**: DEBUG or INFO for validation
- **Staging**: INFO for application flow monitoring
- **Production**: INFO or WARNING based on volume

### 2. Structured Data

Always include relevant context in log messages:

```python
logger.info("User authentication successful", extra={
    "user_dn": user.dn,
    "auth_method": "simple",
    "connection_id": conn.id,
    "duration_ms": auth_duration
})
```

### 3. Performance Considerations

- TRACE level includes expensive operations (cache stats, detailed validation)
- DEBUG includes moderate operations (parameter logging, flow tracking)
- INFO includes essential operations (success/failure, metrics)

### 4. Error Handling

Combine FlextResult patterns with comprehensive logging:

```python
result = ldap_client.search(base_dn, filter)
if not result.success:
    logger.error("LDAP search failed", extra={
        "base_dn": base_dn,
        "filter": filter,
        "error": result.error,
        "retry_count": retry_count
    })
    return result

logger.info("LDAP search successful", extra={
    "base_dn": base_dn,
    "results_count": len(result.data),
    "duration_ms": search_duration
})
```

## ✅ Validation Checklist

- [ ] Environment variables set correctly
- [ ] TRACE level shows detailed debugging
- [ ] DEBUG level shows general debugging
- [ ] INFO level shows application flow
- [ ] Structured logging includes relevant context
- [ ] Performance checks prevent expensive operations
- [ ] Error correlation works with FlextResult
- [ ] Context binding provides operation tracking

## 🎯 Summary

The flext-ldap library provides enterprise-grade logging that:

- ✅ Respects centralized flext-core configuration
- ✅ Supports all standard log levels including TRACE
- ✅ Includes performance optimizations
- ✅ Provides structured logging with context
- ✅ Integrates with FlextResult error handling
- ✅ Supports operation tracking and correlation
- ✅ Follows flext-core architectural patterns

This enables production-ready observability and debugging capabilities for all LDAP operations.
