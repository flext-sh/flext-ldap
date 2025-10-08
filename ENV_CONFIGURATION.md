# FlextLdapConfig Environment Variable Configuration

**Status**: ✅ VALIDATED
**Date**: 2025-01-08
**Pydantic Version**: 2.11+
**Configuration**: Automatic .env loading via FlextConfig inheritance

---

## Configuration Summary

FlextLdapConfig uses **Pydantic 2 Settings** with automatic `.env` file loading and environment variable configuration. All settings are inherited from `FlextConfig` in flext-core.

### Pydantic 2 Settings Configuration

```python
# Inherited from FlextConfig
env_prefix = 'FLEXT_'
env_file = '.env'
env_file_encoding = 'utf-8'
env_nested_delimiter = '__'
```

### Order of Precedence

Configuration values are loaded in the following order (highest to lowest precedence):

1. **Environment Variables** (highest precedence)
2. **`.env` File** (middle precedence)
3. **Field Defaults** (lowest precedence)

---

## Environment Variable Naming Convention

Field names in `FlextLdapConfig` are prefixed with `ldap_`, and with `env_prefix='FLEXT_'`, the environment variable names follow this pattern:

```
Field Name              → Environment Variable
─────────────────────────────────────────────────
ldap_server_uri         → FLEXT_LDAP_SERVER_URI
ldap_port               → FLEXT_LDAP_PORT
ldap_bind_dn            → FLEXT_LDAP_BIND_DN
ldap_bind_password      → FLEXT_LDAP_BIND_PASSWORD
ldap_base_dn            → FLEXT_LDAP_BASE_DN
ldap_pool_size          → FLEXT_LDAP_POOL_SIZE
ldap_connection_timeout → FLEXT_LDAP_CONNECTION_TIMEOUT
ldap_enable_caching     → FLEXT_LDAP_ENABLE_CACHING
ldap_retry_attempts     → FLEXT_LDAP_RETRY_ATTEMPTS
ldap_enable_debug       → FLEXT_LDAP_ENABLE_DEBUG
ldap_enable_trace       → FLEXT_LDAP_ENABLE_TRACE
ldap_log_queries        → FLEXT_LDAP_LOG_QUERIES
ldap_mask_passwords     → FLEXT_LDAP_MASK_PASSWORDS
```

### ⚠️ IMPORTANT: Avoid Duplicate Prefixes

**WRONG** ❌:
```bash
FLEXT_LDAP_LDAP_SERVER_URI=ldap://localhost  # Double "LDAP" prefix
```

**CORRECT** ✅:
```bash
FLEXT_LDAP_SERVER_URI=ldap://localhost  # Single prefix
```

The field name `ldap_server_uri` already contains the `ldap_` prefix. With `env_prefix='FLEXT_'`, the complete environment variable name is automatically `FLEXT_LDAP_SERVER_URI`.

---

## Minimal Configuration Example

The `.env.minimal` file contains the minimum required configuration for local testing:

```bash
# Connection
FLEXT_LDAP_PORT=3390
FLEXT_LDAP_SERVER_URI=ldap://localhost

# Authentication (required together or both omitted for anonymous)
FLEXT_LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local
FLEXT_LDAP_BIND_PASSWORD=REDACTED_LDAP_BIND_PASSWORD123

# Search base
FLEXT_LDAP_BASE_DN=dc=flext,dc=local

# Optional: Override auto-detection
# FLEXT_LDAP_USE_SSL=false
# FLEXT_LOG_LEVEL=DEBUG
```

---

## Logging Configuration

Logging settings can be configured via environment variables:

```bash
# Inherited from FlextConfig (applies to all FLEXT components)
FLEXT_LOG_LEVEL=DEBUG

# LDAP-specific logging
FLEXT_LDAP_ENABLE_DEBUG=true
FLEXT_LDAP_ENABLE_TRACE=true
FLEXT_LDAP_LOG_QUERIES=true
FLEXT_LDAP_MASK_PASSWORDS=true
```

### Computed Field: `logging_info`

FlextLdapConfig provides a computed field `logging_info` that aggregates logging configuration:

```python
config = FlextLdapConfig()
logging_info = config.logging_info

# Returns:
{
    'debug_enabled': True,
    'trace_enabled': True,
    'query_logging': True,
    'password_masking': True,
    'effective_log_level': 'DEBUG'
}
```

---

## Computed Fields Integration

All computed fields work seamlessly with environment variable configuration:

### 1. Connection Information
```python
config.connection_info
# Returns:
{
    'server_uri': 'ldaps://prod.example.com',
    'port': 636,
    'use_ssl': True,
    'verify_certificates': True,
    'effective_uri': 'ldaps://prod.example.com:636',
    'is_secure': True,
    'connection_timeout': 30
}
```

### 2. Authentication Information
```python
config.authentication_info
# Returns:
{
    'bind_dn_configured': True,
    'bind_password_configured': True,
    'base_dn': 'dc=example,dc=com',
    'anonymous_bind': False
}
```

### 3. Pooling Information
```python
config.pooling_info
# Returns:
{
    'pool_size': 20,
    'pool_timeout': 30,
    'pool_utilization': '20/50'
}
```

### 4. Caching Information
```python
config.caching_info
# Returns:
{
    'caching_enabled': True,
    'cache_ttl': 600,
    'cache_ttl_minutes': 10,
    'cache_effective': True
}
```

### 5. Retry Information
```python
config.retry_info
# Returns:
{
    'retry_attempts': 5,
    'retry_delay': 1,
    'total_retry_time': 5,
    'retry_enabled': True
}
```

### 6. LDAP Capabilities
```python
config.ldap_capabilities
# Returns:
{
    'supports_ssl': True,
    'supports_caching': True,
    'supports_retry': True,
    'supports_debug': True,
    'has_authentication': True,
    'has_pooling': True,
    'is_production_ready': True
}
```

---

## Security: SecretStr Password Handling

Passwords use Pydantic's `SecretStr` type for protection:

```python
from pydantic import Field, SecretStr

ldap_bind_password: SecretStr | None = Field(
    default=None,
    description="LDAP bind password (sensitive)"
)
```

**Environment Variable Loading**:
```bash
FLEXT_LDAP_BIND_PASSWORD=my-secret-password
```

**Accessing the Value**:
```python
config = FlextLdapConfig()

# Get the actual password value
password = config.get_effective_bind_password()  # Returns: "my-secret-password"

# Direct access returns SecretStr object
secret_str = config.ldap_bind_password  # Returns: SecretStr instance
```

**Model Serialization**:
```python
# Passwords are masked in serialization
config_dict = config.model_dump()
# ldap_bind_password is excluded or masked by default
```

---

## Validation Rules

FlextLdapConfig enforces several validation rules:

### 1. Bind DN and Password Consistency
```python
# ❌ INVALID: bind_dn without bind_password
FLEXT_LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
# Missing FLEXT_LDAP_BIND_PASSWORD
# Raises: "Bind password is required when bind DN is specified"

# ✅ VALID: Both provided
FLEXT_LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
FLEXT_LDAP_BIND_PASSWORD=secret
```

### 2. SSL Configuration Consistency
```python
# ❌ INVALID: ldaps:// URI without SSL enabled
FLEXT_LDAP_SERVER_URI=ldaps://server.com
FLEXT_LDAP_USE_SSL=false
# Raises: "SSL must be enabled for ldaps:// server URIs"

# ✅ VALID: Consistent SSL configuration
FLEXT_LDAP_SERVER_URI=ldaps://server.com
FLEXT_LDAP_USE_SSL=true
```

### 3. Caching Configuration Consistency
```python
# ❌ INVALID: caching enabled with zero TTL
FLEXT_LDAP_ENABLE_CACHING=true
FLEXT_LDAP_CACHE_TTL=0
# Raises: "Cache TTL must be positive when caching is enabled"

# ✅ VALID: Positive TTL with caching
FLEXT_LDAP_ENABLE_CACHING=true
FLEXT_LDAP_CACHE_TTL=600
```

### 4. Timeout Relationships
```python
# ❌ INVALID: operation_timeout <= connection_timeout
FLEXT_LDAP_CONNECTION_TIMEOUT=30
FLEXT_LDAP_OPERATION_TIMEOUT=25
# Raises: "Operation timeout must be greater than connection timeout"

# ✅ VALID: operation_timeout > connection_timeout
FLEXT_LDAP_CONNECTION_TIMEOUT=30
FLEXT_LDAP_OPERATION_TIMEOUT=60
```

---

## Testing

Environment variable configuration is validated by comprehensive unit tests:

**Test File**: `tests/unit/test_config_env.py`

**Test Coverage**:
- ✅ `env_prefix`, `env_file`, `env_nested_delimiter` configuration
- ✅ Field name to environment variable mapping
- ✅ Environment variable loading (highest precedence)
- ✅ .env file loading (middle precedence)
- ✅ Order of precedence validation
- ✅ Logging configuration from environment
- ✅ Computed fields integration with environment configuration
- ✅ .env.minimal format validation
- ✅ Nested delimiter configuration
- ✅ SecretStr password handling

**Run Tests**:
```bash
# Run config environment tests
pytest tests/unit/test_config_env.py -v

# Run with coverage
pytest tests/unit/test_config_env.py --cov=src/flext_ldap.config -v
```

---

## Best Practices

### 1. Use Environment-Specific .env Files
```bash
.env.development
.env.staging
.env.production
```

### 2. Never Commit Credentials
```bash
# .gitignore
.env
.internal.invalid
.env.*.local
```

### 3. Document Required Variables
Create `.env.example` with dummy values:
```bash
FLEXT_LDAP_SERVER_URI=ldap://localhost
FLEXT_LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
FLEXT_LDAP_BIND_PASSWORD=changeme
```

### 4. Use Consistent Naming
Always follow the pattern: `FLEXT_[field_name_in_uppercase]`

### 5. Validate Configuration
```python
config = FlextLdapConfig()
validation = config.validate_ldap_requirements()
if validation.is_failure:
    print(f"Configuration error: {validation.error}")
```

---

## Troubleshooting

### Issue: Configuration Not Loading

**Problem**: Environment variables not being picked up

**Solution**:
1. Verify variable names match pattern: `FLEXT_LDAP_*`
2. Check .env file is in current working directory
3. Verify no syntax errors in .env file (no spaces around `=`)
4. Check file encoding is UTF-8

### Issue: Validation Errors

**Problem**: Configuration validation fails on startup

**Solution**:
1. Review validation rules above
2. Check for missing required pairs (bind_dn + bind_password)
3. Verify SSL configuration consistency
4. Check timeout relationships

### Issue: Duplicate Prefix

**Problem**: Using `FLEXT_LDAP_LDAP_*` instead of `FLEXT_LDAP_*`

**Solution**:
- Field names already have `ldap_` prefix
- Use `FLEXT_LDAP_SERVER_URI`, not `FLEXT_LDAP_LDAP_SERVER_URI`
- Run test: `pytest tests/unit/test_config_env.py::TestFlextLdapConfigEnvironment::test_env_file_minimal_format -v`

---

## Migration Notes

### From Old Format (.env.examples)

**Old format** (nested delimiter):
```bash
FLEXT_LDAP_AUTH__BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local
FLEXT_LDAP_CONNECTION__SERVER=localhost
FLEXT_LDAP_CONNECTION__PORT=3390
```

**New format** (flat field names):
```bash
FLEXT_LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local
FLEXT_LDAP_SERVER_URI=ldap://localhost
FLEXT_LDAP_PORT=3390
```

The nested delimiter `__` is configured but not required for FlextLdapConfig since it uses flat field names.

---

## References

- **Pydantic Settings Documentation**: https://docs.pydantic.dev/latest/concepts/pydantic_settings/
- **FlextConfig Source**: `/home/marlonsc/flext/flext-core/src/flext_core/config.py`
- **FlextLdapConfig Source**: `src/flext_ldap/config.py`
- **Unit Tests**: `tests/unit/test_config_env.py`

---

**Last Updated**: 2025-01-08
**Validated By**: Environment variable integration test suite
**Status**: ✅ All tests passing
