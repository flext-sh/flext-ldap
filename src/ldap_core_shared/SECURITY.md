# Security Documentation - LDAP Core Shared

## Overview

This document outlines the security considerations, patterns, and best practices implemented in the ldap-core-shared library. All security-related code has been reviewed and hardened according to enterprise security standards.

## Security Improvements Implemented

### 1. Password and Credential Management

#### Hardcoded Password Fixes

- **Fixed**: Replaced hardcoded password masking with configurable constants
- **Location**: `src/ldap_core_shared/connections/base.py`
- **Implementation**: Uses `SENSITIVE_DATA_MASK` constant from `utils/constants.py`
- **Security Benefit**: Centralized control over sensitive data masking

#### Password Attribute Configuration

- **Fixed**: Replaced hardcoded password attribute defaults
- **Location**: `src/ldap_core_shared/operations/compare.py`
- **Implementation**: Uses `DEFAULT_PASSWORD_ATTRIBUTE` constant
- **Security Benefit**: Configurable through environment variables

### 2. SASL Authentication Security

#### DIGEST-MD5 Mechanism

- **Location**: `src/ldap_core_shared/protocols/sasl/mechanisms/digest_md5.py`
- **Security Note**: MD5 usage is REQUIRED by RFC 2831 specification
- **Status**: Properly documented with security annotations
- **Recommendations**:
  - Use SCRAM-SHA-256 for new deployments
  - DIGEST-MD5 is deprecated per RFC 6331

```python
# Example: MD5 usage is protocol-mandated, not a security flaw
ha1 = hashlib.md5(a1.encode("utf-8")).hexdigest()  # noqa: S324
```

### 3. Protocol Constants Security

#### OID Constants

- **Fixed**: Replaced hardcoded OID placeholders causing false S104 violations
- **Implementation**: Uses `PLACEHOLDER_OID` constant
- **Security Benefit**: Clear distinction between placeholder values and actual network bindings

#### Password Policy Constants

- **Fixed**: Added security annotations to LDAP protocol constants
- **Examples**:
  - `PASSWORD_POLICY = "1.3.6.1.4.1.42.2.27.8.5.1"  # noqa: S105`
  - `MODIFY_PASSWORD = "1.3.6.1.4.1.4203.1.11.1"  # noqa: S105`
- **Security Benefit**: Suppresses false positives while maintaining protocol compliance

## Security Configuration

### Environment Variables

Recommended environment variables for secure configuration:

```bash
# LDAP Connection Security
LDAP_PASSWORD_ATTRIBUTE=userPassword
LDAP_SENSITIVE_DATA_MASK=***MASKED***

# Authentication Settings
LDAP_AUTH_METHOD=sasl
LDAP_SASL_MECHANISM=SCRAM-SHA-256

# Connection Security
LDAP_USE_TLS=true
LDAP_VERIFY_CERTIFICATES=true
LDAP_MIN_TLS_VERSION=1.2
```

### Secure Connection Patterns

```python
from ldap_core_shared.connections.base import LDAPConnectionConfig
from ldap_core_shared.utils.constants import DEFAULT_PASSWORD_ATTRIBUTE

# Secure connection configuration
config = LDAPConnectionConfig(
    host="ldap.example.com",
    port=636,
    use_ssl=True,
    bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    bind_password=os.getenv("LDAP_PASSWORD"),  # Never hardcode
    verify_certificates=True,
)

# Secure password comparison
await compare_ops.compare_password(
    user_dn="uid=user,ou=people,dc=example,dc=com",
    password_attribute=os.getenv("LDAP_PASSWORD_ATTRIBUTE", DEFAULT_PASSWORD_ATTRIBUTE),
    plaintext_password=user_provided_password,
)
```

## Security Best Practices

### 1. Credential Management

- ✅ Never hardcode passwords, tokens, or API keys
- ✅ Use environment variables or secure vault systems
- ✅ Implement proper credential rotation
- ✅ Mask sensitive data in logs and debugging output

### 2. Connection Security

- ✅ Always use encrypted connections (LDAPS/StartTLS)
- ✅ Verify server certificates
- ✅ Use strong TLS versions (1.2+)
- ✅ Implement proper timeout and retry logic

### 3. Authentication Security

- ✅ Prefer modern SASL mechanisms (SCRAM-SHA-256)
- ✅ Avoid deprecated mechanisms (DIGEST-MD5, CRAM-MD5)
- ✅ Implement proper challenge-response validation
- ✅ Use mutual authentication when possible

### 4. Input Validation

- ✅ Validate all DN components
- ✅ Sanitize LDAP filter inputs
- ✅ Implement proper escaping for special characters
- ✅ Validate attribute names and values

## Security Test Patterns

### Testing Secure Configurations

```python
def test_secure_connection_config():
    """Test secure connection configuration."""
    config = LDAPConnectionConfig(
        host="test.example.com",
        use_ssl=True,
        verify_certificates=True,
    )
    
    # Verify sensitive data is masked
    masked_data = config.mask_sensitive_data()
    assert masked_data["bind_password"] == SENSITIVE_DATA_MASK
```

### Testing Authentication

```python
async def test_password_authentication():
    """Test secure password authentication."""
    # Use test-only credentials
    test_password = os.getenv("TEST_LDAP_PASSWORD", "test-password-do-not-use-in-prod")
    
    result = await auth_service.authenticate_user(
        user_dn="uid=testuser,ou=people,dc=test,dc=com",
        password=test_password,
        password_attribute=DEFAULT_PASSWORD_ATTRIBUTE,
    )
    
    assert isinstance(result, bool)
```

## Security Monitoring

### Logging Security Events

```python
import logging

# Security-focused logging
security_logger = logging.getLogger("ldap.security")

# Log authentication attempts
security_logger.info(
    "Authentication attempt",
    extra={
        "user_dn": user_dn,
        "source_ip": client_ip,
        "mechanism": auth_mechanism,
        "success": auth_result,
    }
)

# Never log passwords or sensitive data
security_logger.warning(
    "Failed authentication",
    extra={
        "user_dn": user_dn,
        "error": "invalid_credentials",
        # Password intentionally omitted
    }
)
```

### Security Metrics

Monitor these security-related metrics:

- Authentication success/failure rates
- Connection encryption usage
- Certificate validation failures
- Protocol downgrade attempts
- Suspicious DN patterns

## Compliance and Standards

This implementation follows:

- **RFC 4511**: LDAP Protocol specification
- **RFC 4513**: LDAP Authentication Methods
- **RFC 4422**: SASL Authentication Framework
- **OWASP**: Secure coding practices
- **NIST**: Cryptographic standards

## Security Contact

For security issues or questions:

1. Review this documentation
2. Check the implementation in relevant source files
3. Follow secure coding patterns outlined above
4. Report security vulnerabilities through appropriate channels

## Changelog

- **2025-01-21**: Initial security review and hardening
- **2025-01-21**: Fixed S105/S106/S107 hardcoded password violations
- **2025-01-21**: Added security annotations for protocol constants
- **2025-01-21**: Implemented secure configuration patterns
- **2025-01-21**: Added comprehensive security documentation
