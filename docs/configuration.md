# Configuration Guide

**Environment setup and configuration options for flext-ldap**

This guide covers all configuration aspects for integrating flext-ldap in your FLEXT ecosystem applications.

---

## Configuration Overview

FLEXT-LDAP follows the FLEXT framework configuration patterns using Pydantic BaseSettings with environment variable support.

### Configuration Hierarchy

```python
from Flext_ldap import FlextLDAPConfig

# 1. Default configuration
config = FlextLDAPConfig()

# 2. Environment variables (preferred)
config = FlextLDAPConfig.from_env()

# 3. Explicit configuration
config = FlextLDAPConfig(
    host="ldap.example.com",
    port=FlextLDAPConstants.Protocol.DEFAULT_SSL_PORT,
    use_ssl=True,
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="admin-password",
    base_dn="dc=example,dc=com"
)
```

---

## Environment Variables

### LDAP Server Configuration

```bash
# Required settings
export FLEXT_LDAP_HOST="ldap.example.com"
export FLEXT_LDAP_BIND_DN="cn=admin,dc=example,dc=com"
export FLEXT_LDAP_BIND_PASSWORD="your-password"
export FLEXT_LDAP_BASE_DN="dc=example,dc=com"

# Optional settings
export FLEXT_LDAP_PORT=${FlextLDAPConstants.Protocol.DEFAULT_SSL_PORT}
export FLEXT_LDAP_USE_SSL=true
export FLEXT_LDAP_TIMEOUT=${FlextLDAPConstants.DEFAULT_TIMEOUT}
export FLEXT_LDAP_POOL_SIZE=5
```

### Security Configuration

```bash
# SSL/TLS settings
export FLEXT_LDAP_USE_SSL=true
export FLEXT_LDAP_START_TLS=false
export FLEXT_LDAP_VERIFY_CERTS=true
export FLEXT_LDAP_CA_CERT_FILE="/path/to/ca.pem"

# Authentication
export FLEXT_LDAP_AUTH_METHOD="simple"  # simple, sasl
export FLEXT_LDAP_SASL_MECHANISM="GSSAPI"  # For SASL auth
```

### Connection Pool Settings

```bash
# Connection management
export FLEXT_LDAP_POOL_SIZE=5
export FLEXT_LDAP_MAX_RETRIES=3
export FLEXT_LDAP_RETRY_DELAY=1.0
export FLEXT_LDAP_CONNECTION_TIMEOUT=10
export FLEXT_LDAP_RECEIVE_TIMEOUT=30
```

---

## Configuration File

### Python Configuration

Create `ldap_config.py`:

```python
from Flext_ldap import FlextLDAPConfig

# Production configuration
PRODUCTION_CONFIG = FlextLDAPConfig(
    host="ldap-prod.example.com",
    port=FlextLDAPConstants.Protocol.DEFAULT_SSL_PORT,
    use_ssl=True,
    bind_dn="cn=service-account,ou=applications,dc=example,dc=com",
    bind_password="${LDAP_PROD_PASSWORD}",
    base_dn="dc=example,dc=com",
    timeout=FlextLDAPConstants.DEFAULT_TIMEOUT,
    pool_size=10
)

# Development configuration
DEVELOPMENT_CONFIG = FlextLDAPConfig(
    host="ldap-dev.example.com",
    port=FlextLDAPConstants.Protocol.DEFAULT_PORT,
    use_ssl=False,
    bind_dn="cn=admin,dc=dev,dc=example,dc=com",
    bind_password="${LDAP_DEV_PASSWORD}",
    base_dn="dc=dev,dc=example,dc=com",
    timeout=FlextLDAPConstants.LdapRetry.CONNECTION_RETRY_DELAY,
    pool_size=3
)
```

### Environment-Specific Configuration

```python
import os
from Flext_ldap import FlextLDAPConfig

def get_config() -> FlextLDAPConfig:
    """Get configuration based on environment."""
    env = os.getenv("FLEXT_ENV", "development")

    if env == "production":
        return PRODUCTION_CONFIG
    elif env == "staging":
        return STAGING_CONFIG
    else:
        return DEVELOPMENT_CONFIG

# Usage
config = get_config()
```

---

## Docker Configuration

### Environment File

Create `.env` file:

```env
# LDAP Configuration
FLEXT_LDAP_HOST=ldap.example.com
FLEXT_LDAP_PORT=636
FLEXT_LDAP_USE_SSL=true
FLEXT_LDAP_BIND_DN=cn=admin,dc=example,dc=com
FLEXT_LDAP_BIND_PASSWORD=admin-password
FLEXT_LDAP_BASE_DN=dc=example,dc=com

# Connection settings
FLEXT_LDAP_TIMEOUT=30
FLEXT_LDAP_POOL_SIZE=5
```

### Docker Compose

```yaml
version: "3.8"
services:
  app:
    image: your-app:latest
    env_file:
      - .env
    environment:
      - FLEXT_ENV=production
    depends_on:
      - ldap-server
```

---

## Testing Configuration

### Test LDAP Server

For development and testing:

```bash
# Start test LDAP server (if available)
docker run -d \
  --name flext-ldap-test \
  -p 389:389 \
  -p 636:636 \
  -e LDAP_ORGANISATION="FLEXT Test" \
  -e LDAP_DOMAIN="test.flext.local" \
  osixia/openldap:1.5.0
```

### Test Configuration

```python
from Flext_ldap import FlextLDAPConfig

TEST_CONFIG = FlextLDAPConfig(
    host=FlextConstants["Platform.DEFAULT_HOST"],
    port=FlextLDAPConstants.Protocol.DEFAULT_PORT,
    use_ssl=False,
    bind_dn="cn=admin,dc=test,dc=flext,dc=local",
    bind_password="admin",
    base_dn="dc=test,dc=flext,dc=local",
    timeout=FlextLDAPConstants.LdapRetry.CONNECTION_RETRY_DELAY,
    pool_size=2
)
```

---

## Configuration Validation

### Validating Configuration

```python
from flext_ldap import get_flext_ldap_api

def validate_config():
    """Validate LDAP configuration."""
    api = get_flext_ldap_api()

    result = api.test_connection()
    if result.is_success:
        print("✅ Configuration valid - LDAP connection successful")
    else:
        print(f"❌ Configuration invalid: {result.error}")

run(validate_config())
```

### Common Configuration Issues

**Connection Refused:**

- Check host and port settings
- Verify firewall allows LDAP traffic (389/636)
- Confirm LDAP server is running

**Authentication Failed:**

- Verify bind DN format (RFC 4514 compliant)
- Check bind password
- Ensure service account has appropriate permissions

**SSL/TLS Errors:**

- Verify certificate chain
- Check CA certificate file path
- Confirm SSL port (usually 636)

---

## Security Best Practices

### Credential Management

```python
# Use environment variables for secrets
import os

config = FlextLDAPConfig(
    host=os.getenv("FLEXT_LDAP_HOST"),
    bind_password=os.getenv("FLEXT_LDAP_BIND_PASSWORD"),
    # ... other settings
)
```

### SSL/TLS Configuration

```python
from ssl import create_default_context

config = FlextLDAPConfig(
    host="ldap.example.com",
    port=FlextLDAPConstants.Protocol.DEFAULT_SSL_PORT,
    use_ssl=True,
    ca_cert_file="/etc/ssl/certs/ca-bundle.pem",
    verify_certs=True
)
```

---

## Performance Tuning

### Connection Pool Optimization

```python
# High-traffic configuration
config = FlextLDAPConfig(
    pool_size=20,           # Adjust based on concurrent users
    connection_timeout=FlextLDAPConstants.LdapRetry.CONNECTION_RETRY_DELAY,   # Fast connection timeout
    receive_timeout=FlextLDAPConstants.LdapRetry.SERVER_READY_TIMEOUT,     # Operation timeout
    max_retries=2          # Retry failed operations
)
```

### Search Optimization

```python
from flext_ldap import FlextLDAPEntities

# Optimized search request
search_request = FlextLDAPEntities.SearchRequest(
    base_dn="ou=users,dc=example,dc=com",
    filter_str="(&(objectClass=person)(uid=*))",
    scope="onelevel",  # Use minimal scope needed
    attributes=["uid", "cn"],  # Request only needed attributes
    size_limit=100,    # Limit result size
    time_limit=10      # Set search timeout
)
```

---

For more configuration examples, see the [examples/](examples/) directory.

---

**Next:** [Development Guide](development.md) →
