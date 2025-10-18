# Configuration Guide
## Table of Contents

- [Configuration Guide](#configuration-guide)
  - [Configuration Overview](#configuration-overview)
    - [Configuration Hierarchy](#configuration-hierarchy)
- [1. Default configuration](#1-default-configuration)
- [2. Environment variables (preferred)](#2-environment-variables-preferred)
- [3. Explicit configuration](#3-explicit-configuration)
  - [Environment Variables](#environment-variables)
    - [LDAP Server Configuration](#ldap-server-configuration)
- [Required settings](#required-settings)
- [Optional settings](#optional-settings)
    - [Security Configuration](#security-configuration)
- [SSL/TLS settings](#ssltls-settings)
- [Authentication](#authentication)
    - [Connection Pool Settings](#connection-pool-settings)
- [Connection management](#connection-management)
  - [Configuration File](#configuration-file)
    - [Python Configuration](#python-configuration)
- [Production configuration](#production-configuration)
- [Development configuration](#development-configuration)
    - [Environment-Specific Configuration](#environment-specific-configuration)
- [Usage](#usage)
  - [Docker Configuration](#docker-configuration)
    - [Environment File](#environment-file)
- [LDAP Configuration](#ldap-configuration)
- [Connection settings](#connection-settings)
    - [Docker Compose](#docker-compose)
  - [Testing Configuration](#testing-configuration)
    - [Test LDAP Server](#test-ldap-server)
- [Start test LDAP server (if available)](#start-test-ldap-server-if-available)
    - [Test Configuration](#test-configuration)
  - [Configuration Validation](#configuration-validation)
    - [Validating Configuration](#validating-configuration)
    - [Common Configuration Issues](#common-configuration-issues)
  - [Security Best Practices](#security-best-practices)
    - [Credential Management](#credential-management)
- [Use environment variables for secrets](#use-environment-variables-for-secrets)
    - [SSL/TLS Configuration](#ssltls-configuration)
  - [Performance Tuning](#performance-tuning)
    - [Connection Pool Optimization](#connection-pool-optimization)
- [High-traffic configuration](#high-traffic-configuration)
    - [Search Optimization](#search-optimization)
- [Optimized search request](#optimized-search-request)


**Environment setup and configuration options for flext-ldap**

This guide covers all configuration aspects for integrating flext-ldap in your FLEXT ecosystem applications.

**Version**: 0.9.9 | **Test Coverage**: 35% | **Phase 2**: ✅ Complete
**Architecture**: Clean Architecture + DDD + Railway-oriented programming

---

## Configuration Overview

FLEXT-LDAP follows the FLEXT framework configuration patterns using Pydantic BaseSettings with environment variable support.

### Configuration Hierarchy

```python
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import FlextHandlers
from flext_core import FlextLogger
from flext_core import FlextMixins
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import FlextProtocols
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import FlextTypes
from flext_core import FlextUtilities  # For platform constants
from flext_ldap import FlextLdapConfig

# 1. Default configuration
config = FlextLdapConfig()

# 2. Environment variables (preferred)
config = FlextLdapConfig.from_env()

# 3. Explicit configuration
config = FlextLdapConfig(
    host="ldap.example.com",
    port=FlextConstants.Platform.LDAPS_DEFAULT_PORT,
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
export FLEXT_LDAP_PORT=${FlextConstants.Platform.LDAPS_DEFAULT_PORT}
export FLEXT_LDAP_USE_SSL=true
export FLEXT_LDAP_TIMEOUT=${FlextLdapConstants.DEFAULT_TIMEOUT}
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
from Flext_ldap import FlextLdapConfig

# Production configuration
PRODUCTION_CONFIG = FlextLdapConfig(
    host="ldap-prod.example.com",
    port=FlextConstants.Platform.LDAPS_DEFAULT_PORT,
    use_ssl=True,
    bind_dn="cn=service-account,ou=applications,dc=example,dc=com",
    bind_password="${LDAP_PROD_PASSWORD}",
    base_dn="dc=example,dc=com",
    timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
    pool_size=10
)

# Development configuration
DEVELOPMENT_CONFIG = FlextLdapConfig(
    host="ldap-dev.example.com",
    port=FlextConstants.Platform.LDAP_DEFAULT_PORT,
    use_ssl=False,
    bind_dn="cn=admin,dc=dev,dc=example,dc=com",
    bind_password="${LDAP_DEV_PASSWORD}",
    base_dn="dc=dev,dc=example,dc=com",
    timeout=FlextLdapConstants.LdapRetry.CONNECTION_RETRY_DELAY,
    pool_size=3
)
```

### Environment-Specific Configuration

```python
import os
from Flext_ldap import FlextLdapConfig

def get_config() -> FlextLdapConfig:
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
from Flext_ldap import FlextLdapConfig

TEST_CONFIG = FlextLdapConfig(
    host=FlextConstants["Platform.DEFAULT_HOST"],
    port=FlextConstants.Platform.LDAP_DEFAULT_PORT,
    use_ssl=False,
    bind_dn="cn=admin,dc=test,dc=flext,dc=local",
    bind_password="admin",
    base_dn="dc=test,dc=flext,dc=local",
    timeout=FlextLdapConstants.LdapRetry.CONNECTION_RETRY_DELAY,
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

config = FlextLdapConfig(
    host=os.getenv("FLEXT_LDAP_HOST"),
    bind_password=os.getenv("FLEXT_LDAP_BIND_PASSWORD"),
    # ... other settings
)
```

### SSL/TLS Configuration

```python
from ssl import create_default_context

config = FlextLdapConfig(
    host="ldap.example.com",
    port=FlextConstants.Platform.LDAPS_DEFAULT_PORT,
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
config = FlextLdapConfig(
    pool_size=20,           # Adjust based on concurrent users
    connection_timeout=FlextLdapConstants.LdapRetry.CONNECTION_RETRY_DELAY,   # Fast connection timeout
    receive_timeout=FlextLdapConstants.LdapRetry.SERVER_READY_TIMEOUT,     # Operation timeout
    max_retries=2          # Retry failed operations
)
```

### Search Optimization

```python
from flext_ldap import FlextLdapEntities

# Optimized search request
search_request = FlextLdapEntities.SearchRequest(
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
