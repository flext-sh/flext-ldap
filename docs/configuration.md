# Configuration Guide

<!-- TOC START -->

- [Table of Contents](#table-of-contents)
- [Configuration Overview](#configuration-overview)
  - [Configuration Hierarchy](#configuration-hierarchy)
- [Environment Variables](#environment-variables)
  - [LDAP Server Configuration](#ldap-server-configuration)
  - [Security Configuration](#security-configuration)
  - [Connection Pool Settings](#connection-pool-settings)
- [Configuration File](#configuration-file)
  - [Python Configuration](#python-configuration)
  - [Environment-Specific Configuration](#environment-specific-configuration)
  - [Docker Compose](#docker-compose)
- [Testing Configuration](#testing-configuration)
  - [Test LDAP Server](#test-ldap-server)
  - [Test Configuration](#test-configuration)
- [Configuration Validation](#configuration-validation)
  - [Validating Configuration](#validating-configuration)
  - [Common Configuration Issues](#common-configuration-issues)
- [Security Best Practices](#security-best-practices)
  - [Credential Management](#credential-management)
  - [SSL/TLS Configuration](#ssltls-configuration)
- [Performance Tuning](#performance-tuning)

<!-- TOC END -->

## Table of Contents

- Configuration Guide
  - Configuration Overview
    - Configuration Hierarchy
- 1. Default configuration
- 1. Environment variables (preferred)
- 1. Explicit configuration
  - Environment Variables
    - LDAP Server Configuration
- Required settings
- Optional settings
  - Security Configuration
- SSL/TLS settings
- Authentication
  - Connection Pool Settings
- Connection management
  - Configuration File
    - Python Configuration
- Production configuration
- Development configuration
  - Environment-Specific Configuration
- Usage
  - Docker Configuration
    - Environment File
- LDAP Configuration
- Connection settings
  - Docker Compose
  - Testing Configuration
    - Test LDAP Server
- Start test LDAP server (if available)
  - Test Configuration
  - Configuration Validation
    - Validating Configuration
    - Common Configuration Issues
  - Security Best Practices
    - Credential Management
- Use environment variables for secrets
  - SSL/TLS Configuration
  - Performance Tuning
    - Connection Pool Optimization
- High-traffic configuration
  - Search Optimization
- Optimized search request

**Environment setup and configuration options for flext-ldap**

This guide covers all configuration aspects for integrating flext-ldap in your FLEXT
ecosystem applications.

**Version**: 0.9.9 | **Test Coverage**: 35% | **Phase 2**: ✅ Complete **Architecture**:
Clean Architecture + DDD + Railway-oriented programming

---

## Configuration Overview

FLEXT-LDAP follows the FLEXT framework configuration patterns using Pydantic
BaseSettings with environment variable support.

### Configuration Hierarchy

```python
from flext_ldap import FlextLdapSettings

# 1. Default configuration
settings = FlextLdapSettings()

# 2. Environment variables (preferred)
settings = FlextLdapSettings.from_env()

# 3. Explicit configuration
settings = FlextLdapSettings(
    host="ldap.example.com",
    port=FlextConstants.LDAPS_DEFAULT_PORT,
    use_ssl=True,
    bind_dn="cn=admin,dc=example,dc=com",
    bind_password="admin-password",
    base_dn="dc=example,dc=com",
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
export FLEXT_LDAP_PORT=${FlextConstants.LDAPS_DEFAULT_PORT}
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
from Flext_ldap import FlextLdapSettings

# Production configuration
PRODUCTION_CONFIG = FlextLdapSettings(
    host="ldap-prod.example.com",
    port=FlextConstants.LDAPS_DEFAULT_PORT,
    use_ssl=True,
    bind_dn="cn=service-account,ou=applications,dc=example,dc=com",
    bind_password="${LDAP_PROD_PASSWORD}",
    base_dn="dc=example,dc=com",
    timeout=FlextLdapConstants.DEFAULT_TIMEOUT,
    pool_size=10,
)

# Development configuration
DEVELOPMENT_CONFIG = FlextLdapSettings(
    host="ldap-dev.example.com",
    port=FlextConstants.LDAP_DEFAULT_PORT,
    use_ssl=False,
    bind_dn="cn=admin,dc=dev,dc=example,dc=com",
    bind_password="${LDAP_DEV_PASSWORD}",
    base_dn="dc=dev,dc=example,dc=com",
    timeout=FlextLdapConstants.LdapRetry.CONNECTION_RETRY_DELAY,
    pool_size=3,
)
```

### Environment-Specific Configuration

````python
from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

import os

from Flext_ldap import FlextLdapSettings


def get_config() -> FlextLdapSettings:
    """Get configuration based on environment."""
    env = os.getenv("FLEXT_ENV", "development")

    if env == "production":
        return PRODUCTION_CONFIG
    if env == "staging":
        return STAGING_CONFIG
    return DEVELOPMENT_CONFIG


# Usage
settings = get_config()


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
````

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
  -e LDAP_DOMAIN="internal.invalid" \
  osixia/openldap:1.5.0
```

### Test Configuration

```python
from Flext_ldap import FlextLdapSettings

TEST_CONFIG = FlextLdapSettings(
    host=FlextConstants["Platform.DEFAULT_HOST"],
    port=FlextConstants.LDAP_DEFAULT_PORT,
    use_ssl=False,
    bind_dn="cn=admin,dc=test,dc=flext,dc=local",
    bind_password="admin",
    base_dn="dc=test,dc=flext,dc=local",
    timeout=FlextLdapConstants.LdapRetry.CONNECTION_RETRY_DELAY,
    pool_size=2,
)
```

---

## Configuration Validation

### Validating Configuration

```python
from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from flext_ldap.api import ldap


def validate_config():
    """Validate LDAP configuration."""
    api = ldap

    result = api.test_connection()
    if result.success:
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

settings = FlextLdapSettings(
    host=os.getenv("FLEXT_LDAP_HOST"),
    bind_password=os.getenv("FLEXT_LDAP_BIND_PASSWORD"),
    # ... other settings
)
```

### SSL/TLS Configuration

```python
settings = FlextLdapSettings(
    host="ldap.example.com",
    port=FlextConstants.LDAPS_DEFAULT_PORT,
    use_ssl=True,
    ca_cert_file="/etc/ssl/certs/ca-bundle.pem",
    verify_certs=True,
)
```

---

## Performance Tuning

Submit the complete phase batch to `plan_upsert(entries, planned_entries=())`.
The LDAP owner groups reads by parent and requested attributes, bounds their
filters through `c.Ldap.BATCH_SIZE`, and reuses the same preparation for
`batch_upsert`. Data comparison remains `u.Ldap.compare_entries`.

`UpsertPlan.operations` holds the ordered native preparations shared with writes:
the original entry, operation, exact native modification changes, and
`observed_entry` (the effective comparison projection or observed absence).
`observation_is_projected` identifies observations containing preceding declared
effects or an earlier planned ADD. These observations contain only comparison
attributes; they are not complete, recoverable directory backups. The frozen
envelopes retain native payload references; consumers must not mutate them.
`added_dns`, `modified_dns`, `unchanged_dns` and counts derive from operations.
Carry the final `plan.planned_entries` ADD state into
a later phase through `planned_entries`; an empty ACI replacement on a future ADD is
unchanged and does not require a directory lookup.

Writes remain ordered. A repeated DN starts a fresh read wave during apply;
planning projects only the preceding declared RFC changes. Operational
attributes are requested explicitly, and ambiguous user/operational projection
uses native schema USAGE instead of a manual attribute table. LDAP 32 is legal
absence; other read errors, result limits and write errors remain failures.

Upsert and batch upsert have no retry knobs or legacy changetype-in-attributes
route. Connection/TLS configuration remains independent. No directory data is
cached on disk.

---

For more configuration examples, see the examples/ directory.

---

**Next:** Development Guide →
