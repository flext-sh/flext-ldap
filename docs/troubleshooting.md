# Troubleshooting Guide

## Table of Contents

- [Troubleshooting Guide](#troubleshooting-guide)
  - [Connection Issues](#connection-issues)
    - [Connection Refused Errors](#connection-refused-errors)
- [Test LDAP server connectivity](#test-ldap-server-connectivity)
- [Check if server is listening](#check-if-server-is-listening)
- [Test with ldapsearch (if available)](#test-with-ldapsearch-if-available)
  - [SSL/TLS Connection Errors](#ssltls-connection-errors)
- [Test SSL connection](#test-ssl-connection)
- [Check certificate validity](#check-certificate-validity)
- [Test LDAP with StartTLS](#test-ldap-with-starttls)
- [Disable certificate verification (development only)](#disable-certificate-verification-development-only)
- [Proper certificate configuration](#proper-certificate-configuration)
  - [Authentication Issues](#authentication-issues)
    - [Invalid Credentials](#invalid-credentials)
    - [DN Format Issues](#dn-format-issues)
- [❌ WRONG - Spaces around commas](#-wrong---spaces-around-commas)
- [❌ WRONG - Wrong attribute names](#-wrong---wrong-attribute-names)
- [✅ CORRECT - Proper RFC 4514 format](#-correct---proper-rfc-4514-format)
- [✅ CORRECT - Escaped special characters](#-correct---escaped-special-characters)
- [Test DN validation](#test-dn-validation)
  - [Search and Query Issues](#search-and-query-issues)
    - [Search Filter Syntax Errors](#search-filter-syntax-errors)
- [❌ WRONG - Missing parentheses](#-wrong---missing-parentheses)
- [❌ WRONG - Invalid operators](#-wrong---invalid-operators)
- [❌ WRONG - Unescaped special characters](#-wrong---unescaped-special-characters)
- [✅ CORRECT - Proper LDAP filter syntax](#-correct---proper-ldap-filter-syntax)
- [✅ CORRECT - Complex filters](#-correct---complex-filters)
- [Test filters](#test-filters)
  - [Search Base DN Not Found](#search-base-dn-not-found)
  - [Performance Issues](#performance-issues)
    - [Slow Search Operations](#slow-search-operations)
- [❌ Inefficient - searches entire directory](#-inefficient---searches-entire-directory)
- [✅ Efficient - searches specific branch](#-efficient---searches-specific-branch)
- [❌ Inefficient - broad filter](#-inefficient---broad-filter)
- [✅ Efficient - indexed attribute with specific value](#-efficient---indexed-attribute-with-specific-value)
- [✅ Efficient - compound filter with indexed attributes](#-efficient---compound-filter-with-indexed-attributes)
  - [Connection Pool Exhaustion](#connection-pool-exhaustion)
- [Check connection pool configuration](#check-connection-pool-configuration)
  - [Configuration Issues](#configuration-issues)
    - [Environment Variable Problems](#environment-variable-problems)
    - [Docker Environment Issues](#docker-environment-issues)
- [docker-compose.yml](#docker-composeyml)
- [Test from within container](#test-from-within-container)
  - [Development and Testing Issues](#development-and-testing-issues)
    - [Import Errors](#import-errors)
- [Check package installation](#check-package-installation)
- [Check available imports](#check-available-imports)
  - [Test Environment Setup](#test-environment-setup)
- [Check if test server is running](#check-if-test-server-is-running)
- [Check logs](#check-logs)
- [Test connectivity](#test-connectivity)
- [Restart test server](#restart-test-server)
  - [Error Message Reference](#error-message-reference)
    - [Common Error Patterns](#common-error-patterns)
    - [FlextResult Error Handling](#flextresult-error-handling)
  - [Debugging Tools and Techniques](#debugging-tools-and-techniques)
    - [Enable Debug Logging](#enable-debug-logging)
- [Enable debug logging](#enable-debug-logging)
- [FLEXT logger with debug level](#flext-logger-with-debug-level)
  - [Network Debugging](#network-debugging)
- [Monitor LDAP traffic with tcpdump](#monitor-ldap-traffic-with-tcpdump)
- [Analyze with Wireshark](#analyze-with-wireshark)
- [Test with different LDAP tools](#test-with-different-ldap-tools)
  - [Performance Profiling](#performance-profiling)
- [Run profiling](#run-profiling)
  - [Getting Help](#getting-help)
    - [Information to Include in Bug Reports](#information-to-include-in-bug-reports)
    - [Diagnostic Information Collection](#diagnostic-information-collection)

**Common issues, diagnostics, and solutions for flext-ldap**

This guide helps diagnose and resolve common problems with FLEXT-LDAP integration and LDAP operations.

**Version**: 0.9.9 | **Test Coverage**: 35% | **Phase 2**: ✅ Complete
**Architecture**: Clean Architecture + DDD + Railway-oriented programming

---

## Connection Issues

### Connection Refused Errors

**Symptom:**

```yaml
ConnectionError: Connection failed: [Errno 111] Connection refused
```

**Diagnosis:**

```bash
# Test LDAP server connectivity
telnet ldap.example.com 389     # Standard LDAP port
telnet ldap.example.com 636     # LDAPS port

# Check if server is listening
nmap -p 389,636 ldap.example.com

# Test with ldapsearch (if available)
ldapsearch -x -H ldap://ldap.example.com:389 -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" -w password -b "dc=example,dc=com"
```

**Solutions:**

1. **Verify server is running and accessible**
2. **Check firewall settings** - ensure ports 389/636 are open
3. **Confirm network connectivity** between client and server
4. **Validate DNS resolution** of LDAP server hostname

### SSL/TLS Connection Errors

**Symptom:**

```yaml
ConnectionError: TLS handshake failed
```

**Diagnosis:**

```bash
# Test SSL connection
openssl s_client -connect ldap.example.com:636 -verify 5

# Check certificate validity
openssl x509 -in /path/to/cert.pem -text -noout

# Test LDAP with StartTLS
ldapsearch -x -H ldap://ldap.example.com:389 -ZZ -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" -w password
```

**Solutions:**

1. **Verify SSL certificate is valid and not expired**
2. **Check certificate chain completeness**
3. **Ensure CA certificate is installed**
4. **Configure certificate verification settings**

```python
from Flext_ldap import FlextLdapConfig

# Disable certificate verification (development only)
config = FlextLdapConfig(
    host="ldap.example.com",
    port=636,
    use_ssl=True,
    verify_certs=False  # Only for testing!
)

# Proper certificate configuration
config = FlextLdapConfig(
    host="ldap.example.com",
    port=636,
    use_ssl=True,
    ca_cert_file="/etc/ssl/certs/ca-bundle.pem",
    verify_certs=True
)
```

---

## Authentication Issues

### Invalid Credentials

**Symptom:**

```yaml
AuthenticationError: Authentication failed: Invalid credentials
```

**Diagnosis:**

```python
from flext_ldap import get_flext_ldap_api

def diagnose_auth():
    api = get_flext_ldap_api()

    # Test connection without authentication
    connection_result = api.test_connection()
    print(f"Connection: {connection_result.is_success}")

    # Test with known REDACTED_LDAP_BIND_PASSWORD credentials
    auth_result = api.authenticate_user("REDACTED_LDAP_BIND_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD-password")
    print(f"Auth result: {auth_result.is_success}")
    if auth_result.is_failure:
        print(f"Error: {auth_result.error}")

run(diagnose_auth())
```

**Solutions:**

1. **Verify bind DN format** - must be RFC 4514 compliant
2. **Check bind password** - ensure no special characters are escaped incorrectly
3. **Confirm user exists** in the directory
4. **Test with LDAP REDACTED_LDAP_BIND_PASSWORD tools** first

### DN Format Issues

**Symptom:**

```yaml
SearchError: Invalid DN format
```

**Common DN Format Mistakes:**

```python
# ❌ WRONG - Spaces around commas
dn = "cn=John Doe , ou=users , dc=example , dc=com"

# ❌ WRONG - Wrong attribute names
dn = "name=John Doe,unit=users,domain=example"

# ✅ CORRECT - Proper RFC 4514 format
dn = "cn=John Doe,ou=users,dc=example,dc=com"

# ✅ CORRECT - Escaped special characters
dn = "cn=John\\, Doe,ou=users,dc=example,dc=com"
```

**Validation:**

```python
from flext_ldap import m

def validate_dn(dn_string: str) -> bool:
    """Validate DN format."""
    try:
        dn = m.DistinguishedName(value=dn_string)
        return True
    except ValueError as e:
        print(f"Invalid DN: {e}")
        return False

# Test DN validation
test_dns = [
    "cn=John Doe,ou=users,dc=example,dc=com",
    "uid=john.doe,ou=people,dc=company,dc=org",
    "invalid-dn-format"
]

for test_dn in test_dns:
    result = validate_dn(test_dn)
    print(f"{test_dn}: {'✅' if result else '❌'}")
```

---

## Search and Query Issues

### Search Filter Syntax Errors

**Symptom:**

```yaml
SearchError: Bad search filter
```

**Common Filter Mistakes:**

```python
# ❌ WRONG - Missing parentheses
filter_str = "objectClass=person"

# ❌ WRONG - Invalid operators
filter_str = "(uid == john.doe)"

# ❌ WRONG - Unescaped special characters
filter_str = "(cn=John (Doe))"

# ✅ CORRECT - Proper LDAP filter syntax
filter_str = "(objectClass=person)"
filter_str = "(uid=john.doe)"
filter_str = "(cn=John \\28Doe\\29)"  # Escaped parentheses

# ✅ CORRECT - Complex filters
filter_str = "(&(objectClass=person)(uid=j*))"
filter_str = "(|(cn=John*)(mail=*@example.com))"
```

**Filter Validation:**

```python
from flext_ldap import m, c

def validate_filter(filter_string: str) -> bool:
    """Validate LDAP filter syntax."""
    try:
        ldap_filter = FlextLdapModels.ValueObjects.Filter(expression=filter_string)
        return True
    except ValueError as e:
        print(f"Invalid filter: {e}")
        return False

# Test filters
test_filters = [
    "(objectClass=person)",
    "(&(objectClass=person)(uid=j*))",
    "(|(cn=John*)(mail=*@example.com))",
    "invalid-filter-format"
]

for test_filter in test_filters:
    result = validate_filter(test_filter)
    print(f"{test_filter}: {'✅' if result else '❌'}")
```

### Search Base DN Not Found

**Symptom:**

```yaml
SearchError: No such object: ou=users,dc=example,dc=com
```

**Diagnosis:**

```python
from flext_ldap import get_flext_ldap_api, FlextLdapEntities

def diagnose_base_dn():
    api = get_flext_ldap_api()

    # Search from root to find available bases
    search_request = FlextLdapEntities.SearchRequest(
        base_dn="dc=example,dc=com",
        filter_str="(objectClass=*)",
        scope="onelevel",  # Only immediate children
        attributes=["dn", "objectClass"]
    )

    result = api.search_entries(search_request)
    if result.is_success:
        entries = result.unwrap()
        print("Available organizational units:")
        for entry in entries:
            print(f"  {entry.dn}")
    else:
        print(f"Root search failed: {result.error}")

run(diagnose_base_dn())
```

---

## Performance Issues

### Slow Search Operations

**Symptoms:**

- Long response times for directory searches
- Timeout errors on large result sets

**Diagnosis:**

```python
import time
from flext_ldap import get_flext_ldap_api, FlextLdapEntities

def diagnose_performance():
    api = get_flext_ldap_api()

    # Test different search scopes and filters
    test_cases = [
        {
            "name": "Base scope (fastest)",
            "base_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            "scope": "base",
            "filter": "(objectClass=*)"
        },
        {
            "name": "One level scope",
            "base_dn": "dc=example,dc=com",
            "scope": "onelevel",
            "filter": "(objectClass=organizationalUnit)"
        },
        {
            "name": "Subtree scope (slowest)",
            "base_dn": "dc=example,dc=com",
            "scope": "subtree",
            "filter": "(objectClass=person)"
        }
    ]

    for test_case in test_cases:
        start_time = time.time()

        search_request = FlextLdapEntities.SearchRequest(
            base_dn=test_case["base_dn"],
            filter_str=test_case["filter"],
            scope=test_case["scope"],
            attributes=["dn"],
            size_limit=100
        )

        result = api.search_entries(search_request)
        duration = time.time() - start_time

        if result.is_success:
            count = len(result.unwrap())
            print(f"{test_case['name']}: {count} results in {duration:.2f}s")
        else:
            print(f"{test_case['name']}: Failed - {result.error}")

run(diagnose_performance())
```

**Optimization Solutions:**

1. **Use specific base DNs:**

```python
# ❌ Inefficient - searches entire directory
search_request = FlextLdapEntities.SearchRequest(
    base_dn="dc=example,dc=com",
    filter_str="(uid=john.doe)",
    scope="subtree"
)

# ✅ Efficient - searches specific branch
search_request = FlextLdapEntities.SearchRequest(
    base_dn="ou=users,dc=example,dc=com",
    filter_str="(uid=john.doe)",
    scope="onelevel"
)
```

2. **Optimize search filters:**

```python
# ❌ Inefficient - broad filter
filter_str = "(cn=*john*)"

# ✅ Efficient - indexed attribute with specific value
filter_str = "(uid=john.doe)"

# ✅ Efficient - compound filter with indexed attributes
filter_str = "(&(objectClass=person)(uid=john.doe))"
```

3. **Limit result sets:**

```python
search_request = FlextLdapEntities.SearchRequest(
    base_dn="ou=users,dc=example,dc=com",
    filter_str="(objectClass=person)",
    scope="subtree",
    attributes=["uid", "cn"],  # Only needed attributes
    size_limit=100,           # Reasonable limit
    time_limit=10             # Prevent long-running queries
)
```

### Connection Pool Exhaustion

**Symptoms:**

```yaml
ConnectionError: Connection pool exhausted
```

**Diagnosis:**

```python
# Check connection pool configuration
from Flext_ldap import FlextLdapConfig

config = FlextLdapConfig.from_env()
print(f"Pool size: {config.pool_size}")
print(f"Connection timeout: {config.connection_timeout}")
```

**Solutions:**

1. **Increase pool size:**

```python
config = FlextLdapConfig(
    host="ldap.example.com",
    pool_size=20,  # Increase from default 5
    connection_timeout=10,
    receive_timeout=30
)
```

2. **Implement connection reuse:**

```python
class LDAPService:
    def __init__(self):
        self._api = get_flext_ldap_api()  # Reuse single instance

    def multiple_operations(self, users: list):
        """Perform multiple operations with same connection."""
        results = []
        for user in users:
            result = self._api.authenticate_user(user.username, user.password)
            results.append(result)
        return results
```

---

## Configuration Issues

### Environment Variable Problems

**Diagnosis:**

```python
import os
from Flext_ldap import FlextLdapConfig

def diagnose_config():
    """Check configuration values."""
    config = FlextLdapConfig.from_env()

    print("LDAP Configuration:")
    print(f"  Host: {config.host}")
    print(f"  Port: {config.port}")
    print(f"  Use SSL: {config.use_ssl}")
    print(f"  Bind DN: {config.bind_dn}")
    print(f"  Base DN: {config.base_dn}")

    # Check environment variables
    env_vars = [
        'FLEXT_LDAP_HOST',
        'FLEXT_LDAP_PORT',
        'FLEXT_LDAP_BIND_DN',
        'FLEXT_LDAP_BIND_PASSWORD',
        'FLEXT_LDAP_BASE_DN'
    ]

    print("\nEnvironment Variables:")
    for var in env_vars:
        value = os.getenv(var)
        if var == 'FLEXT_LDAP_BIND_PASSWORD':
            value = "***" if value else None
        print(f"  {var}: {value}")

diagnose_config()
```

### Docker Environment Issues

**Common Docker Problems:**

1. **Service name resolution:**

```yaml
# docker-compose.yml
services:
  app:
    environment:
      - FLEXT_LDAP_HOST=ldap-server # Use service name, not localhost

  ldap-server:
    image: osixia/openldap:1.5.0
```

2. **Network connectivity:**

```bash
# Test from within container
docker exec -it app-container ping ldap-server
docker exec -it app-container telnet ldap-server 389
```

3. **Volume persistence:**

```yaml
services:
  ldap-server:
    volumes:
      - ldap_data:/var/lib/ldap
      - ldap_config:/etc/ldap/slapd.d
    # Ensure data persists between restarts
```

---

## Development and Testing Issues

### Import Errors

**Symptom:**

```python
ImportError: cannot import name 'FlextLdapClients' from 'flext_ldap'
```

**Diagnosis:**

```python
# Check package installation
import pkg_resources
try:
    version = pkg_resources.get_distribution('flext-ldap').version
    print(f"flext-ldap version: {version}")
except pkg_resources.DistributionNotFound:
    print("flext-ldap not installed")

# Check available imports
try:
    from flext_ldap import get_flext_ldap_api
    print("✅ get_flext_ldap_api available")
except ImportError as e:
    print(f"❌ Import error: {e}")

try:
    from flext_ldap import FlextLdapEntities
    print("✅ FlextLdapEntities available")
except ImportError as e:
    print(f"❌ Import error: {e}")
```

### Test Environment Setup

**Docker LDAP Server Issues:**

```bash
# Check if test server is running
docker ps | grep flext-ldap-test-server

# Check logs
docker logs flext-ldap-test-server

# Test connectivity
docker exec -it flext-ldap-test-server ldapsearch \
  -x -H ldap://localhost:389 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w "REDACTED_LDAP_BIND_PASSWORD123" \
  -b "dc=flext,dc=local"

# Restart test server
docker stop flext-ldap-test-server
docker rm flext-ldap-test-server
make ldap-test-server
```

---

## Error Message Reference

### Common Error Patterns

| Error Type     | Pattern                     | Common Cause                    |
| -------------- | --------------------------- | ------------------------------- |
| Connection     | `Connection refused`        | Server down or port blocked     |
| Authentication | `Invalid credentials`       | Wrong username/password         |
| Authorization  | `Insufficient access`       | User lacks required permissions |
| Search         | `Bad search filter`         | Invalid LDAP filter syntax      |
| Search         | `No such object`            | Base DN doesn't exist           |
| Search         | `Size limit exceeded`       | Result set too large            |
| Timeout        | `Operation timed out`       | Slow server or network issues   |
| SSL/TLS        | `Certificate verify failed` | Invalid or expired certificate  |

### FlextResult Error Handling

```python
from flext_ldap import get_flext_ldap_api

def handle_errors_properly():
    """Demonstrate proper error handling with FlextResult."""
    api = get_flext_ldap_api()

    # Always check result status
    result = api.authenticate_user("test", "wrong-password")

    if result.is_success:
        user = result.unwrap()
        print(f"Success: {user.cn}")
    else:
        # Extract error message
        error_msg = result.error
        print(f"Error: {error_msg}")

        # Handle specific error types
        if "Invalid credentials" in error_msg:
            print("Suggestion: Check username and password")
        elif "Connection refused" in error_msg:
            print("Suggestion: Check LDAP server status")
        elif "No such object" in error_msg:
            print("Suggestion: Verify user exists in directory")

run(handle_errors_properly())
```

---

## Debugging Tools and Techniques

### Enable Debug Logging

```python
from flext_core import FlextBus
from flext_core import FlextConfig
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import FlextResult
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import t
from flext_core import u

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# FLEXT logger with debug level
logger = FlextLogger(__name__)
logger.setLevel(logging.DEBUG)
```

### Network Debugging

```bash
# Monitor LDAP traffic with tcpdump
sudo tcpdump -i any -s 0 -w ldap.pcap port 389 or port 636

# Analyze with Wireshark
wireshark ldap.pcap

# Test with different LDAP tools
ldapsearch -v -x -H ldap://server:389 -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" -w password
ldapwhoami -v -x -H ldap://server:389 -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" -w password
```

### Performance Profiling

```python
import cProfile
import pstats
from flext_ldap import get_flext_ldap_api, FlextLdapEntities

def profile_ldap_operations():
    """Profile LDAP operations for performance analysis."""
    api = get_flext_ldap_api()

    # Create multiple search requests
    search_request = FlextLdapEntities.SearchRequest(
        base_dn="dc=example,dc=com",
        filter_str="(objectClass=person)",
        scope="subtree",
        attributes=["uid", "cn", "mail"],
        size_limit=100
    )

    # Perform multiple operations
    for _ in range(10):
        result = api.search_entries(search_request)
        if result.is_failure:
            print(f"Search failed: {result.error}")

def run_profiling():
    profiler = cProfile.Profile()
    profiler.enable()

    run(profile_ldap_operations())

    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats(20)  # Top 20 functions

# Run profiling
run_profiling()
```

---

## Getting Help

### Information to Include in Bug Reports

When reporting issues, include:

1. **Environment details:**
   - Python version
   - flext-ldap version
   - Operating system
   - LDAP server type and version

2. **Configuration:**
   - Sanitized configuration (no passwords)
   - Environment variables
   - Network setup (Docker, Kubernetes, etc.)

3. **Error details:**
   - Complete error messages
   - Stack traces
   - Relevant log output

4. **Reproduction steps:**
   - Minimal code example
   - Steps to reproduce
   - Expected vs actual behavior

### Diagnostic Information Collection

```python
import sys
import pkg_resources
from Flext_ldap import FlextLdapConfig

def collect_diagnostic_info():
    """Collect diagnostic information for bug reports."""
    print("=== FLEXT-LDAP Diagnostic Information ===")

    # System information
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")

    # Package versions
    packages = ['flext-ldap', 'flext-core', 'ldap3', 'pydantic']
    for package in packages:
        try:
            version = pkg_resources.get_distribution(package).version
            print(f"{package}: {version}")
        except pkg_resources.DistributionNotFound:
            print(f"{package}: Not installed")

    # Configuration (sanitized)
    try:
        config = FlextLdapConfig.from_env()
        print(f"LDAP Host: {config.host}")
        print(f"LDAP Port: {config.port}")
        print(f"Use SSL: {config.use_ssl}")
        print(f"Base DN: {config.base_dn}")
        print("Bind credentials: [CONFIGURED]")
    except Exception as e:
        print(f"Configuration error: {e}")

collect_diagnostic_info()
```

---

For additional support and community resources:

- [GitHub Issues](https://github.com/flext/flext-ldap/issues) - Bug reports and feature requests
- [FLEXT Documentation](https://docs.flext.dev) - Framework documentation
- [Examples](examples/) - Working code examples

---

**Previous:** [Integration Guide](guides/integration.md) ←
