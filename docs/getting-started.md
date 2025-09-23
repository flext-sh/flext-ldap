# Getting Started with FLEXT-LDAP

**LDAP directory services integration for the FLEXT ecosystem**

This guide covers installation, basic configuration, and first steps with flext-ldap.

---

## Prerequisites

### **System Requirements**

- **Python 3.13+** with type system support
- **Poetry 1.8+** for dependency management
- **Git** for version control
- **Docker** (optional, for testing with OpenLDAP container)

### **LDAP Server Requirements**

**Production:**

- OpenLDAP 2.5+, Active Directory, or other LDAP v3 compliant server
- SSL/TLS configured (recommended)
- Service account with appropriate permissions

**Development/Testing:**

- Docker for running test LDAP server
- osixia/openldap:1.5.0 container (automatic setup available)

---

## Installation

### **Production Installation**

Install from PyPI:

```bash
pip install flext-ldap
# or with poetry
poetry add flext-ldap
```

### **Development Installation**

Clone and setup development environment:

```bash
git clone <repository-url>
cd flext-ldap
make setup      # Install dependencies, pre-commit hooks, dev tools
make validate   # Run quality checks to verify installation
```

### **Verify Installation**

Test your installation:

```bash
python -c "from flext_ldap import get_flext_ldap_api; print('Installation successful')"
```

---

## Configuration

### **Environment Variables**

Configure LDAP connection settings:

```bash
# Basic LDAP server configuration
export FLEXT_LDAP_HOST=ldap.example.com
export FLEXT_LDAP_PORT=636
export FLEXT_LDAP_USE_SSL=true
export FLEXT_LDAP_BASE_DN="dc=example,dc=com"

# Authentication
export FLEXT_LDAP_BIND_DN="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
export FLEXT_LDAP_BIND_PASSWORD="your-password"

# Connection settings
export FLEXT_LDAP_TIMEOUT=30
export FLEXT_LDAP_POOL_SIZE=5
```

### **Configuration File**

Create `flext_ldap_config.py`:

```python
from flext_ldap import FlextLdapConfigs

config = FlextLdapConfigs(
    host="ldap.example.com",
    port=636,
    use_ssl=True,
    base_dn="dc=example,dc=com",
    bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    bind_password="your-password",
    timeout=30,
    pool_size=5
)
```

---

## First Steps

### **Basic Connection Test**

```python
import asyncio
from flext_ldap import get_flext_ldap_api

async def test_connection():
    """Test basic LDAP connectivity."""
    api = get_flext_ldap_api()

    result = await api.test_connection()
    if result.is_success:
        print("✅ LDAP connection successful")
    else:
        print(f"❌ Connection failed: {result.error}")

asyncio.run(test_connection())
```

### **Simple Directory Search**

```python
import asyncio
from flext_ldap import get_flext_ldap_api, FlextLdapEntities

async def basic_search():
    """Perform a basic directory search."""
    api = get_flext_ldap_api()

    search_request = FlextLdapEntities.SearchRequest(
        base_dn="dc=example,dc=com",
        filter_str="(objectClass=organizationalUnit)",
        scope="subtree",
        attributes=["ou", "description"]
    )

    result = await api.search_entries(search_request)
    if result.is_success:
        entries = result.unwrap()
        print(f"Found {len(entries)} organizational units:")
        for entry in entries:
            print(f"  - {entry.ou}: {entry.description}")
    else:
        print(f"Search failed: {result.error}")

asyncio.run(basic_search())
```

### **User Authentication**

```python
import asyncio
from flext_ldap import get_flext_ldap_api

async def authenticate_user():
    """Authenticate a user against LDAP."""
    api = get_flext_ldap_api()

    username = "john.doe"
    password = "user-password"

    result = await api.authenticate_user(username, password)
    if result.is_success:
        user = result.unwrap()
        print(f"✅ Authentication successful for {user.uid}")
    else:
        print(f"❌ Authentication failed: {result.error}")

asyncio.run(authenticate_user())
```

---

## Development Environment

### **Test LDAP Server Setup**

For development and testing, use Docker:

```bash
# Start OpenLDAP test server
make ldap-test-server

# Verify server is running
docker ps | grep flext-ldap-test-server

# Stop test server
make ldap-test-server-stop
```

### **Run Tests**

```bash
# Run all tests
make test

# Run specific test categories
pytest tests/unit/           # Unit tests
pytest tests/integration/   # Integration tests (requires LDAP server)
pytest tests/e2e/          # End-to-end tests

# Run with coverage
pytest --cov=src/flext_ldap
```

### **Development Workflow**

```bash
# Daily development cycle
make format     # Auto-format code
make lint       # Check code style
make type-check # Verify type annotations
make test       # Run tests
make validate   # Complete quality pipeline
```

---

## Next Steps

Once you have flext-ldap installed and working:

1. **[Architecture Guide](architecture.md)** - Understand Clean Architecture patterns
2. **[API Reference](api-reference.md)** - Complete API documentation
3. **[Integration Guide](integration.md)** - FLEXT ecosystem integration
4. **[Examples](examples/)** - Working code examples
5. **[Development Guide](development.md)** - Contributing to the project

---

## Troubleshooting

### **Common Issues**

**Connection refused:**

- Verify LDAP server is running and accessible
- Check firewall settings for LDAP port (389/636)
- Confirm SSL/TLS configuration

**Authentication failed:**

- Verify bind DN and password are correct
- Check user permissions in LDAP directory
- Ensure proper DN format (RFC 4514)

**Import errors:**

- Verify installation: `pip list | grep flext-ldap`
- Check Python version: `python --version` (requires 3.13+)
- Reinstall: `pip uninstall flext-ldap && pip install flext-ldap`

For more troubleshooting help, see [Troubleshooting Guide](troubleshooting.md).

---

**Next:** [Architecture Overview](architecture.md) →
