# Development Environment Setup

**Complete guide for setting up FLEXT-LDAP development environment**

This guide will help you set up a complete development environment for FLEXT-LDAP, including all necessary dependencies, tools, and integrations with the FLEXT ecosystem.

---

## 🎯 Prerequisites

### System Requirements

- **Python**: 3.13+ with pip and venv support
- **Docker**: For LDAP server testing and integration tests
- **Git**: Version control and FLEXT workspace management
- **Make**: Build automation (GNU Make 4.0+)
- **Poetry**: Python dependency management (1.7+)

### FLEXT Workspace

FLEXT-LDAP is part of the FLEXT ecosystem and requires the complete workspace:

```bash
# Clone FLEXT ecosystem repository
git clone https://github.com/flext-sh/flext.git
cd flext

# Verify workspace structure
ls -la
# Should see: flext-core/, flext-ldap/, flext-observability/, etc.
```

---

## 🚀 Quick Setup

### Automated Setup (Recommended)

```bash
cd flext/flext-ldap

# Complete development setup
make setup

# Verify installation
make doctor
```

This will:

- Install Poetry if not present
- Create Python virtual environment
- Install all dependencies (dev, test, docs)
- Setup pre-commit hooks
- Configure Git hooks
- Verify FLEXT-Core integration

### Manual Setup (Alternative)

```bash
# 1. Install Poetry (if not installed)
curl -sSL https://install.python-poetry.org | python3 -

# 2. Install dependencies
poetry install --with dev,test,docs,typings,security

# 3. Activate virtual environment
poetry shell

# 4. Install pre-commit hooks
poetry run pre-commit install

# 5. Verify setup
make validate
```

---

## 🏗️ Development Environment

### Python Environment

```bash
# Verify Python version
python --version  # Should be 3.13+

# Check virtual environment
poetry env info

# View installed dependencies
poetry show --tree

# Check for security vulnerabilities
poetry run pip-audit
```

### IDE Configuration

#### VS Code Setup

Create `.vscode/settings.json`:

```json
{
    "python.defaultInterpreterPath": "./.venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.ruffEnabled": true,
    "python.linting.mypyEnabled": true,
    "python.formatting.provider": "ruff",
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests", "--cov=src", "--cov-report=html"],
    "files.exclude": {
        "**/__pycache__": true,
        "**/.pytest_cache": true,
        "**/.mypy_cache": true,
        "**/.ruff_cache": true
    }
}
```

#### PyCharm Setup

1. **Interpreter**: Set to Poetry virtual environment
2. **Code Style**: Import FLEXT code style configuration
3. **Run Configurations**: Configure pytest and make targets
4. **Plugins**: Install Poetry, Ruff, and MyPy plugins

### Environment Variables

Create `.env` file for development:

```bash
# Development LDAP server
FLEXT_LDAP_HOST=localhost
FLEXT_LDAP_PORT=3389
FLEXT_LDAP_USE_SSL=false
FLEXT_LDAP_BASE_DN=dc=flext,dc=local
FLEXT_LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local
FLEXT_LDAP_BIND_PASSWORD=REDACTED_LDAP_BIND_PASSWORD123

# Development settings
FLEXT_LDAP_TIMEOUT=30
FLEXT_LDAP_POOL_SIZE=5
FLEXT_LDAP_ENABLE_METRICS=true
FLEXT_LDAP_LOG_LEVEL=DEBUG

# Testing settings
FLEXT_LDAP_TEST_CONTAINER_PORT=3389
FLEXT_LDAP_TEST_DOMAIN=internal.invalid
```

---

## 🧪 Testing Environment

### Docker LDAP Server

Development and testing use containerized OpenLDAP:

```bash
# Start test LDAP server
make ldap-test-server

# Check container status
docker ps | grep flext-ldap-test-server

# View LDAP server logs
docker logs flext-ldap-test-server

# Stop test server
make ldap-test-server-stop
```

### Manual LDAP Server Setup

```bash
# Start OpenLDAP container
docker run -d \
  --name flext-ldap-test-server \
  -p 3389:389 \
  -e LDAP_ORGANISATION="FLEXT Development" \
  -e LDAP_DOMAIN="internal.invalid" \
  -e LDAP_ADMIN_PASSWORD="REDACTED_LDAP_BIND_PASSWORD123" \
  osixia/openldap:1.5.0

# Add test data
ldapadd -H ldap://localhost:3389 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w REDACTED_LDAP_BIND_PASSWORD123 \
  -f tests/fixtures/test_data.ldif
```

### Test Execution

```bash
# Run all tests
make test

# Run specific test types
make test-unit           # Unit tests only
make test-integration    # Integration tests with Docker
make test-e2e           # End-to-end workflow tests

# Run tests with specific markers
poetry run pytest -m "not slow"        # Exclude slow tests
poetry run pytest -m "integration"     # Integration tests only
poetry run pytest -m "ldap"           # LDAP-specific tests

# Run single test file
poetry run pytest tests/test_api.py -v

# Run single test method
poetry run pytest tests/test_api.py::test_create_user -v -s

# Run tests with coverage
poetry run pytest --cov=src --cov-report=html --cov-report=term
```

### Test Data Management

```bash
# Load test data into LDAP server
make test-data-load

# Clean test data
make test-data-clean

# Reset test environment
make test-reset
```

---

## 🔧 Development Tools

### Code Quality Tools

```bash
# Linting with Ruff
make lint                    # Check code style
make format                  # Auto-format code
poetry run ruff check src/   # Manual linting
poetry run ruff format src/  # Manual formatting

# Type checking with MyPy
make type-check              # Check types
poetry run mypy src/         # Manual type check

# Security scanning
make security                # Bandit + pip-audit
poetry run bandit -r src/    # Manual security scan
poetry run pip-audit         # Dependency vulnerability scan
```

### Documentation Tools

```bash
# Build documentation
make docs                    # Build all documentation
make docs-serve             # Serve docs locally (http://localhost:8000)

# API documentation
poetry run sphinx-build docs/api/ docs/_build/api/

# Architecture documentation
poetry run mkdocs build     # Build with MkDocs
poetry run mkdocs serve     # Serve locally
```

### Database Tools

```bash
# LDAP browser/client tools
sudo apt-get install ldap-utils    # Ubuntu/Debian
brew install openldap              # macOS

# Test LDAP connectivity
ldapsearch -H ldap://localhost:3389 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w REDACTED_LDAP_BIND_PASSWORD123 \
  -b "dc=flext,dc=local" \
  "(objectClass=*)"

# Add test user
ldapadd -H ldap://localhost:3389 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w REDACTED_LDAP_BIND_PASSWORD123 << EOF
dn: uid=testuser,ou=users,dc=flext,dc=local
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: testuser
cn: Test User
sn: User
mail: test@internal.invalid
EOF
```

---

## 🔗 FLEXT Integration Setup

### flext-core Integration

```bash
# Verify flext-core is available
cd ../flext-core
poetry install
cd ../flext-ldap

# Test integration
poetry run python -c "
from flext_core import FlextResult, get_logger
from flext_ldap import get_ldap_api
print('✅ FLEXT-Core integration working')
"
```

### flext-observability Integration

```bash
# Setup observability
cd ../flext-observability
poetry install
cd ../flext-ldap

# Test logging integration
poetry run python -c "
from flext_observability import get_logger
logger = get_logger('test')
logger.info('✅ Observability integration working')
"
```

### Singer Ecosystem Setup

```bash
# Install Singer SDK (for future integration)
poetry add singer-sdk

# Setup tap/target development
mkdir -p ../flext-tap-ldap
mkdir -p ../flext-target-ldap
mkdir -p ../flext-dbt-ldap

# Test Singer integration (when implemented)
# poetry run python -c "from flext_tap_ldap import FlextLdapTap; print('✅ Singer integration working')"
```

---

## 🎯 Development Workflow

### Daily Development Cycle

```bash
# 1. Start development session
cd flext/flext-ldap
poetry shell

# 2. Pull latest changes
git pull origin main

# 3. Start test services
make ldap-test-server

# 4. Run quick validation
make check                  # lint + type-check

# 5. Run relevant tests
make test-unit             # During development
make test-integration      # Before commits

# 6. Clean up
make clean
make ldap-test-server-stop
```

### Feature Development

```bash
# 1. Create feature branch
git checkout -b feature/new-ldap-operation

# 2. Implement changes following Clean Architecture
# - Domain layer: entities, value objects, business rules
# - Application layer: use cases, services
# - Infrastructure layer: repositories, clients
# - API layer: controllers, adapters

# 3. Write tests (TDD approach)
poetry run pytest tests/test_new_feature.py -v

# 4. Ensure quality gates pass
make validate              # All quality checks

# 5. Commit with conventional commits
git add .
git commit -m "feat: add new LDAP operation with Clean Architecture"

# 6. Push and create PR
git push origin feature/new-ldap-operation
```

### Debugging Setup

```bash
# Enable debug logging
export FLEXT_LOG_LEVEL=DEBUG
export FLEXT_LDAP_LOG_LEVEL=TRACE

# Run with debugger
poetry run python -m pdb -c continue tests/test_specific.py

# Debug specific test
poetry run pytest tests/test_api.py::test_create_user --pdb

# Debug with logging
poetry run python examples/debug_example.py
```

---

## 📊 Performance Development

### Profiling Setup

```bash
# Install profiling tools
poetry add --group dev py-spy cProfile line-profiler memory-profiler

# Profile LDAP operations
poetry run py-spy record -o profile.svg -- python examples/performance_test.py

# Memory profiling
poetry run mprof run examples/memory_test.py
poetry run mprof plot
```

### Benchmarking

```bash
# Run performance benchmarks
make benchmark

# Custom benchmarks
poetry run pytest tests/test_performance.py --benchmark-only
```

---

## 🔒 Security Development

### Security Testing

```bash
# Security scans
make security                       # Bandit + pip-audit
poetry run bandit -r src/ -f json  # JSON output
poetry run safety check            # Additional dependency checks

# LDAP security testing
poetry run python tests/security/test_ldap_injection.py
poetry run python tests/security/test_credential_handling.py
```

### Secrets Management

```bash
# Never commit secrets - use environment variables
echo "FLEXT_LDAP_BIND_PASSWORD=secret123" >> .env
echo ".env" >> .gitignore

# Use poetry-plugin-env for automatic .env loading
poetry self add poetry-plugin-env
```

---

## 📋 Troubleshooting

### Common Issues

**Poetry Installation Issues**

```bash
# Clear Poetry cache
poetry cache clear pypi --all

# Reinstall dependencies
rm poetry.lock
poetry install
```

**Docker LDAP Server Issues**

```bash
# Remove problematic container
docker stop flext-ldap-test-server
docker rm flext-ldap-test-server

# Clear Docker networks
docker network prune

# Restart with verbose logging
docker run -d --name flext-ldap-test-server \
  -p 3389:389 \
  -e LDAP_LOG_LEVEL=debug \
  osixia/openldap:1.5.0
```

**Import/Path Issues**

```bash
# Verify Python path
poetry run python -c "import sys; print('\n'.join(sys.path))"

# Check flext-core installation
poetry run python -c "from flext_core import FlextResult; print('OK')"

# Rebuild editable installs
poetry install --no-deps
```

**Test Failures**

```bash
# Run with maximum verbosity
poetry run pytest -vvv --tb=long --no-header

# Run specific failing test in isolation
poetry run pytest tests/test_failing.py::test_method -vvv -s

# Check test dependencies
poetry run pytest --collect-only
```

### Getting Help

- **Documentation**: Check [docs/](../README.md) for detailed guides
- **Issues**: Search [GitHub issues](https://github.com/flext-sh/flext/issues)
- **Discussions**: Ask in [GitHub discussions](https://github.com/flext-sh/flext/discussions)
- **Community**: Join FLEXT developer community channels

---

## ✅ Setup Verification

Run this checklist to verify your development environment:

```bash
# 1. Basic setup
make doctor                    # ✅ Should pass all checks

# 2. Code quality
make validate                  # ✅ Should pass all quality gates

# 3. Tests
make test-unit                # ✅ Should pass all unit tests
make test-integration         # ✅ Should pass integration tests

# 4. FLEXT integration
python -c "
from flext_core import FlextResult
from flext_ldap import get_ldap_api
print('✅ All integrations working')
"

# 5. Development tools
poetry run ruff --version     # ✅ Should show Ruff version
poetry run mypy --version     # ✅ Should show MyPy version
docker --version             # ✅ Should show Docker version
```

If all checks pass, your development environment is ready! 🎉

---

_This setup guide is part of the FLEXT-LDAP development documentation and follows FLEXT Framework development standards._
