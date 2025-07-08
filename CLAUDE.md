# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Development Commands

### Setup and Installation
```bash
# Activate workspace virtual environment (MANDATORY)
source /home/marlonsc/flext/.venv/bin/activate

# Install dependencies
make install  # or poetry install
```

### Running Tests
```bash
# Run all tests with coverage (95% minimum requirement)
make test-coverage  # or pytest --cov-fail-under=95

# Run specific test categories
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests
pytest -m "not slow"     # Exclude slow tests
pytest -k test_ldap_connection  # Run specific test

# Run tests in parallel
pytest -n auto

# Test dependent projects (CRITICAL after changes)
python scripts/test_algar_oud_mig_integration.py
python scripts/test_flx_ldap_integration.py
python scripts/test_singer_ldap_integration.py
```

### Code Quality
```bash
# Run all quality checks (ZERO TOLERANCE policy)
make check  # Runs lint + tests

# Individual checks
ruff check .          # Linting (all rules enabled)
mypy src/ --strict    # Type checking (strict mode)
black .               # Format code
```

### Building
```bash
make build  # or poetry build
```

## Architecture Overview

### Project Structure
This is an enterprise LDAP library implementing a comprehensive facade pattern that provides:
- High-performance async operations (12K+ entries/sec LDIF processing)
- Complete LDAP protocol support (v2/v3 RFC 4511 compliant)
- Enterprise features (SASL, transactions, vectorized operations)
- Migration tools for Oracle OID → OUD

### Key Architectural Components

#### 1. Main API Facade (`src/flext_ldap/api/__init__.py`)
The `LDAP` class is the primary entry point that delegates to 85+ modules across 20+ categories. It provides 53 public methods covering:
- Core LDAP operations (search, modify, add, delete)
- Async operations with callbacks
- Transaction support
- Vectorized bulk operations
- Advanced controls and extensions
- Schema management
- LDIF processing

#### 2. Domain-Driven Design Structure
```
src/flext_ldap/
├── api/              # Main facade and public interfaces
├── core/             # Core functionality (config, logging, exceptions)
├── domain/           # Domain models and value objects
├── protocols/        # Protocol implementations
│   ├── asn1/        # ASN.1 encoding/decoding
│   ├── sasl/        # All SASL mechanisms
│   └── ldapi/       # LDAP over IPC
├── controls/         # LDAP controls (paging, sorting, etc.)
├── extensions/       # LDAP extensions
├── schema/          # Schema discovery and management
├── ldif/            # High-performance LDIF processing
├── vectorized/      # Bulk operations with NumPy/Pandas
└── migration/       # Enterprise migration tools
```

#### 3. Dependency Injection
Uses both `dependency-injector` and `lato` for clean dependency management. Configuration is centralized through Pydantic settings.

#### 4. Async-First Design
- All operations have async variants
- Connection pooling for high concurrency
- Streaming support for large datasets
- Non-blocking I/O throughout

## Critical Project Context

### Shared Library Dependencies
This is a SHARED LIBRARY used by multiple projects:
- `algar-oud-mig` - PRODUCTION LDAP migration
- `flx-ldap` - LDAP framework integration  
- `tap-ldap` - LDAP data extraction
- `target-ldap` - LDAP data loading
- `dbt-ldap` - LDAP dbt models

**CRITICAL**: Changes have CASCADE effects. Always test ALL dependent projects before making changes.

### Python Version Requirement
**REQUIRES Python 3.13** - This is the latest Python version and is mandatory.

### Quality Standards
- **Test Coverage**: 95% minimum (enforced by pytest)
- **Type Safety**: 100% strict typing with MyPy
- **Linting**: Ruff with ALL rules enabled (specific exceptions in pyproject.toml)
- **Performance**: 12K+ entries/sec for LDIF processing

### Security Considerations
- Handles authentication and authorization
- TLS/SSL encryption support
- SASL authentication mechanisms
- Credential management in production environments

## Common Development Tasks

### Adding New LDAP Operations
1. Implement in appropriate module under `src/flext_ldap/`
2. Add delegation method to main `LDAP` facade class
3. Include comprehensive tests (unit + integration)
4. Update type hints and documentation
5. Test all dependent projects

### Performance Optimization
- Use vectorized operations for bulk processing
- Leverage connection pooling
- Implement streaming for large datasets
- Monitor with built-in performance tracking

### Schema Evolution
```bash
# Discover and compare schemas
python -m flext_ldap.schema discover --server ldap://source.com
python -m flext_ldap.schema compare --source ldap://old --target ldap://new
```

### Migration Operations
```bash
# Run enterprise migrations
python -m flext_ldap.migration migrate \
  --source ldap://oid.company.com \
  --target ldap://oud.company.com \
  --schema-mapping oid_to_oud
```

## Environment Variables

Key environment variables (from .env):
- `LDAP_CORE_DEFAULT_SERVER` - Default LDAP server URL
- `LDAP_CORE_CONNECTION_TIMEOUT` - Connection timeout in seconds
- `LDAP_CORE_SEARCH_SIZE_LIMIT` - Maximum search results
- `LDAP_CORE_ENABLE_CONNECTION_POOLING` - Enable/disable pooling
- `LDAP_CORE_TLS_VALIDATION` - TLS validation mode (strict/permissive)

## Testing Infrastructure

### Test Categories
- `unit` - Fast, isolated unit tests
- `integration` - Tests requiring LDAP server
- `e2e` - End-to-end workflow tests
- `performance` - Performance benchmarks
- `security` - Security-focused tests
- `migration` - Migration tool tests
- `schema` - Schema management tests

### Test Containers
Uses testcontainers for integration tests with real LDAP servers (OpenLDAP, ApacheDS).

## Documentation Structure
- `docs/` - Main documentation
- `docs/architecture/` - ADRs and design decisions
- `docs/rfcs/` - RFC implementations documentation
- `examples/` - Usage examples
- `CHANGELOG.md` - Version history