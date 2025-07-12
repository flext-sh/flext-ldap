# CLAUDE.md

**FLEXT-LDAP Development Guide for Claude Code**

This file provides specific guidance for working with the FLEXT-LDAP enterprise LDAP library within the FLEXT ecosystem.

## Project Context

### FLEXT Ecosystem Position

- **Role**: Core infrastructure component for LDAP operations
- **Dependencies**: Extends `flext-core`, integrates `flext-observability`
- **Dependents**: `algar-oud-mig`, `flext-tap-ldap`, `flext-target-ldap`, enterprise projects
- **Architecture**: Clean Architecture + DDD using FLEXT standards

### Current Status (Accurate)

- **Quality**: 0 linting errors, 100% MyPy strict compliance
- **Test Coverage**: 48% (target: 95%+)
- **Architecture**: Clean/DDD with proper separation
- **LDAP Integration**: Real ldap3 implementation + memory fallback
- **Production Usage**: Used in enterprise LDAP migration projects

## Build and Development Commands

### Setup and Installation

```bash
# MANDATORY: Use FLEXT workspace environment
source /home/marlonsc/flext/.venv/bin/activate

# Install dependencies (Poetry managed)
poetry install --all-extras

# Verify installation
python -c "from flext_ldap import LDAPService; print('✅ Import successful')"
```

### Running Tests

```bash
# Run all tests with coverage (current: 48%, target: 95%+)
pytest --cov=src/flext_ldap --cov-report=term-missing

# Run specific test suites
pytest tests/test_utils.py -v                    # LDAP utilities (52 tests)
pytest tests/test_simple_api.py -v              # API facade (17 tests)
pytest tests/infrastructure/test_repositories.py -v  # Infrastructure (19 tests)

# Run with specific markers (when implemented)
pytest -m unit           # Unit tests
pytest -m integration    # Integration tests with real LDAP
pytest -m "not slow"     # Fast tests only
```

### Code Quality (FLEXT Standards)

```bash
# All quality checks MUST pass (current status: PASSING)
ruff check src/          # Linting (ALL rules) - CLEAN ✅
mypy src/ --strict       # Type checking - CLEAN ✅
bandit -r src/          # Security scanning - CLEAN ✅

# Code formatting
ruff format src/

# Combined quality check
make check  # All quality gates
```

## Architecture Overview (Clean Architecture + DDD)

### Layer Structure (FLEXT Standard)

```
src/flext_ldap/
├── domain/              # 🏛️  Business Logic (zero external dependencies)
│   ├── entities.py      # Domain entities (LDAPUser, LDAPGroup, LDAPConnection)
│   ├── value_objects.py # Immutable values (DN, LDAPFilter, CreateUserRequest)
│   ├── ports.py         # Service contracts and repository interfaces
│   ├── repositories.py  # Abstract repository definitions
│   └── exceptions.py    # Domain-specific exceptions
├── application/         # 🎯  Use Cases (orchestration layer)
│   ├── ldap_service.py  # Main LDAP service (primary facade)
│   └── services.py      # Supporting application services
├── infrastructure/     # 🔌  External Integrations
│   ├── ldap_client.py   # Real LDAP client (ldap3 integration)
│   └── repositories.py  # Concrete repository implementations
├── config.py           # ⚙️  Configuration management (flext-core patterns)
├── simple_api.py       # 🚪  Simple API facade (DI container integration)
└── cli_new.py          # 🖥️  Command-line interface
```

### Key FLEXT Patterns Used

#### 1. ServiceResult Pattern (flext-core)

All operations return `ServiceResult[T]` for type-safe error handling:

```python
# Never throws exceptions - always returns ServiceResult
result = await ldap_service.create_user(request)
if result.is_success:
    user = result.value  # Type: LDAPUser
else:
    logger.error("User creation failed: %s", result.error_message)
```

#### 2. Dependency Injection (flext-core)

```python
@injectable()  # flext-core DI decorator
class LDAPService:
    def __init__(self, 
                 user_service: LDAPUserService,
                 connection_service: LDAPConnectionService):
        self._user_service = user_service
        self._connection_service = connection_service
```

#### 3. Repository Pattern (flext-core)

```python
# Domain defines contracts
class LDAPUserRepository(ABC):
    async def save(self, user: LDAPUser) -> ServiceResult[LDAPUser]: ...

# Infrastructure implements
class LDAPUserRepositoryImpl(LDAPUserRepository):
    async def save(self, user: LDAPUser) -> ServiceResult[LDAPUser]:
        # Real LDAP operations using ldap3
```

#### 4. Configuration (flext-core BaseSettings)

```python
class FlextLDAPSettings(BaseSettings):
    connection: LDAPConnectionConfig = Field(default_factory=LDAPConnectionConfig)
    auth: LDAPAuthConfig = Field(default_factory=LDAPAuthConfig)
    
    model_config = SettingsConfigDict(env_prefix="FLEXT_LDAP_")
```

## Development Guidelines

### FLEXT Standards Compliance

#### Type Safety (Strict)

- **MyPy**: All code must pass `--strict` mode
- **Type Annotations**: 100% coverage required
- **Generic Types**: Use proper generic typing for containers
- **No Any**: Avoid `typing.Any` unless absolutely necessary

#### Error Handling (ServiceResult Only)

```python
# ✅ CORRECT - ServiceResult pattern
async def create_user(self, request: CreateUserRequest) -> ServiceResult[LDAPUser]:
    try:
        user = await self._repository.save(user_entity)
        return ServiceResult.success(user)
    except LDAPException as e:
        return ServiceResult.failure(f"LDAP error: {e}")

# ❌ INCORRECT - Exception-based error handling
async def create_user(self, request: CreateUserRequest) -> LDAPUser:
    user = await self._repository.save(user_entity)  # May raise exception
    return user
```

#### Logging (flext-observability)

```python
from flext_observability.logging import get_logger

logger = get_logger(__name__)

# ✅ CORRECT - Structured logging
logger.info("LDAP connection established to %s", server_url)
logger.error("LDAP operation failed: operation=%s error=%s", operation, error)

# ❌ INCORRECT - String formatting in log calls
logger.info(f"LDAP connection established to {server_url}")
```

### Architecture Boundaries

#### Domain Layer Rules

- **NO external dependencies** (no imports from infrastructure/application)
- **Pure business logic** - no framework coupling
- **Rich domain models** with behavior and validation
- **Value objects** for data that belongs together

#### Application Layer Rules  

- **Orchestrates use cases** - business workflow coordination
- **Depends only on domain** - can import from domain layer
- **No direct infrastructure access** - uses repository interfaces
- **ServiceResult pattern** for all operations

#### Infrastructure Layer Rules

- **Implements domain contracts** - repository interfaces, external services
- **Framework integration** - ldap3, database drivers, file I/O
- **Configuration management** - environment variables, settings
- **External service adapters** - LDAP servers, message queues

## Critical Development Rules

### 1. Shared Library Impact

This is a **SHARED LIBRARY** used by multiple FLEXT projects:

- `algar-oud-mig` (production enterprise migration)
- `flext-tap-ldap` (LDAP data extraction)
- `flext-target-ldap` (LDAP data loading)
- `flext-dbt-ldap` (LDAP dbt models)

**🚨 CRITICAL**: Any breaking changes affect ALL dependent projects.

### 2. Testing Requirements

```bash
# MANDATORY: Test all dependent projects after changes
cd ../algar-oud-mig && python -c "import flext_ldap; print('✅ ALGAR integration OK')"
cd ../flext-tap-ldap && python -c "import flext_ldap; print('✅ TAP integration OK')"
cd ../flext-target-ldap && python -c "import flext_ldap; print('✅ TARGET integration OK')"
```

### 3. Quality Gates (MUST PASS)

```bash
# Zero tolerance policy
ruff check src/          # Must be CLEAN (0 errors)
mypy src/ --strict       # Must be CLEAN (0 errors) 
pytest --cov=src/flext_ldap --cov-fail-under=48  # Minimum current coverage
bandit -r src/          # Must be CLEAN (no high/medium issues)
```

### 4. Production Deployment Considerations

- **Memory usage**: Keep constant memory usage for large directories
- **Connection pooling**: Implement proper LDAP connection management  
- **Error recovery**: Graceful degradation when LDAP servers unavailable
- **Configuration**: Environment-based configuration for different stages

```

### Building

```bash
make build  # Clean + check + test + poetry build
```

## Architecture Overview

### Project Structure

This is an enterprise LDAP library with clean, minimal implementation following SOLID/KISS/DRY principles. It provides:

- **Async-First Design**: Built with Python 3.13+ async/await patterns
- **Type-Safe**: 100% type hints with strict mypy checking  
- **Clean Architecture**: Domain-driven design with clear separation of concerns
- **Enterprise Ready**: Connection pooling, error handling, monitoring integration
- **FLEXT Integration**: Leverages flext-core for minimal duplication

### Key Components

#### 1. Main API (`src/flext_ldap/`)

The core library structure:

```
src/flext_ldap/
├── __init__.py       # Public API exports
├── client.py         # LDAPClient - main async LDAP client
├── models.py         # Pydantic models (LDAPEntry, LDAPFilter, LDAPScope)
├── operations.py     # Core LDAP operations
├── utils.py          # Utility functions
├── config.py         # Configuration management
├── cli.py           # Legacy CLI interface
├── cli_new.py       # New CLI interface  
├── simple_api.py    # Simplified API facade
├── application/     # Application services layer
│   ├── services.py  # Business logic services
│   └── __init__.py
└── domain/          # Domain layer (DDD)
    ├── entities.py      # Domain entities
    ├── value_objects.py # Value objects
    ├── ports.py         # Interfaces/ports
    ├── repositories.py  # Repository interfaces
    └── __init__.py
```

#### 2. Domain-Driven Design

- **Domain Layer**: Core business logic isolated from infrastructure
- **Application Layer**: Services orchestrating domain operations
- **Interface Layer**: CLI and API interfaces
- **Clean Dependencies**: flext-core integration for shared functionality

#### 3. Async-First Architecture

- All LDAP operations are async by default
- Connection management with proper resource cleanup
- Error handling with structured result patterns
- Type-safe interfaces throughout

## Critical Project Context

### FLEXT Framework Integration

This library is part of the FLEXT framework ecosystem and depends on:

- **flext-core**: Foundation classes, logging, configuration, utilities
- **flext-observability**: Monitoring, metrics, tracing integration

### Shared Library Usage

This is a SHARED LIBRARY used by multiple projects in the workspace:

- `algar-oud-mig` - PRODUCTION LDAP migration project
- Other FLEXT LDAP integrations

**CRITICAL**: Changes have CASCADE effects. Always verify dependent project compatibility.

### Python Version Requirement

**REQUIRES Python 3.13** - Latest Python version is mandatory for this project.

### Quality Standards (ULTRA-STRICT)

- **Test Coverage**: 95% minimum (enforced by pytest)
- **Type Safety**: 100% strict typing with MyPy
- **Linting**: Ruff with ALL rules enabled, Pylint 10.0/10 required
- **Security**: Bandit security scanning, pip-audit dependency scanning
- **Code Quality**: Black formatting, isort imports, pydocstyle docstrings

### CLI Interfaces

Two CLI interfaces available:

```bash
# New CLI (recommended)
flext-ldap --help
poetry run python -m flext_ldap.cli_new

# Legacy CLI
flext-ldap-legacy
poetry run python -m flext_ldap.cli
```

## Development Workflow

### Adding New Features

1. **Add to Domain Layer**: Implement core logic in `src/flext_ldap/domain/`
2. **Application Service**: Add orchestration in `src/flext_ldap/application/services.py`
3. **Client Interface**: Expose through `LDAPClient` in `client.py`
4. **Tests**: Add comprehensive tests with appropriate markers
5. **Documentation**: Update docstrings using Google style
6. **Quality Check**: Run `make check` to ensure all standards pass

### Working with Configuration

Configuration is managed through `flext-core` integration:

```python
from flext_ldap.config import LDAPConfig

# Configuration loaded from environment variables or .env file
config = LDAPConfig()
```

### CLI Development

Two CLI entry points for different use cases:

- `cli_new.py` - Modern Click-based CLI (recommended for new features)
- `cli.py` - Legacy CLI (maintained for compatibility)

## Testing Infrastructure

### Test Markers (configured in pyproject.toml)

- `unit` - Fast, isolated unit tests
- `integration` - Tests requiring LDAP server
- `slow` - Slow tests (excluded by default)
- `smoke` - Basic functionality tests
- `e2e` - End-to-end workflow tests
- `ldap` - LDAP-specific tests
- `async` - Async operation tests
- `security` - Security-focused tests
- `performance` - Performance benchmarks
- `requires_ldap_server` - Tests needing real LDAP server

### Running Specific Tests

```bash
# Run specific test categories
pytest -m "unit and not slow"
pytest -m "integration and ldap"
pytest -k "test_client"  # Run tests matching name pattern

# Debug failing tests
make test-debug  # Runs with pdb and detailed output
```

## Project Standards

### Code Organization

- **Domain-First**: Business logic in domain layer, never in infrastructure
- **Async-First**: All I/O operations use async/await
- **Type Safety**: Every function/method must have type hints
- **Error Handling**: Use Result pattern from flext-core
- **Testing**: Every feature requires unit and integration tests

### Documentation Requirements

- **Google-style docstrings** for all public APIs
- **Type hints** for all parameters and return values
- **Examples** in docstrings for complex operations
- **ADRs** for architectural decisions (see `docs/architecture/adr/`)

### Makefile Commands Reference

Essential commands for development:

```bash
make help          # Show all available commands
make setup         # One-time development setup
make check         # All quality checks (required before commit)
make test          # Run all tests with coverage
make coverage      # Generate HTML coverage report
make clean         # Clean build artifacts
make build         # Full build process
make ci            # Run full CI pipeline locally
```
