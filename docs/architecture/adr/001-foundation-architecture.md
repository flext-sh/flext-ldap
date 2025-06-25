# ADR-001: Core Foundation Architecture

**The architectural foundation that will make this the ultimate Python LDAP library**

## 📋 Status

**APPROVED** - Critical infrastructure decision

## 🎯 Context

Based on extensive analysis of our current `src/ldap_core_shared/` implementation and study of 57+ existing LDAP implementations, we need to establish the fundamental architectural patterns that will support enterprise-grade performance, maintainability, and extensibility.

### 🔍 **Current State Analysis**

Our existing architecture in `src/ldap_core_shared/` shows:

- ✅ **Good modular separation**: `core/`, `ldif/`, `schema/`, `utils/`
- ✅ **Enterprise patterns**: Connection pooling, performance monitoring
- ✅ **Modern Python**: Type hints, Pydantic models, async support
- ❌ **Needs enhancement**: Cleaner abstractions, plugin architecture, better error handling

### 🏆 **Best Practices from Analysis**

From studying 57+ implementations, the winning patterns are:

- **Layered Architecture**: Clean separation of concerns
- **Repository Pattern**: Abstract data access
- **Factory Pattern**: Object creation and configuration
- **Observer Pattern**: Event-driven monitoring
- **Strategy Pattern**: Pluggable algorithms

## 🎯 Decision

**We will implement a clean layered architecture with enterprise patterns that scales from simple scripts to complex enterprise applications.**

### 🏗️ **Core Architecture Layers**

```python
"""
🏗️ Foundation Architecture - 4 Core Layers
"""

# Layer 1: Infrastructure (Bottom Layer)
Infrastructure_Layer = {
    "connection_management": "Raw LDAP connections and pooling",
    "network_protocols": "TCP/TLS/SSL handling",
    "authentication": "All auth methods (Simple, SASL, Kerberos)",
    "security": "Encryption, certificates, SSH tunnels",
    "monitoring": "Metrics, health checks, tracing"
}

# Layer 2: Domain (Business Logic)
Domain_Layer = {
    "ldap_operations": "Core LDAP operations abstraction",
    "schema_models": "Schema representation and validation",
    "ldif_models": "LDIF entry and change models",
    "filter_models": "Search filter abstractions",
    "dn_models": "Distinguished Name handling"
}

# Layer 3: Application Services (Use Cases)
Application_Layer = {
    "search_service": "High-level search operations",
    "schema_service": "Schema discovery and management",
    "ldif_service": "LDIF processing and transformation",
    "bulk_operations": "Bulk import/export operations",
    "migration_service": "Schema and data migration"
}

# Layer 4: Interface (Top Layer)
Interface_Layer = {
    "public_api": "User-facing API with fluent interface",
    "integrations": "Framework integrations (Django, Flask, etc.)",
    "cli_tools": "Command-line utilities",
    "plugins": "Extension points for custom functionality"
}
```

### 🎨 **Design Patterns Implementation**

#### 1. **Repository Pattern** - Data Access Abstraction

```python
from abc import ABC, abstractmethod
from typing import List, Optional, AsyncIterator

class LDAPRepository(ABC):
    """Abstract repository for LDAP operations."""

    @abstractmethod
    async def find_by_dn(self, dn: str) -> Optional[LDAPEntry]:
        """Find entry by Distinguished Name."""

    @abstractmethod
    async def find_by_filter(self,
                           base_dn: str,
                           filter_query: Filter,
                           scope: SearchScope = SearchScope.SUBTREE) -> List[LDAPEntry]:
        """Find entries matching filter."""

    @abstractmethod
    async def save(self, entry: LDAPEntry) -> OperationResult:
        """Save entry (add or modify)."""

    @abstractmethod
    async def delete(self, dn: str) -> OperationResult:
        """Delete entry by DN."""

    @abstractmethod
    async def stream_search(self,
                          base_dn: str,
                          filter_query: Filter) -> AsyncIterator[LDAPEntry]:
        """Stream search results for memory efficiency."""

class CachedLDAPRepository(LDAPRepository):
    """Repository with intelligent caching."""

    def __init__(self,
                 base_repository: LDAPRepository,
                 cache: CacheInterface,
                 ttl: int = 300):
        self._base = base_repository
        self._cache = cache
        self._ttl = ttl

    async def find_by_dn(self, dn: str) -> Optional[LDAPEntry]:
        # Try cache first
        cached = await self._cache.get(f"dn:{dn}")
        if cached:
            return LDAPEntry.model_validate(cached)

        # Fallback to base repository
        entry = await self._base.find_by_dn(dn)
        if entry:
            await self._cache.set(f"dn:{dn}", entry.model_dump(), ttl=self._ttl)
        return entry
```

#### 2. **Factory Pattern** - Object Creation

```python
class ConnectionFactory:
    """Factory for creating optimized LDAP connections."""

    @classmethod
    async def create_pooled_connection(cls,
                                     config: ConnectionConfig) -> PooledConnection:
        """Create connection with enterprise pooling."""
        pool = await ConnectionPool.create(
            servers=config.servers,
            pool_size=config.pool_size,
            max_pool_size=config.max_pool_size,
            health_check_interval=config.health_check_interval
        )
        return PooledConnection(pool)

    @classmethod
    async def create_simple_connection(cls,
                                     url: str,
                                     credentials: Credentials) -> SimpleConnection:
        """Create simple connection for basic use cases."""
        return SimpleConnection(url, credentials)

    @classmethod
    async def create_load_balanced_connection(cls,
                                            servers: List[str],
                                            strategy: LoadBalanceStrategy) -> LoadBalancedConnection:
        """Create connection with load balancing."""
        return LoadBalancedConnection(servers, strategy)

class RepositoryFactory:
    """Factory for creating specialized repositories."""

    @classmethod
    def create_cached_repository(cls,
                               connection: Connection,
                               cache_config: CacheConfig) -> CachedLDAPRepository:
        """Create repository with caching."""
        base_repo = StandardLDAPRepository(connection)
        cache = CacheFactory.create_cache(cache_config)
        return CachedLDAPRepository(base_repo, cache)

    @classmethod
    def create_read_only_repository(cls,
                                  connection: Connection) -> ReadOnlyLDAPRepository:
        """Create read-only repository for safety."""
        return ReadOnlyLDAPRepository(connection)
```

#### 3. **Observer Pattern** - Event-Driven Monitoring

```python
from typing import List, Callable
from enum import Enum

class LDAPEvent(Enum):
    CONNECTION_ESTABLISHED = "connection_established"
    CONNECTION_LOST = "connection_lost"
    OPERATION_STARTED = "operation_started"
    OPERATION_COMPLETED = "operation_completed"
    OPERATION_FAILED = "operation_failed"
    POOL_EXHAUSTED = "pool_exhausted"
    HEALTH_CHECK_FAILED = "health_check_failed"

class EventObserver(ABC):
    """Abstract observer for LDAP events."""

    @abstractmethod
    async def handle_event(self, event: LDAPEvent, data: dict) -> None:
        """Handle LDAP event."""

class PerformanceMonitorObserver(EventObserver):
    """Observer that tracks performance metrics."""

    async def handle_event(self, event: LDAPEvent, data: dict) -> None:
        if event == LDAPEvent.OPERATION_COMPLETED:
            await self._record_operation_metrics(data)
        elif event == LDAPEvent.CONNECTION_ESTABLISHED:
            await self._record_connection_metrics(data)

class AlertingObserver(EventObserver):
    """Observer that sends alerts for critical events."""

    async def handle_event(self, event: LDAPEvent, data: dict) -> None:
        if event in [LDAPEvent.POOL_EXHAUSTED, LDAPEvent.HEALTH_CHECK_FAILED]:
            await self._send_alert(event, data)

class EventBus:
    """Central event bus for LDAP events."""

    def __init__(self):
        self._observers: List[EventObserver] = []

    def subscribe(self, observer: EventObserver) -> None:
        """Subscribe observer to events."""
        self._observers.append(observer)

    async def publish(self, event: LDAPEvent, data: dict) -> None:
        """Publish event to all observers."""
        for observer in self._observers:
            try:
                await observer.handle_event(event, data)
            except Exception as e:
                logger.warning(f"Observer {observer} failed to handle event {event}: {e}")
```

#### 4. **Strategy Pattern** - Pluggable Algorithms

```python
class SearchStrategy(ABC):
    """Abstract strategy for search optimization."""

    @abstractmethod
    async def execute_search(self,
                           repository: LDAPRepository,
                           query: SearchQuery) -> SearchResult:
        """Execute search with specific strategy."""

class CachedSearchStrategy(SearchStrategy):
    """Search strategy with intelligent caching."""

    async def execute_search(self, repository: LDAPRepository, query: SearchQuery) -> SearchResult:
        cache_key = self._generate_cache_key(query)

        # Try cache first
        cached_result = await self._cache.get(cache_key)
        if cached_result and not self._is_stale(cached_result):
            return SearchResult.from_cache(cached_result)

        # Execute fresh search
        result = await repository.find_by_filter(query.base_dn, query.filter, query.scope)

        # Cache result
        await self._cache.set(cache_key, result, ttl=query.cache_ttl)

        return SearchResult(entries=result, from_cache=False)

class StreamingSearchStrategy(SearchStrategy):
    """Search strategy optimized for large result sets."""

    async def execute_search(self, repository: LDAPRepository, query: SearchQuery) -> SearchResult:
        # Use streaming for memory efficiency
        entries = []
        async for entry in repository.stream_search(query.base_dn, query.filter):
            entries.append(entry)

            # Yield partial results for immediate processing
            if len(entries) >= query.batch_size:
                yield SearchResult(entries=entries, partial=True)
                entries = []

        # Yield final batch
        if entries:
            yield SearchResult(entries=entries, partial=False)
```

### 🔧 **Dependency Injection Container**

```python
class DIContainer:
    """Dependency injection container for clean architecture."""

    def __init__(self):
        self._services: Dict[str, Any] = {}
        self._factories: Dict[str, Callable] = {}

    def register_singleton(self, interface: type, implementation: Any) -> None:
        """Register singleton service."""
        self._services[interface.__name__] = implementation

    def register_factory(self, interface: type, factory: Callable) -> None:
        """Register factory for service creation."""
        self._factories[interface.__name__] = factory

    def get(self, interface: type) -> Any:
        """Get service instance."""
        service_name = interface.__name__

        # Return singleton if available
        if service_name in self._services:
            return self._services[service_name]

        # Create using factory
        if service_name in self._factories:
            service = self._factories[service_name]()
            return service

        raise ValueError(f"Service {service_name} not registered")

# Example usage
container = DIContainer()

# Register core services
container.register_singleton(EventBus, EventBus())
container.register_factory(LDAPRepository, lambda: RepositoryFactory.create_cached_repository(...))
container.register_factory(ConnectionFactory, lambda: ConnectionFactory())
```

### 📦 **Module Structure Implementation**

```python
"""
🏗️ Foundation Module Structure
"""

ldap_enterprise_ultra/
├── 🔧 foundation/              # Core foundation layer
│   ├── __init__.py
│   ├── architecture.py         # Base architecture patterns
│   ├── dependency_injection.py # DI container
│   ├── event_system.py         # Event bus and observers
│   └── patterns/               # Design pattern implementations
│       ├── repository.py       # Repository pattern
│       ├── factory.py          # Factory patterns
│       ├── strategy.py         # Strategy pattern
│       └── observer.py         # Observer pattern
│
├── 🌐 interfaces/              # Abstract interfaces
│   ├── __init__.py
│   ├── repository.py           # Repository interfaces
│   ├── connection.py           # Connection interfaces
│   ├── cache.py               # Cache interfaces
│   └── monitoring.py          # Monitoring interfaces
│
├── 📊 domain/                  # Domain models and logic
│   ├── __init__.py
│   ├── models/                # Domain models
│   │   ├── entry.py           # LDAP entry models
│   │   ├── schema.py          # Schema models
│   │   ├── filter.py          # Filter models
│   │   └── result.py          # Result models
│   ├── services/              # Domain services
│   │   ├── validation.py      # Validation logic
│   │   ├── transformation.py  # Data transformation
│   │   └── business_rules.py  # Business rule validation
│   └── exceptions.py          # Domain exceptions
│
├── 🔌 infrastructure/         # Infrastructure layer
│   ├── __init__.py
│   ├── connections/           # Connection implementations
│   ├── repositories/          # Repository implementations
│   ├── caching/              # Cache implementations
│   ├── monitoring/           # Monitoring implementations
│   └── external/             # External service integrations
│
└── 🎯 application/           # Application services
    ├── __init__.py
    ├── services/             # Application services
    ├── use_cases/           # Use case implementations
    └── handlers/            # Command/query handlers
```

## 🎯 Consequences

### ✅ **Positive Outcomes**

1. **🚀 Scalability**: Architecture scales from simple scripts to enterprise applications
2. **🔧 Maintainability**: Clear separation of concerns and dependency injection
3. **🧪 Testability**: Each layer can be tested independently with mocks
4. **🔄 Extensibility**: Plugin architecture allows custom implementations
5. **📈 Performance**: Strategy pattern enables optimization without code changes
6. **🔍 Observability**: Event-driven monitoring provides comprehensive insights

### ⚠️ **Potential Challenges**

1. **📚 Complexity**: More complex than simple procedural code
2. **📖 Learning Curve**: Developers need to understand architectural patterns
3. **🏗️ Initial Setup**: More upfront work to establish patterns
4. **🔧 Overhead**: Additional abstraction layers may impact performance

### 🛡️ **Risk Mitigation**

1. **📚 Comprehensive Documentation**: Detailed guides and examples
2. **🎯 Simplified API**: High-level API hides complexity for simple use cases
3. **📊 Performance Monitoring**: Continuous monitoring to ensure overhead is minimal
4. **🧪 Extensive Testing**: Validate architecture with real-world scenarios

## 🚀 Implementation Plan

### 📅 **Phase 1: Core Foundation (Week 1-2)**

```python
# Implementation priorities
Foundation_Tasks = [
    "✅ Create base architecture patterns",
    "✅ Implement dependency injection container",
    "✅ Set up event system and observers",
    "✅ Define core interfaces",
    "✅ Create domain model foundation"
]
```

### 📅 **Phase 2: Infrastructure (Week 3-4)**

```python
Infrastructure_Tasks = [
    "✅ Implement repository pattern",
    "✅ Create connection factory",
    "✅ Set up caching infrastructure",
    "✅ Build monitoring foundation",
    "✅ Create testing framework"
]
```

### 📅 **Phase 3: Validation (Week 5-6)**

```python
Validation_Tasks = [
    "✅ Performance benchmarking",
    "✅ Architecture validation with real scenarios",
    "✅ Documentation and examples",
    "✅ Team training and adoption",
    "✅ Continuous integration setup"
]
```

## 🔗 Related ADRs

- **[ADR-002: Async-First Design](002-async-first-design.md)** - Builds on this foundation
- **[ADR-003: Connection Management](003-connection-management.md)** - Implements connection patterns
- **[ADR-005: Testing Framework](005-testing-framework.md)** - Testing strategy for this architecture

## 🏢 Enterprise Enhancements from FLX Meltano Enterprise

### 🔧 **Dual Dependency Injection Architecture**

Based on insights from the FLX Meltano Enterprise project, we enhance our foundation with a sophisticated dual DI approach:

```python
# Enhanced DI Architecture combining Lato (domain) + Dependency Injector (infrastructure)
from lato import Command, CommandHandler
from dependency_injector import providers, containers
from dependency_injector.wiring import inject, Provide

class LDAPCommand(BaseModel, Command):
    """Base LDAP command with Pydantic validation."""
    model_config = ConfigDict(frozen=True)  # Immutable commands

class SearchCommand(LDAPCommand):
    """LDAP search command."""
    base_dn: str = Field(..., min_length=1)
    filter_query: str = Field(...)
    attributes: List[str] = Field(default_factory=list)
    scope: SearchScope = SearchScope.SUBTREE

# Universal Command Handler supporting CLI, API, and library interfaces
@inject
async def search_handler(
    command: SearchCommand,  # Lato command with Pydantic validation
    repository: LDAPRepository = Provide[Container.repositories.ldap],
    monitor: PerformanceMonitor = Provide[Container.infrastructure.monitoring],
    publish,  # Lato event publishing
) -> SearchResult:
    """Handle search command across all protocols."""

    async with monitor.track_operation("ldap_search"):
        result = await repository.search(
            command.base_dn,
            command.filter_query,
            command.attributes,
            command.scope
        )

        # Publish domain event
        await publish(SearchCompletedEvent(
            base_dn=command.base_dn,
            entry_count=len(result.entries),
            duration=monitor.last_operation_duration
        ))

        return result

# Container Configuration
class LDAPContainer(containers.DeclarativeContainer):
    """Enterprise DI container for LDAP operations."""

    # Configuration providers
    config = providers.Configuration()

    # Infrastructure providers
    connection_pool = providers.Singleton(
        AsyncConnectionPool,
        config.connection.servers,
        min_size=config.connection.pool_min_size,
        max_size=config.connection.pool_max_size
    )

    performance_monitor = providers.Singleton(
        PerformanceMonitor,
        enable_metrics=config.monitoring.enable_metrics
    )

    # Repository providers
    repositories = providers.DependenciesContainer()
    repositories.ldap = providers.Factory(
        CachedLDAPRepository,
        connection_pool=connection_pool,
        cache_config=config.cache
    )

    # Infrastructure container
    infrastructure = providers.DependenciesContainer()
    infrastructure.monitoring = performance_monitor
    infrastructure.unit_of_work = providers.Factory(LDAPUnitOfWork)
```

### 📊 **Implementation Reality Tracking**

Following FLX Meltano's approach of honest implementation assessment:

```python
Foundation_Implementation_Status = {
    "architectural_components": {
        "repository_pattern": {
            "design_quality": "✅ Excellent",
            "implementation_status": "🟡 75% Complete",
            "production_ready": "⚠️ Caching gaps",
            "next_milestone": "Complete cache invalidation strategy"
        },
        "dependency_injection": {
            "design_quality": "✅ Excellent",
            "implementation_status": "🟡 60% Complete",
            "production_ready": "❌ Container not wired",
            "next_milestone": "Wire all infrastructure components"
        },
        "event_system": {
            "design_quality": "✅ Excellent",
            "implementation_status": "🔴 30% Complete",
            "production_ready": "❌ Core observer missing",
            "next_milestone": "Implement EventBus and base observers"
        },
        "async_patterns": {
            "design_quality": "✅ Excellent",
            "implementation_status": "✅ 85% Complete",
            "production_ready": "✅ Yes",
            "next_milestone": "Performance optimization"
        }
    }
}
```

### 🔒 **Zero Tolerance Quality Standards**

Enhanced quality enforcement inspired by FLX enterprise standards:

```python
# Enhanced quality configuration
[tool.ruff]
select = ["ALL"]  # Enable ALL rules for maximum quality
ignore = [
    "D100",  # Allow missing docstrings in specific cases
    "D104",  # Allow missing docstrings in __init__.py
]

# Enterprise-grade type checking
[tool.mypy]
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true

# Production deployment gates
Quality_Gates = {
    "code_quality": {
        "ruff_violations": "0 errors, 0 warnings",
        "mypy_compliance": "100% strict compliance",
        "test_coverage": "> 95%",
        "security_scan": "0 vulnerabilities"
    },
    "performance": {
        "startup_time": "< 100ms",
        "memory_footprint": "< 50MB baseline",
        "operation_latency": "< 10ms P95"
    },
    "production_readiness": {
        "documentation": "100% API coverage",
        "monitoring": "Full observability stack",
        "security": "Enterprise compliance validated"
    }
}
```

## 📊 Success Metrics

```python
Architecture_Success_Metrics = {
    "maintainability": {
        "cyclomatic_complexity": "< 10 per function",
        "coupling": "< 5 dependencies per module",
        "cohesion": "> 80% related functionality per module",
        "technical_debt_ratio": "< 5%",
        "documentation_coverage": "100%"
    },
    "performance": {
        "startup_time": "< 100ms",
        "memory_overhead": "< 10MB base",
        "operation_overhead": "< 5% vs direct implementation",
        "connection_pool_efficiency": "> 95%",
        "cache_hit_ratio": "> 80%"
    },
    "testability": {
        "test_coverage": "> 95%",
        "mock_ability": "All external dependencies mockable",
        "test_speed": "< 1s for unit test suite",
        "property_test_iterations": "> 1000 per property",
        "integration_test_stability": "> 99.5%"
    },
    "enterprise_readiness": {
        "security_compliance": "100% enterprise standards",
        "observability": "Full metrics/tracing/logging",
        "scalability": "Handle 10M+ entries",
        "availability": "> 99.9% uptime"
    }
}
```

---

**🎯 This foundation architecture decision establishes the bedrock for the ultimate Python LDAP library.** Every subsequent ADR builds upon these patterns to create an enterprise-grade, maintainable, and high-performance solution.

**Decision Maker**: Architecture Team
**Date**: 2025-06-24
**Status**: ✅ APPROVED
**Next Review**: Post Phase 1 implementation (Q1 2025)
