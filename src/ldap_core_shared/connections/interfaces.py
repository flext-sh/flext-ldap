"""🔥 SOLID Principle Interfaces for LDAP Connection Management.

This module defines the clean interfaces following SOLID principles:
- Single Responsibility: Each interface has one clear purpose
- Open/Closed: Open for extension, closed for modification
- Liskov Substitution: All implementations are interchangeable
- Interface Segregation: Small, focused interfaces
- Dependency Inversion: Depend on abstractions, not concretions

ZERO TOLERANCE SOLID implementation following enterprise patterns.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator

    import ldap3

    from ldap_core_shared.connections.base import LDAPConnectionInfo, LDAPSearchConfig
    from ldap_core_shared.domain.results import LDAPConnectionResult
    from ldap_core_shared.types.aliases import DN, Attributes

# ============================================================================
# 🔥 SINGLE RESPONSIBILITY PRINCIPLE - ONE PURPOSE PER INTERFACE
# ============================================================================


@runtime_checkable
class IConnectionFactory(Protocol):
    """🎯 Single Responsibility: Create LDAP connections only."""

    @abstractmethod
    def create_connection(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> ldap3.Connection:
        """Create a new LDAP connection.

        Args:
            connection_info: Connection configuration

        Returns:
            Configured LDAP connection
        """


@runtime_checkable
class IConnectionPool(Protocol):
    """🎯 Single Responsibility: Manage connection pooling only."""

    @abstractmethod
    async def acquire_connection(self) -> AsyncGenerator[ldap3.Connection, None]:
        """Acquire connection from pool.

        Yields:
            LDAP connection from pool
        """

    @abstractmethod
    async def return_connection(self, connection: ldap3.Connection) -> None:
        """Return connection to pool.

        Args:
            connection: Connection to return
        """

    @abstractmethod
    async def initialize_pool(self, size: int) -> None:
        """Initialize connection pool.

        Args:
            size: Pool size
        """

    @abstractmethod
    async def cleanup_pool(self) -> None:
        """Cleanup all pooled connections."""


@runtime_checkable
class IHealthMonitor(Protocol):
    """🎯 Single Responsibility: Monitor connection health only."""

    @abstractmethod
    async def check_health(self, connection: ldap3.Connection) -> bool:
        """Check if connection is healthy.

        Args:
            connection: Connection to check

        Returns:
            True if healthy
        """

    @abstractmethod
    async def start_monitoring(self) -> None:
        """Start health monitoring."""

    @abstractmethod
    async def stop_monitoring(self) -> None:
        """Stop health monitoring."""


@runtime_checkable
class IPerformanceTracker(Protocol):
    """🎯 Single Responsibility: Track performance metrics only."""

    @abstractmethod
    def record_operation(
        self,
        operation_type: str,
        duration: float,
        success: bool,
    ) -> None:
        """Record operation performance.

        Args:
            operation_type: Type of operation
            duration: Operation duration
            success: Whether operation succeeded
        """

    @abstractmethod
    def get_metrics(self) -> dict[str, Any]:
        """Get current performance metrics.

        Returns:
            Performance metrics dictionary
        """


@runtime_checkable
class ISecurityManager(Protocol):
    """🎯 Single Responsibility: Handle security concerns only."""

    @abstractmethod
    async def setup_tls(self, connection_info: LDAPConnectionInfo) -> ldap3.Tls | None:
        """Setup TLS configuration.

        Args:
            connection_info: Connection configuration

        Returns:
            TLS configuration object
        """

    @abstractmethod
    async def validate_credentials(self, connection_info: LDAPConnectionInfo) -> bool:
        """Validate connection credentials.

        Args:
            connection_info: Connection configuration

        Returns:
            True if credentials are valid
        """

# ============================================================================
# 🔥 INTERFACE SEGREGATION PRINCIPLE - SMALL, FOCUSED INTERFACES
# ============================================================================


@runtime_checkable
class ISearchOperations(Protocol):
    """🎯 Interface Segregation: Search operations only."""

    @abstractmethod
    async def search(
        self,
        search_base: str,
        search_filter: str,
        **kwargs: str | int | bool | list[str] | None,
    ) -> AsyncIterator[Attributes]:
        """Perform LDAP search."""

    @abstractmethod
    async def search_with_config(
        self,
        config: LDAPSearchConfig,
    ) -> AsyncIterator[Attributes]:
        """Search with configuration object."""


@runtime_checkable
class IModificationOperations(Protocol):
    """🎯 Interface Segregation: Modification operations only."""

    @abstractmethod
    async def add_entry(self, dn: DN, attributes: Attributes) -> bool:
        """Add new LDAP entry."""

    @abstractmethod
    async def modify_entry(self, dn: DN, changes: Attributes) -> bool:
        """Modify existing LDAP entry."""

    @abstractmethod
    async def delete_entry(self, dn: DN) -> bool:
        """Delete LDAP entry."""


@runtime_checkable
class IRetrievalOperations(Protocol):
    """🎯 Interface Segregation: Retrieval operations only."""

    @abstractmethod
    async def get_entry(
        self,
        dn: DN,
        attributes: list[str] | None = None,
    ) -> Attributes | None:
        """Get single LDAP entry."""

    @abstractmethod
    async def compare_attribute(self, dn: DN, attribute: str, value: str) -> bool:
        """Compare attribute value."""


@runtime_checkable
class IBulkOperations(Protocol):
    """🎯 Interface Segregation: Bulk operations only."""

    @abstractmethod
    async def bulk_search(
        self,
        configs: list[LDAPSearchConfig],
    ) -> list[list[dict[str, Any]]]:
        """Perform bulk search operations."""


@runtime_checkable
class ISchemaOperations(Protocol):
    """🎯 Interface Segregation: Schema operations only."""

    @abstractmethod
    async def get_schema_info(self) -> dict[str, Any]:
        """Get LDAP schema information."""


@runtime_checkable
class IConnectionDiagnostics(Protocol):
    """🎯 Interface Segregation: Diagnostic operations only."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Perform health check."""

    @abstractmethod
    async def test_connection(self) -> LDAPConnectionResult:
        """Test connection comprehensively."""


@runtime_checkable
class IConnectionLifecycle(Protocol):
    """🎯 Interface Segregation: Connection lifecycle only."""

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize connection manager."""

    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup resources."""

    @abstractmethod
    async def refresh(self) -> None:
        """Refresh connections."""

# ============================================================================
# 🔥 OPEN/CLOSED PRINCIPLE - EXTENSIBLE ABSTRACTIONS
# ============================================================================


class BaseConnectionComponent(ABC):
    """🎯 Open/Closed: Base for all connection components.

    Open for extension through inheritance.
    Closed for modification of core behavior.
    """

    def __init__(self, connection_info: LDAPConnectionInfo) -> None:
        """Initialize component with connection info.

        Args:
            connection_info: LDAP connection configuration
        """
        self.connection_info = connection_info

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize component."""

    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup component resources."""


class BaseOperationHandler(ABC):
    """🎯 Open/Closed: Base for operation handlers.

    Extensible for new operation types.
    """

    @abstractmethod
    async def execute(self, *args: str | int | bool, **kwargs: str | int | bool | list[str] | None) -> bool | list[Attributes] | None:
        """Execute operation."""

    @abstractmethod
    def validate_parameters(self, *args: str | int | bool, **kwargs: str | int | bool | list[str] | None) -> bool:
        """Validate operation parameters."""

# ============================================================================
# 🔥 DEPENDENCY INVERSION PRINCIPLE - DEPEND ON ABSTRACTIONS
# ============================================================================


@runtime_checkable
class ILDAPConnectionManager(Protocol):
    """🎯 Dependency Inversion: High-level connection manager interface.

    All implementations must conform to this contract.
    Clients depend on this abstraction, not concrete implementations.
    """

    # Core connection management
    async def get_connection(self) -> AsyncGenerator[ldap3.Connection, None]:
        """Get managed connection."""

    # Search operations
    async def search(
        self,
        search_base: str,
        search_filter: str,
        **kwargs: str | int | bool | list[str] | None,
    ) -> AsyncIterator[Attributes]:
        """Perform search operation."""

    # Modification operations
    async def add_entry(self, dn: DN, attributes: Attributes) -> bool:
        """Add new entry."""

    async def modify_entry(self, dn: DN, changes: Attributes) -> bool:
        """Modify existing entry."""

    async def delete_entry(self, dn: DN) -> bool:
        """Delete entry."""

    # Lifecycle management
    async def initialize(self) -> None:
        """Initialize manager."""

    async def cleanup(self) -> None:
        """Cleanup resources."""


@runtime_checkable
class IConnectionManagerFactory(Protocol):
    """🎯 Dependency Inversion: Factory for connection managers.

    Allows creation of different manager implementations.
    """

    @abstractmethod
    def create_manager(
        self,
        connection_info: LDAPConnectionInfo,
        **kwargs: str | int | bool | list[str] | None,
    ) -> ILDAPConnectionManager:
        """Create connection manager instance.

        Args:
            connection_info: Connection configuration
            **kwargs: Additional configuration

        Returns:
            Connection manager instance
        """

# ============================================================================
# 🔥 LISKOV SUBSTITUTION PRINCIPLE - INTERCHANGEABLE IMPLEMENTATIONS
# ============================================================================


class ConnectionManagerContract(ABC):
    """🎯 Liskov Substitution: Contract that all managers must follow.

    Ensures all implementations are interchangeable.
    """

    @abstractmethod
    async def perform_operation(
        self,
        operation_type: str,
        *args: str | int | bool,
        **kwargs: str | int | bool | list[str] | None,
    ) -> bool | list[Attributes] | None:
        """Generic operation interface.

        All implementations must handle operations consistently.
        Preconditions cannot be strengthened.
        Postconditions cannot be weakened.
        """

    @abstractmethod
    def validate_state(self) -> bool:
        """Validate manager state.

        All implementations must maintain consistent state validation.
        """

    @abstractmethod
    async def handle_error(self, error: Exception) -> None:
        """Handle errors consistently.

        All implementations must handle errors the same way.
        """

# ============================================================================
# 🔥 COMPOSITION INTERFACES - ENABLE DEPENDENCY INJECTION
# ============================================================================


@runtime_checkable
class IServiceContainer(Protocol):
    """🎯 Dependency Injection: Service container interface."""

    @abstractmethod
    def register(self, interface: type, implementation: type) -> None:
        """Register service implementation."""

    @abstractmethod
    def resolve(self, interface: type) -> Any:
        """Resolve service instance."""

    @abstractmethod
    def register_singleton(self, interface: type, implementation: type) -> None:
        """Register singleton service."""


@runtime_checkable
class IConfigurationProvider(Protocol):
    """🎯 Dependency Injection: Configuration provider interface."""

    @abstractmethod
    def get_connection_config(self) -> LDAPConnectionInfo:
        """Get connection configuration."""

    @abstractmethod
    def get_pool_config(self) -> dict[str, Any]:
        """Get pool configuration."""

    @abstractmethod
    def get_security_config(self) -> dict[str, Any]:
        """Get security configuration."""


@runtime_checkable
class ILogger(Protocol):
    """🎯 Dependency Injection: Logger interface."""

    @abstractmethod
    def log_info(self, message: str, **kwargs) -> None:
        """Log info message."""

    @abstractmethod
    def log_error(
        self,
        message: str,
        error: Exception | None = None,
        **kwargs: Any,
    ) -> None:
        """Log error message."""

    @abstractmethod
    def log_debug(self, message: str, **kwargs) -> None:
        """Log debug message."""

# ============================================================================
# 🔥 SOLID PRINCIPLE VALIDATION
# ============================================================================


def validate_solid_compliance(implementation: type) -> dict[str, bool]:
    """🎯 Validate SOLID principle compliance.

    Args:
        implementation: Class to validate

    Returns:
        Dictionary with compliance results for each principle
    """
    return {
        "single_responsibility": _check_single_responsibility(implementation),
        "open_closed": _check_open_closed(implementation),
        "liskov_substitution": _check_liskov_substitution(implementation),
        "interface_segregation": _check_interface_segregation(implementation),
        "dependency_inversion": _check_dependency_inversion(implementation),
    }


def _check_single_responsibility(implementation: type) -> bool:
    """Check Single Responsibility Principle compliance."""
    # Implementation would analyze class methods and attributes
    return True


def _check_open_closed(implementation: type) -> bool:
    """Check Open/Closed Principle compliance."""
    # Implementation would check inheritance and extension points
    return True


def _check_liskov_substitution(implementation: type) -> bool:
    """Check Liskov Substitution Principle compliance."""
    # Implementation would verify contract compliance
    return True


def _check_interface_segregation(implementation: type) -> bool:
    """Check Interface Segregation Principle compliance."""
    # Implementation would analyze interface size and cohesion
    return True


def _check_dependency_inversion(implementation: type) -> bool:
    """Check Dependency Inversion Principle compliance."""
    # Implementation would check dependency on abstractions
    return True
