"""LDAP Domain Protocols - CONSOLIDATED ABSTRACTIONS.

🎯 SOLID CONSOLIDATION: Single source of truth for ALL LDAP abstractions
Following copy→refactor→replace strategy with advanced Python 3.13 + Pydantic.

ELIMINATES MASSIVE DUPLICATIONS:
- FlextLdapDirectoryRepository (domain/interfaces.py:78) → FlextLdapRepository
- FlextLdapGroupRepository (domain/interfaces.py:205) → FlextLdapRepository
- FlextLdapConnectionService (domain/ports.py:21) → FlextLdapConnectionProtocol
- FlextLdapSearchService (domain/ports.py:71) → FlextLdapSearchProtocol
- FlextLdapUserService (domain/ports.py:97) → FlextLdapUserProtocol
- FlextLdapSchemaService (domain/ports.py:149) → FlextLdapSchemaProtocol
- FlextLdapMigrationService (domain/ports.py:171) → FlextLdapMigrationProtocol
- FlextLdapDirectoryServiceInterface (adapters/directory_adapter.py:72) → FlextLdapServiceProtocol
- LdapUserServiceProtocol (protocols.py:286) → FlextLdapUserProtocol
- LdapGroupServiceProtocol (protocols.py:313) → FlextLdapGroupProtocol

This module provides the SINGLE SOURCE OF TRUTH for ALL LDAP abstractions,
using flext-core patterns with LDAP-specific behaviors while maintaining
100% SOLID compliance and eliminating ALL duplications.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING, Protocol, runtime_checkable

# ✅ CORRECT: Import by root from flext-core (not submodules)
from flext_core import (
    FlextIdGenerator,
    FlextResult,
    FlextTypes,
    get_logger,
)

# ✅ CORRECT: Advanced Python 3.13 + Pydantic for extensive validation
from pydantic import BaseModel, ConfigDict, Field, field_validator

if TYPE_CHECKING:
    # ✅ CORRECT: Import existing flext-* libraries by root when available
    # TODO: Replace with flext-ldif when integrated
    # from flext_ldif import FlextLdifExporter, FlextLdifImporter
    # TODO: Replace with flext-observability when integrated
    # from flext_observability import FlextSecurityEventLogger
    # TODO: Replace with flext-auth when integrated
    # from flext_auth import FlextCredentialManager

    from flext_ldap.types import FlextLdapScopeEnum
    from flext_ldap.value_objects import (
        FlextLdapDistinguishedName,
        FlextLdapFilter,
    )

logger = get_logger(__name__)


# =============================================================================
# ADVANCED PYDANTIC MODELS - Python 3.13 + Extensive Validation
# =============================================================================


class FlextLdapConnectionConfigAdvanced(BaseModel):
    """Advanced Pydantic model for LDAP connection configuration.

    Uses Python 3.13 advanced features + extensive Pydantic validation
    as required by user specifications.
    """

    model_config = ConfigDict(
        extra="forbid",  # Python 3.13 Pydantic v2 syntax
        validate_assignment=True,
        validate_default=True,
        str_strip_whitespace=True,
        frozen=False,  # Allow mutation for configuration updates
    )

    server_url: str = Field(
        ...,
        description="LDAP server URL (ldap:// or ldaps://)",
        min_length=1,
        max_length=2048,
    )
    bind_dn: str | None = Field(
        None,
        description="Bind distinguished name (None for anonymous)",
        max_length=1024,
    )
    password: str | None = Field(
        None,
        description="Bind password (None for anonymous)",
        repr=False,  # Security: don't show in repr
    )
    timeout_seconds: int = Field(
        default=30,
        description="Connection timeout in seconds",
        ge=1,
        le=300,
    )
    use_tls: bool = Field(
        default=False,
        description="Use TLS encryption",
    )
    validate_certificates: bool = Field(
        default=True,
        description="Validate SSL/TLS certificates",
    )
    pool_size: int = Field(
        default=5,
        description="Connection pool size",
        ge=1,
        le=100,
    )

    @field_validator("server_url")
    @classmethod
    def validate_server_url(cls, v: str) -> str:
        """Validate LDAP server URL format."""
        if not v.startswith(("ldap://", "ldaps://")):
            msg = "Server URL must start with ldap:// or ldaps://"
            raise ValueError(msg)
        return v

    @field_validator("bind_dn")
    @classmethod
    def validate_bind_dn(cls, v: str | None) -> str | None:
        """Validate bind DN format."""
        if v is not None and not v.strip():
            return None  # Convert empty strings to None
        return v


class FlextLdapSearchConfigAdvanced(BaseModel):
    """Advanced Pydantic model for LDAP search configuration."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
    )

    base_dn: str = Field(
        ...,
        description="Search base distinguished name",
        min_length=1,
        max_length=1024,
    )
    search_filter: str = Field(
        default="(objectClass=*)",
        description="LDAP search filter (RFC 4515 compliant)",
        min_length=1,
        max_length=1024,
    )
    scope: FlextLdapScopeEnum = Field(
        default="subtree",  # Will be converted to enum
        description="Search scope (base, onelevel, subtree)",
    )
    attributes: list[str] | None = Field(
        None,
        description="Attributes to return (None = all)",
    )
    size_limit: int = Field(
        default=1000,
        description="Maximum entries to return",
        ge=0,
        le=10000,
    )
    time_limit: int = Field(
        default=60,
        description="Search timeout in seconds",
        ge=1,
        le=300,
    )

    @field_validator("search_filter")
    @classmethod
    def validate_search_filter(cls, v: str) -> str:
        """Validate LDAP search filter syntax."""
        if not v.startswith("(") or not v.endswith(")"):
            msg = "LDAP filter must be enclosed in parentheses"
            raise ValueError(msg)
        return v


class FlextLdapOperationResult(BaseModel):
    """Advanced Pydantic model for LDAP operation results."""

    model_config = ConfigDict(
        extra="allow",  # Allow additional context data
        validate_assignment=True,
    )

    success: bool = Field(
        ...,
        description="Operation success status",
    )
    entry_count: int = Field(
        default=0,
        description="Number of entries affected/returned",
        ge=0,
    )
    execution_time_ms: float = Field(
        default=0.0,
        description="Execution time in milliseconds",
        ge=0.0,
    )
    server_info: FlextTypes.Core.JsonDict = Field(
        default_factory=dict,
        description="Server information and diagnostics",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Operation warnings",
    )
    operation_id: str = Field(
        default_factory=lambda: FlextIdGenerator.generate_id(),
        description="Unique operation identifier",
    )


# =============================================================================
# CONSOLIDATED REPOSITORY PROTOCOLS - Single Source of Truth
# =============================================================================


@runtime_checkable
class FlextLdapRepositoryProtocol(Protocol):
    """CONSOLIDATED LDAP Repository Protocol extending flext-core patterns.

    🎯 ELIMINATES ALL REPOSITORY DUPLICATIONS:
    - FlextLdapDirectoryRepository (domain/interfaces.py:78)
    - FlextLdapGroupRepository (domain/interfaces.py:205)
    - All scattered repository interfaces across multiple files

    Uses advanced Python 3.13 Protocol with runtime checking as required.
    Extends flext-core FlextRepository patterns without duplication.
    """

    @abstractmethod
    async def search_entries(
        self,
        connection_id: str,
        config: FlextLdapSearchConfigAdvanced,
    ) -> FlextResult[list[FlextTypes.Core.JsonDict]]:
        """Search LDAP directory entries using advanced configuration.

        Args:
            connection_id: Active LDAP connection identifier
            config: Advanced search configuration with validation

        Returns:
            FlextResult containing list of matching LDAP entries

        """
        ...

    @abstractmethod
    async def create_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        attributes: FlextTypes.Core.JsonDict,
    ) -> FlextResult[FlextLdapOperationResult]:
        """Create new LDAP entry with advanced result tracking.

        Args:
            connection_id: Active LDAP connection identifier
            dn: Distinguished name for new entry
            attributes: LDAP attributes with type validation

        Returns:
            FlextResult containing advanced operation result

        """
        ...

    @abstractmethod
    async def modify_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        changes: FlextTypes.Core.JsonDict,
    ) -> FlextResult[FlextLdapOperationResult]:
        """Modify existing LDAP entry with change tracking.

        Args:
            connection_id: Active LDAP connection identifier
            dn: Distinguished name of entry to modify
            changes: Modifications with RFC 4511 compliance

        Returns:
            FlextResult containing operation result with metrics

        """
        ...

    @abstractmethod
    async def delete_entry(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
    ) -> FlextResult[FlextLdapOperationResult]:
        """Delete LDAP entry with audit trail.

        Args:
            connection_id: Active LDAP connection identifier
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult containing deletion result with audit info

        """
        ...

    @abstractmethod
    async def find_entries_by_filter(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        search_filter: FlextLdapFilter,
        *,
        limit: int = 1000,
    ) -> FlextResult[list[FlextTypes.Core.JsonDict]]:
        """Find entries using flexible filter with result limiting.

        Args:
            connection_id: Active LDAP connection identifier
            base_dn: Search base for entry search
            search_filter: Validated LDAP filter
            limit: Maximum entries to return (named-only)

        Returns:
            FlextResult containing matching entries

        """
        ...

    @abstractmethod
    async def batch_operations(
        self,
        connection_id: str,
        operations: list[FlextTypes.Core.JsonDict],
        *,
        atomic: bool = True,
    ) -> FlextResult[list[FlextLdapOperationResult]]:
        """Perform batch LDAP operations with atomicity control.

        Args:
            connection_id: Active LDAP connection identifier
            operations: List of operations to perform
            atomic: If True, rollback all operations on any failure

        Returns:
            FlextResult containing results for each operation

        """
        ...


# =============================================================================
# CONSOLIDATED DOMAIN SERVICE PROTOCOLS - Single Source of Truth
# =============================================================================


@runtime_checkable
class FlextLdapServiceProtocol(Protocol):
    """CONSOLIDATED LDAP Domain Service Protocol extending flext-core patterns.

    🎯 ELIMINATES ALL SERVICE DUPLICATIONS:
    - FlextLdapConnectionService (domain/ports.py:21)
    - FlextLdapSearchService (domain/ports.py:71)
    - FlextLdapUserService (domain/ports.py:97)
    - FlextLdapSchemaService (domain/ports.py:149)
    - FlextLdapMigrationService (domain/ports.py:171)
    - FlextLdapDirectoryServiceInterface (adapters/directory_adapter.py:72)
    - LdapUserServiceProtocol (protocols.py:286)
    - LdapGroupServiceProtocol (protocols.py:313)

    Uses advanced Python 3.13 Protocol extending flext-core patterns.
    """

    # CONNECTION MANAGEMENT OPERATIONS

    @abstractmethod
    async def connect(
        self,
        config: FlextLdapConnectionConfigAdvanced,
    ) -> FlextResult[str]:
        """Establish LDAP connection using advanced configuration.

        Args:
            config: Advanced connection configuration with validation

        Returns:
            FlextResult containing connection ID if successful

        """
        ...

    @abstractmethod
    async def disconnect(
        self,
        connection_id: str,
    ) -> FlextResult[None]:
        """Disconnect from LDAP server with cleanup.

        Args:
            connection_id: Connection identifier to disconnect

        Returns:
            FlextResult indicating success or failure

        """
        ...

    @abstractmethod
    async def test_connection(
        self,
        connection_id: str,
    ) -> FlextResult[FlextTypes.Core.JsonDict]:
        """Test LDAP connection health with diagnostics.

        Args:
            connection_id: Connection identifier to test

        Returns:
            FlextResult containing health status and diagnostics

        """
        ...

    # SCHEMA VALIDATION OPERATIONS

    @abstractmethod
    async def get_schema_info(
        self,
        connection_id: str,
    ) -> FlextResult[FlextTypes.Core.JsonDict]:
        """Get comprehensive LDAP schema information.

        Args:
            connection_id: Active connection identifier

        Returns:
            FlextResult containing schema information with metadata

        """
        ...

    @abstractmethod
    async def validate_entry_against_schema(
        self,
        connection_id: str,
        dn: FlextLdapDistinguishedName,
        attributes: FlextTypes.Core.JsonDict,
    ) -> FlextResult[list[str]]:
        """Validate entry against LDAP schema with detailed errors.

        Args:
            connection_id: Active connection identifier
            dn: Entry distinguished name
            attributes: Entry attributes to validate

        Returns:
            FlextResult containing list of validation errors (empty = valid)

        """
        ...

    # MIGRATION OPERATIONS (DELEGATED TO flext-ldif)

    @abstractmethod
    async def export_to_ldif(
        self,
        connection_id: str,
        base_dn: FlextLdapDistinguishedName,
        search_filter: FlextLdapFilter,
    ) -> FlextResult[str]:
        """Export LDAP entries to LDIF format.

        IMPLEMENTATION REQUIREMENT:
        This method MUST delegate to flext-ldif library:
        ```python
        from flext_ldif import FlextLdifExporter
        exporter = FlextLdifExporter()
        return await exporter.export_entries(...)
        ```

        Args:
            connection_id: Active connection identifier
            base_dn: Export base distinguished name
            search_filter: Filter for entries to export

        Returns:
            FlextResult containing LDIF data as string

        """
        ...

    @abstractmethod
    async def import_from_ldif(
        self,
        connection_id: str,
        ldif_data: str,
        *,
        dry_run: bool = False,
    ) -> FlextResult[FlextTypes.Core.JsonDict]:
        """Import LDAP entries from LDIF format.

        IMPLEMENTATION REQUIREMENT:
        This method MUST delegate to flext-ldif library:
        ```python
        from flext_ldif import FlextLdifImporter
        importer = FlextLdifImporter()
        return await importer.import_entries(...)
        ```

        Args:
            connection_id: Active connection identifier
            ldif_data: LDIF data to import as string
            dry_run: If True, validate only without importing

        Returns:
            FlextResult containing import statistics and results

        """
        ...


# =============================================================================
# SPECIALIZED PROTOCOLS - Advanced Python 3.13 Extensions
# =============================================================================


@runtime_checkable
class FlextLdapConnectionProtocol(FlextLdapServiceProtocol, Protocol):
    """LDAP Connection Management Protocol - Specialized from FlextLdapServiceProtocol."""

    @abstractmethod
    async def manage_connection_pool(
        self,
        config: FlextLdapConnectionConfigAdvanced,
    ) -> FlextResult[FlextTypes.Core.JsonDict]:
        """Manage LDAP connection pool with advanced metrics.

        Args:
            config: Pool configuration with validation

        Returns:
            FlextResult containing pool status and metrics

        """
        ...


@runtime_checkable
class FlextLdapUserProtocol(FlextLdapServiceProtocol, Protocol):
    """LDAP User Management Protocol - Specialized from FlextLdapServiceProtocol."""

    @abstractmethod
    async def create_user_advanced(
        self,
        connection_id: str,
        user_config: BaseModel,  # Will be proper user config model
    ) -> FlextResult[FlextLdapOperationResult]:
        """Create user with advanced validation and tracking.

        Args:
            connection_id: Active connection identifier
            user_config: Advanced user configuration with Pydantic validation

        Returns:
            FlextResult containing user creation result

        """
        ...


@runtime_checkable
class FlextLdapGroupProtocol(FlextLdapServiceProtocol, Protocol):
    """LDAP Group Management Protocol - Specialized from FlextLdapServiceProtocol."""

    @abstractmethod
    async def create_group_advanced(
        self,
        connection_id: str,
        group_config: BaseModel,  # Will be proper group config model
    ) -> FlextResult[FlextLdapOperationResult]:
        """Create group with advanced validation and tracking.

        Args:
            connection_id: Active connection identifier
            group_config: Advanced group configuration with Pydantic validation

        Returns:
            FlextResult containing group creation result

        """
        ...


@runtime_checkable
class FlextLdapSchemaProtocol(FlextLdapServiceProtocol, Protocol):
    """LDAP Schema Validation Protocol - Specialized from FlextLdapServiceProtocol."""

    @abstractmethod
    async def analyze_schema_compliance(
        self,
        connection_id: str,
        compliance_rules: list[str],
    ) -> FlextResult[FlextTypes.Core.JsonDict]:
        """Analyze schema compliance with detailed reporting.

        Args:
            connection_id: Active connection identifier
            compliance_rules: List of compliance rules to check

        Returns:
            FlextResult containing compliance analysis report

        """
        ...


@runtime_checkable
class FlextLdapMigrationProtocol(FlextLdapServiceProtocol, Protocol):
    """LDAP Migration Protocol - Specialized from FlextLdapServiceProtocol."""

    @abstractmethod
    async def migrate_entries_advanced(
        self,
        source_connection_id: str,
        target_connection_id: str,
        migration_config: BaseModel,  # Will be proper migration config model
    ) -> FlextResult[FlextTypes.Core.JsonDict]:
        """Migrate entries between LDAP servers with advanced tracking.

        Args:
            source_connection_id: Source LDAP connection
            target_connection_id: Target LDAP connection
            migration_config: Advanced migration configuration

        Returns:
            FlextResult containing migration results and statistics

        """
        ...


# =============================================================================
# FACTORY PROTOCOLS - DI Library Pattern Requirements
# =============================================================================


@runtime_checkable
class FlextLdapFactoryProtocol(Protocol):
    """Factory Protocol for creating LDAP service instances.

    LIBRARY PATTERN: This follows DI library patterns where factories
    create properly configured service instances, not service implementations.
    """

    @abstractmethod
    def create_repository(self) -> FlextLdapRepositoryProtocol:
        """Create LDAP repository instance.

        Returns:
            Configured LDAP repository following protocol contract

        """
        ...

    @abstractmethod
    def create_service(self) -> FlextLdapServiceProtocol:
        """Create LDAP service instance.

        Returns:
            Configured LDAP service following protocol contract

        """
        ...

    @abstractmethod
    def create_connection_manager(self) -> FlextLdapConnectionProtocol:
        """Create LDAP connection manager instance.

        Returns:
            Configured connection manager following protocol contract

        """
        ...


# =============================================================================
# CONSOLIDATED EXPORTS - SINGLE SOURCE OF TRUTH
# =============================================================================

__all__ = [
    # Advanced Pydantic Models - Python 3.13 + Extensive Validation
    "FlextLdapConnectionConfigAdvanced",
    # Specialized Protocols - Advanced Extensions
    "FlextLdapConnectionProtocol",
    # Factory Protocol - DI Library Pattern
    "FlextLdapFactoryProtocol",
    "FlextLdapGroupProtocol",
    "FlextLdapMigrationProtocol",
    "FlextLdapOperationResult",
    # Core Protocols - Consolidated Abstractions
    "FlextLdapRepositoryProtocol",
    "FlextLdapSchemaProtocol",
    "FlextLdapSearchConfigAdvanced",
    "FlextLdapServiceProtocol",
    "FlextLdapUserProtocol",
]
