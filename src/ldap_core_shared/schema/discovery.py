from __future__ import annotations

from ldap_core_shared.utils.constants import DEFAULT_TIMEOUT_SECONDS

"""Schema Discovery - Discover LDAP schemas from servers."""


import logging
from typing import TYPE_CHECKING

import ldap3
from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.domain.results import LDAPOperationResult
from ldap_core_shared.utils.performance import PerformanceMonitor

# Constants for magic values

if TYPE_CHECKING:
    from ldap_core_shared.core.connection_manager import ConnectionInfo

logger = logging.getLogger(__name__)


class SchemaDiscoveryConfig(BaseModel):
    """Configuration for schema discovery operations."""

    model_config = ConfigDict(strict=True, extra="forbid")

    include_attribute_types: bool = Field(
        default=True,
        description="Include attribute types",
    )
    include_object_classes: bool = Field(
        default=True,
        description="Include object classes",
    )
    include_syntax_definitions: bool = Field(
        default=True,
        description="Include syntax definitions",
    )
    include_matching_rules: bool = Field(
        default=True,
        description="Include matching rules",
    )
    timeout_seconds: int = Field(
        default=DEFAULT_TIMEOUT_SECONDS,
        ge=1,
        description="Discovery timeout",
    )


class SchemaInfo(BaseModel):
    """Information about discovered schema."""

    model_config = ConfigDict(strict=True, extra="forbid")

    server_info: str = Field(default="", description="Server information")
    schema_dn: str = Field(default="", description="Schema DN")
    attribute_types: list[str] = Field(
        default_factory=list,
        description="Attribute type definitions",
    )
    object_classes: list[str] = Field(
        default_factory=list,
        description="Object class definitions",
    )
    syntax_definitions: list[str] = Field(
        default_factory=list,
        description="Syntax definitions",
    )
    matching_rules: list[str] = Field(
        default_factory=list,
        description="Matching rule definitions",
    )
    server_controls: list[str] = Field(
        default_factory=list,
        description="Supported server controls",
    )
    extensions: list[str] = Field(default_factory=list, description="Server extensions")


class SchemaDiscovery:
    """Discover LDAP schemas from servers."""

    def __init__(self, config: SchemaDiscoveryConfig | None = None) -> None:
        """Initialize schema discovery with configuration."""
        self.config = config or SchemaDiscoveryConfig()
        self.performance_monitor = PerformanceMonitor()

    def discover_from_server(
        self,
        connection_info: ConnectionInfo,
    ) -> LDAPOperationResult[SchemaInfo]:
        """Discover schema from LDAP server.

        Args:
            connection_info: Connection information

        Returns:
            Operation result with discovered schema
        """
        with self.performance_monitor.track_operation("schema_discovery"):
            try:
                # Create connection
                server = ldap3.Server(
                    f"{connection_info.host}:{connection_info.port}",
                    use_ssl=connection_info.use_ssl,
                    get_info=ldap3.ALL,
                )

                conn = ldap3.Connection(
                    server,
                    user=connection_info.bind_dn,
                    password=connection_info.password,
                    auto_bind=True,
                    raise_exceptions=True,
                )

                schema_info = self._discover_schema(conn)
                conn.unbind()

                return LDAPOperationResult[SchemaInfo](
                    success=True,
                    data=schema_info,
                    operation="discover_from_server",
                    metadata={
                        "server": f"{connection_info.host}:{connection_info.port}",
                    },
                )

            except Exception as e:
                logger.exception("Schema discovery failed for {connection_info.host}")
                return LDAPOperationResult[SchemaInfo](
                    success=False,
                    error_message=f"Discovery failed: {e!s}",
                    operation="discover_from_server",
                    metadata={
                        "server": f"{connection_info.host}:{connection_info.port}",
                    },
                )

    def _discover_schema(self, conn: ldap3.Connection) -> SchemaInfo:
        """Internal schema discovery implementation."""
        schema_info = SchemaInfo()

        # Get server information
        if conn.server.info:
            schema_info.server_info = str(conn.server.info)

        # Get schema DN from RootDSE
        schema_dn = self._get_schema_dn(conn)
        schema_info.schema_dn = schema_dn

        # Search for schema entry
        conn.search(
            schema_dn,
            "(objectClass=*)",
            search_scope=ldap3.BASE,
            attributes=["*"],
        )

        if conn.entries:
            entry = conn.entries[0]

            # Extract attribute types
            if self.config.include_attribute_types and hasattr(entry, "attributeTypes"):
                schema_info.attribute_types = list(entry.attributeTypes.values)

            # Extract object classes
            if self.config.include_object_classes and hasattr(entry, "objectClasses"):
                schema_info.object_classes = list(entry.objectClasses.values)

            # Extract syntax definitions
            if self.config.include_syntax_definitions and hasattr(
                entry,
                "ldapSyntaxes",
            ):
                schema_info.syntax_definitions = list(entry.ldapSyntaxes.values)

            # Extract matching rules
            if self.config.include_matching_rules and hasattr(entry, "matchingRules"):
                schema_info.matching_rules = list(entry.matchingRules.values)

        # Get server controls and extensions
        if conn.server.info:
            if hasattr(conn.server.info, "supported_controls"):
                schema_info.server_controls = list(conn.server.info.supported_controls)
            if hasattr(conn.server.info, "supported_extensions"):
                schema_info.extensions = list(conn.server.info.supported_extensions)

        return schema_info

    def _get_schema_dn(self, conn: ldap3.Connection) -> str:
        """Get schema DN from server RootDSE."""
        try:
            conn.search(
                "",
                "(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["subschemaSubentry"],
            )

            if conn.entries and hasattr(conn.entries[0], "subschemaSubentry"):
                return str(conn.entries[0].subschemaSubentry.value)
        except Exception:
            logger.debug("Failed to get schema DN from RootDSE: {e}")

        # Fallback to standard schema DN
        return "cn=schema"
