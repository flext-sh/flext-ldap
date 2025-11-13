"""Server operations factory for dynamic instantiation.

Factory for creating appropriate server operations instances based on
detected server type from connections or entries with auto-detection.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.services.server import FlextLdifServer
from ldap3 import Connection
from pydantic import PrivateAttr

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.servers.ad_operations import (
    FlextLdapServersActiveDirectoryOperations,
)
from flext_ldap.servers.base_operations import FlextLdapServersBaseOperations
from flext_ldap.servers.generic_operations import FlextLdapServersGenericOperations
from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations
from flext_ldap.servers.openldap1_operations import FlextLdapServersOpenLDAP1Operations
from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations
from flext_ldap.utilities import FlextLdapUtilities


class FlextLdapServersFactory(FlextService[None]):
    """Factory for creating appropriate server operations instances.

    This factory provides methods to:
    - Detect server type from LDAP connections (root DSE)
    - Detect server type from FlextLdif entries
    - Instantiate appropriate server operations class
    - Fallback to generic operations when server type unknown

    Server Type Mappings:
        - "openldap1" → OpenLDAP1Operations
        - "openldap2" → OpenLDAP2Operations
        - "openldap" → OpenLDAP2Operations (default to 2.x)
        - "oid" → OIDOperations
        - "oud" → OUDOperations
        - "ad" → GenericOperations (AD support planned)
        - "generic" → GenericOperations (fallback)
    """

    # Private attributes (Pydantic v2 PrivateAttr for internal state)
    _ldif: FlextLdif = PrivateAttr()
    _s_manager: FlextLdifServer = PrivateAttr()
    _server_registry: dict[str, type[FlextLdapServersBaseOperations]] = PrivateAttr()

    def __init__(self) -> None:
        """Initialize server operations factory with Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._ldif = FlextLdif.get_instance()
        self._s_manager = FlextLdifServer.get_global_instance()
        self._server_registry = cast(
            "dict[str, type[FlextLdapServersBaseOperations]]",
            {
                FlextLdapConstants.ServerTypes.OPENLDAP1: FlextLdapServersOpenLDAP1Operations,
                FlextLdapConstants.ServerTypes.OPENLDAP2: FlextLdapServersOpenLDAP2Operations,
                FlextLdapConstants.ServerTypes.OPENLDAP: FlextLdapServersOpenLDAP2Operations,
                FlextLdapConstants.ServerTypes.OID: FlextLdapServersOIDOperations,
                FlextLdapConstants.ServerTypeAliases.ORACLE_OID: FlextLdapServersOIDOperations,
                FlextLdapConstants.ServerTypes.OUD: FlextLdapServersOUDOperations,
                FlextLdapConstants.ServerTypeAliases.ORACLE_OUD: FlextLdapServersOUDOperations,
                FlextLdapConstants.ServerTypes.AD: FlextLdapServersActiveDirectoryOperations,
                FlextLdapConstants.ServerTypes.AD_SHORT: FlextLdapServersActiveDirectoryOperations,
                FlextLdapConstants.ServerTypeAliases.ACTIVE_DIRECTORY: FlextLdapServersActiveDirectoryOperations,
                FlextLdapConstants.Defaults.SERVER_TYPE: FlextLdapServersGenericOperations,
            },
        )

    def execute(self) -> FlextResult[None]:
        """Execute method required by FlextService."""
        return FlextResult[None].ok(None)

    def create_from_server_type(
        self,
        server_type: str,
    ) -> FlextResult[FlextLdapServersBaseOperations]:
        """Create server operations instance from explicit server type.

        Args:
            server_type: Server type identifier (e.g., "openldap2", "oid", "oud")

        Returns:
            FlextResult containing server operations instance

        """
        try:
            if not server_type or not server_type.strip():
                return FlextResult[FlextLdapServersBaseOperations].fail(
                    "Server type cannot be empty",
                )

            server_type_lower = server_type.lower().strip()

            # Check registry for exact match
            if server_type_lower in self._server_registry:
                operations_class = self._server_registry[server_type_lower]
                operations_instance = operations_class()
                self.logger.debug(
                    "Server operations created",
                    extra={
                        "server_type": server_type_lower,
                        "class_name": operations_class.__name__,
                    },
                )
                return FlextResult[FlextLdapServersBaseOperations].ok(
                    operations_instance,
                )

            # Fallback to generic
            self.logger.debug(
                "Unknown server type, using generic operations",
                extra={"server_type": server_type_lower},
            )
            return FlextResult[FlextLdapServersBaseOperations].ok(
                cast(
                    "FlextLdapServersBaseOperations",
                    FlextLdapServersGenericOperations(),
                ),
            )

        except Exception as e:
            self.logger.exception(
                "Failed to create server operations",
                extra={"server_type": server_type, "error": str(e)},
            )
            return FlextResult[FlextLdapServersBaseOperations].fail(
                f"Server operations creation failed: {e}",
            )

    def create_from_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[FlextLdapServersBaseOperations]:
        """Create server operations instance by detecting server type from entries.

        Uses FlextLdif detection system to analyze entry characteristics and
        determine the appropriate server operations class.

        Args:
        entries: List of FlextLdif entries to analyze

        Returns:
        FlextResult containing server operations instance

        """
        if not entries:
            self.logger.debug("No entries provided, using generic operations")
            return FlextResult[FlextLdapServersBaseOperations].ok(
                cast(
                    "FlextLdapServersBaseOperations",
                    FlextLdapServersGenericOperations(),
                ),
            )

        # Convert entries to LDIF content
        ldif_write_result = self._ldif.write(entries)
        if ldif_write_result.is_failure:
            self.logger.debug(
                "Entries to LDIF conversion failed, using generic operations",
                extra={"error": str(ldif_write_result.error)},
            )
            return FlextResult[FlextLdapServersBaseOperations].ok(
                cast(
                    "FlextLdapServersBaseOperations",
                    FlextLdapServersGenericOperations(),
                ),
            )

        ldif_content = ldif_write_result.unwrap()

        # Use FlextLdif API to detect server type
        api = FlextLdif.get_instance()
        detection_result = api.detect_server_type(ldif_content=ldif_content)
        if detection_result.is_failure:
            self.logger.debug(
                "Server type detection failed, using generic operations",
                extra={"error": str(detection_result.error)},
            )
            return FlextResult[FlextLdapServersBaseOperations].ok(
                cast(
                    "FlextLdapServersBaseOperations",
                    FlextLdapServersGenericOperations(),
                ),
            )

        detected_result = detection_result.unwrap()
        detected_type = detected_result.detected_server_type
        self.logger.debug(
            "Server type detected from entries",
            extra={"server_type": detected_type, "entry_count": len(entries)},
        )

        # Create operations instance for detected type
        return self.create_from_server_type(detected_type)

    def detect_server_type_from_root_dse(
        self,
        connection: Connection,
    ) -> FlextResult[str]:
        """Detect server type from root DSE (rootDomainServiceEntry).

        Refactored with Railway Pattern: 7→4 returns (SOLID/DRY compliance).

        The root DSE contains server-specific attributes that can be used
        to identify the LDAP server implementation.

        Detection Heuristics:
            - vendorName/vendorVersion attributes
            - supportedExtension OIDs
            - namingContexts structure
            - Server-specific operational attributes

        Args:
            connection: Active ldap3 connection

        Returns:
            FlextResult containing detected server type string

        Examples:
            - OpenLDAP: vendorName="OpenLDAP"
            - Oracle OID: vendorName="Oracle Corporation"
            - Oracle OUD: supportedExtension contains OUD-specific OIDs
            - AD: rootDomainNamingContext present

        """
        try:
            # Railway Pattern: Early validation
            if not connection or not connection.bound:
                return FlextResult[str].fail("Connection not bound")

            # Railway Pattern: Search root DSE and extract entry
            entry_result = self._fetch_root_dse_entry(connection)
            if entry_result.is_failure:
                self.logger.debug("Root DSE query failed, using generic server type")
                return FlextResult[str].ok(FlextLdapConstants.Defaults.SERVER_TYPE)

            entry = entry_result.unwrap()

            # Railway Pattern: Delegate detection to helper
            detected_type = self._detect_server_type_from_entry_attributes(entry)
            return FlextResult[str].ok(detected_type)

        except Exception as e:
            self.logger.exception(
                "Root DSE detection error",
                extra={"error": str(e)},
            )
            return FlextResult[str].fail(f"Root DSE detection failed: {e}")

    def _fetch_root_dse_entry(self, connection: Connection) -> FlextResult[object]:
        """Fetch root DSE entry from connection.

        Helper for Railway Pattern - extracted from detect_server_type_from_root_dse().

        Args:
            connection: Active ldap3 connection

        Returns:
            FlextResult containing root DSE entry or failure

        """
        search_result = connection.search(
            search_base="",
            search_filter=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
            search_scope=cast(
                "FlextLdapConstants.Types.Ldap3Scope",
                FlextLdapConstants.Scopes.BASE_LDAP3,
            ),
            attributes=["*", "+"],  # All standard and operational attributes
        )

        if not search_result or not connection.entries:
            return FlextResult[object].fail("Root DSE query returned no entries")

        return FlextResult[object].ok(connection.entries[0])

    def _detect_server_type_from_entry_attributes(self, entry: object) -> str:
        """Detect server type from root DSE entry using FlextLdapUtilities.

        Consolidated with FlextLdapUtilities.ServerDetection for reusability.
        Converts ldap3 entry object to dict for utility compatibility.

        Args:
            entry: Root DSE entry from ldap3 connection

        Returns:
            Server type string (openldap1, openldap2, oid, oud, ad, generic)

        """
        # Convert ldap3 entry to dict for utility compatibility
        root_dse: dict[str, object] = {}
        if hasattr(entry, "vendorName"):
            root_dse["vendorName"] = str(entry.vendorName)
        if hasattr(entry, "vendorVersion"):
            root_dse["vendorVersion"] = str(entry.vendorVersion)
        if hasattr(entry, "configContext"):
            root_dse["configContext"] = str(entry.configContext)
        if hasattr(
            entry, FlextLdapConstants.RootDseAttributes.ROOT_DOMAIN_NAMING_CONTEXT
        ):
            root_dse[
                FlextLdapConstants.RootDseAttributes.ROOT_DOMAIN_NAMING_CONTEXT
            ] = str(
                getattr(
                    entry,
                    FlextLdapConstants.RootDseAttributes.ROOT_DOMAIN_NAMING_CONTEXT,
                )
            )
        if hasattr(entry, FlextLdapConstants.RootDseAttributes.DEFAULT_NAMING_CONTEXT):
            root_dse[FlextLdapConstants.RootDseAttributes.DEFAULT_NAMING_CONTEXT] = str(
                getattr(
                    entry, FlextLdapConstants.RootDseAttributes.DEFAULT_NAMING_CONTEXT
                )
            )

        # Delegate to FlextLdapUtilities for detection
        return FlextLdapUtilities.ServerDetection.detect_server_type_from_root_dse(
            root_dse,
        )

    def create_from_connection(
        self,
        connection: Connection,
    ) -> FlextResult[FlextLdapServersBaseOperations]:
        """Create server operations instance by detecting server type from connection.

        Performs root DSE query to detect server type, then instantiates
        appropriate server operations class.

        Args:
        connection: Active ldap3 connection

        Returns:
        FlextResult containing server operations instance

        """
        try:
            if not connection:
                return FlextResult[FlextLdapServersBaseOperations].fail(
                    "Connection cannot be None",
                )

            # Detect server type from root DSE
            detection_result = self.detect_server_type_from_root_dse(connection)
            if detection_result.is_failure:
                self.logger.debug(
                    "Server detection from connection failed, using generic",
                    extra={"error": str(detection_result.error)},
                )
                return FlextResult[FlextLdapServersBaseOperations].ok(
                    cast(
                        "FlextLdapServersBaseOperations",
                        FlextLdapServersGenericOperations(),
                    ),
                )

            detected_type = detection_result.unwrap()

            # Create operations instance for detected type
            return self.create_from_server_type(detected_type)

        except Exception as e:
            self.logger.exception(
                "Failed to create server operations from connection",
                extra={"error": str(e)},
            )
            return FlextResult[FlextLdapServersBaseOperations].fail(
                f"Server operations creation from connection failed: {e}",
            )

    def get_supported_server_types(self) -> list[str]:
        """Get list of supported server types.

        Returns:
        List of server type identifiers

        """
        return list(self._server_registry.keys())

    def is_server_type_supported(self, server_type: str) -> bool:
        """Check if server type is supported.

        Args:
        server_type: Server type identifier

        Returns:
        True if server type is supported

        """
        return server_type.lower().strip() in self._server_registry

    def get_server_info(self, server_type: str) -> FlextResult[dict[str, object]]:
        """Get information about a server type.

        Args:
        server_type: Server type identifier

        Returns:
        FlextResult containing server information dict

        """
        try:
            if not self.is_server_type_supported(server_type):
                return FlextResult[dict[str, object]].fail(
                    f"Unsupported server type: {server_type}",
                )

            server_type_lower = server_type.lower().strip()
            operations_class = self._server_registry[server_type_lower]
            temp_instance = operations_class()

            info: dict[str, object] = {
                "server_type": server_type,
                "class_name": operations_class.__name__,
                "default_port": temp_instance.get_default_port(use_ssl=False),
                "default_ssl_port": temp_instance.get_default_port(use_ssl=True),
                "supports_start_tls": temp_instance.supports_start_tls(),
                "bind_mechanisms": temp_instance.get_bind_mechanisms(),
                "schema_dn": temp_instance.get_schema_dn(),
            }

            return FlextResult[dict[str, object]].ok(info)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to get server info: {e}",
            )
