"""Server Operations Factory for dynamic server type instantiation.

This module provides a factory for creating appropriate server operations
instances based on server type detection from connections or entries.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels
from flext_ldif.quirks import FlextLdifQuirksManager

from flext_core import FlextLogger, FlextResult, FlextService, FlextTypes
from flext_ldap.servers.ad_operations import (
    FlextLdapServersADOperations as ActiveDirectoryOperations,
)
from flext_ldap.servers.base_operations import (
    FlextLdapServersBaseOperations as BaseServerOperations,
)
from flext_ldap.servers.generic_operations import (
    FlextLdapServersGenericOperations,
)
from flext_ldap.servers.oid_operations import (
    FlextLdapServersOIDOperations as OracleOIDOperations,
)
from flext_ldap.servers.openldap1_operations import (
    FlextLdapServersOpenLDAP1Operations as OpenLDAP1Operations,
)
from flext_ldap.servers.openldap2_operations import (
    FlextLdapServersOpenLDAP2Operations as OpenLDAP2Operations,
)
from flext_ldap.servers.oud_operations import (
    FlextLdapServersOUDOperations as OracleOUDOperations,
)


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
        - "oid" → OracleOIDOperations
        - "oud" → OracleOUDOperations
        - "ad" → ActiveDirectoryOperations (stub)
        - "generic" → FlextLdapServersGenericOperations (fallback)
    """

    def __init__(self) -> None:
        """Initialize server operations factory."""
        super().__init__()
        self.logger = FlextLogger(__name__)
        self._quirks_manager = FlextLdifQuirksManager()
        self._server_registry: dict[str, type[BaseServerOperations]] = {
            "openldap1": OpenLDAP1Operations,
            "openldap2": OpenLDAP2Operations,
            "openldap": OpenLDAP2Operations,  # Default OpenLDAP to 2.x
            "oid": OracleOIDOperations,
            "oud": OracleOUDOperations,
            "ad": ActiveDirectoryOperations,
            "generic": FlextLdapServersGenericOperations,
        }

    def execute(self) -> FlextResult[None]:
        """Execute method required by FlextService."""
        return FlextResult[None].ok(None)

    def create_from_server_type(
        self, server_type: str
    ) -> FlextResult[BaseServerOperations]:
        """Create server operations instance from explicit server type.

        Args:
            server_type: Server type identifier (e.g., "openldap2", "oid", "oud")

        Returns:
            FlextResult containing server operations instance

        """
        try:
            if not server_type or not server_type.strip():
                return FlextResult[BaseServerOperations].fail(
                    "Server type cannot be empty"
                )

            server_type_lower = server_type.lower().strip()

            # Check registry for exact match
            if server_type_lower in self._server_registry:
                operations_class = self._server_registry[server_type_lower]
                operations_instance = operations_class()
                self.logger.info(
                    "Server operations created",
                    extra={
                        "server_type": server_type_lower,
                        "class": operations_class.__name__,
                    },
                )
                return FlextResult[BaseServerOperations].ok(operations_instance)

            # Fallback to generic
            self.logger.warning(
                "Unknown server type, using generic operations",
                extra={"server_type": server_type_lower},
            )
            return FlextResult[BaseServerOperations].ok(
                FlextLdapServersGenericOperations()
            )

        except Exception as e:
            self.logger.error(
                "Failed to create server operations",
                extra={"server_type": server_type, "error": str(e)},
            )
            return FlextResult[BaseServerOperations].fail(
                f"Server operations creation failed: {e}"
            )

    def create_from_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[BaseServerOperations]:
        """Create server operations instance by detecting server type from entries.

        Uses FlextLdif quirks system to analyze entry characteristics and
        determine the appropriate server operations class.

        Args:
            entries: List of FlextLdif entries to analyze

        Returns:
            FlextResult containing server operations instance

        """
        try:
            if not entries:
                self.logger.warning("No entries provided, using generic operations")
                return FlextResult[BaseServerOperations].ok(
                    FlextLdapServersGenericOperations()
                )

            # Use quirks manager to detect server type
            detection_result = self._quirks_manager.detect_server_type(entries)
            if detection_result.is_failure:
                self.logger.warning(
                    "Server type detection failed, using generic operations",
                    extra={"error": detection_result.error},
                )
                return FlextResult[BaseServerOperations].ok(
                    FlextLdapServersGenericOperations()
                )

            detected_type = detection_result.unwrap()
            self.logger.info(
                "Server type detected from entries",
                extra={"server_type": detected_type, "entry_count": len(entries)},
            )

            # Create operations instance for detected type
            return self.create_from_server_type(detected_type)

        except Exception as e:
            self.logger.error(
                "Failed to create server operations from entries",
                extra={"entry_count": len(entries) if entries else 0, "error": str(e)},
            )
            return FlextResult[BaseServerOperations].fail(
                f"Server operations creation from entries failed: {e}"
            )

    def detect_server_type_from_root_dse(self, connection: object) -> FlextResult[str]:
        """Detect server type from root DSE (rootDomainServiceEntry).

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
            if not connection or not connection.bound:
                return FlextResult[str].fail("Connection not bound")

            # Search for root DSE
            success = connection.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=[
                    "vendorName",
                    "vendorVersion",
                    "supportedExtension",
                    "supportedControl",
                    "namingContexts",
                    "subschemaSubentry",
                    "configContext",
                    "rootDomainNamingContext",  # AD-specific
                    "defaultNamingContext",  # AD-specific
                ],
            )

            if not success or not connection.entries:
                self.logger.warning(
                    "Root DSE query failed, unable to detect server type"
                )
                return FlextResult[str].ok("generic")

            entry = connection.entries[0]

            # Detect OpenLDAP
            vendor_name = str(entry.vendorName) if hasattr(entry, "vendorName") else ""
            if "openldap" in vendor_name.lower():
                # Check version for OpenLDAP 1.x vs 2.x
                vendor_version = (
                    str(entry.vendorVersion) if hasattr(entry, "vendorVersion") else ""
                )
                if vendor_version.startswith("1."):
                    detected_type = "openldap1"
                else:
                    detected_type = "openldap2"  # Default to 2.x

                self.logger.info(
                    "OpenLDAP detected from root DSE",
                    extra={"version": vendor_version, "type": detected_type},
                )
                return FlextResult[str].ok(detected_type)

            # Detect Oracle OID/OUD
            if "oracle" in vendor_name.lower():
                # Check for OUD-specific indicators
                config_context = (
                    str(entry.configContext) if hasattr(entry, "configContext") else ""
                )
                if "cn=config" in config_context.lower():
                    detected_type = "oud"  # OUD uses cn=config like OpenLDAP 2.x
                else:
                    detected_type = "oid"  # OID uses traditional structure

                self.logger.info(
                    "Oracle directory server detected from root DSE",
                    extra={"vendor": vendor_name, "type": detected_type},
                )
                return FlextResult[str].ok(detected_type)

            # Detect Active Directory
            if hasattr(entry, "rootDomainNamingContext") or hasattr(
                entry, "defaultNamingContext"
            ):
                self.logger.info("Active Directory detected from root DSE")
                return FlextResult[str].ok("ad")

            # Generic fallback
            self.logger.info(
                "Generic LDAP server detected",
                extra={"vendor": vendor_name or "unknown"},
            )
            return FlextResult[str].ok("generic")

        except Exception as e:
            self.logger.error(
                "Root DSE detection error",
                extra={"error": str(e)},
            )
            return FlextResult[str].fail(f"Root DSE detection failed: {e}")

    def create_from_connection(
        self, connection: object
    ) -> FlextResult[BaseServerOperations]:
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
                return FlextResult[BaseServerOperations].fail(
                    "Connection cannot be None"
                )

            # Detect server type from root DSE
            detection_result = self.detect_server_type_from_root_dse(connection)
            if detection_result.is_failure:
                self.logger.warning(
                    "Server detection from connection failed, using generic",
                    extra={"error": detection_result.error},
                )
                return FlextResult[BaseServerOperations].ok(
                    FlextLdapServersGenericOperations()
                )

            detected_type = detection_result.unwrap()

            # Create operations instance for detected type
            return self.create_from_server_type(detected_type)

        except Exception as e:
            self.logger.error(
                "Failed to create server operations from connection",
                extra={"error": str(e)},
            )
            return FlextResult[BaseServerOperations].fail(
                f"Server operations creation from connection failed: {e}"
            )

    def get_supported_server_types(self) -> FlextTypes.StringList:
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

    def get_server_info(self, server_type: str) -> FlextResult[FlextTypes.Dict]:
        """Get information about a server type.

        Args:
            server_type: Server type identifier

        Returns:
            FlextResult containing server information dict

        """
        try:
            if not self.is_server_type_supported(server_type):
                return FlextResult[FlextTypes.Dict].fail(
                    f"Unsupported server type: {server_type}"
                )

            server_type_lower = server_type.lower().strip()
            operations_class = self._server_registry[server_type_lower]
            temp_instance = operations_class()

            info: FlextTypes.Dict = {
                "server_type": server_type,
                "class_name": operations_class.__name__,
                "default_port": temp_instance.get_default_port(use_ssl=False),
                "default_ssl_port": temp_instance.get_default_port(use_ssl=True),
                "supports_start_tls": temp_instance.supports_start_tls(),
                "bind_mechanisms": temp_instance.get_bind_mechanisms(),
                "schema_dn": temp_instance.get_schema_dn(),
            }

            return FlextResult[FlextTypes.Dict].ok(info)

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(f"Failed to get server info: {e}")
