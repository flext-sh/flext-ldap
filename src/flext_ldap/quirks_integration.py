"""Quirks Integration for FlextLdif server-specific handling.

This module integrates FlextLdif's quirks system into flext-ldap, providing
server-specific handling for schemas, ACLs, and entries across different
LDAP server implementations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextService, FlextTypes
from flext_ldif import FlextLdifModels
from flext_ldif.quirks import FlextLdifEntryQuirks, FlextLdifQuirksManager


class FlextLdapQuirksIntegration(FlextService[FlextTypes.Dict]):
    """Adapter for FlextLdif quirks system integration with flext-ldap.

    This adapter wraps FlextLdif's quirks management to provide:
    - Server type detection from LDAP entries
    - Server-specific behavior handling
    - ACL format detection and conversion
    - Schema discovery endpoint detection
    - Entry attribute normalization

    Supports complete implementations for:
    - OpenLDAP 1.x (slapd.conf, access attribute)
    - OpenLDAP 2.x (cn=config, olcAccess attribute)
    - Oracle OID (orclaci ACLs)
    - Oracle OUD (ds-privilege-name ACLs)

    Provides stubs for:
    - Active Directory (nTSecurityDescriptor)
    - Apache Directory Server
    - Novell eDirectory
    - IBM Tivoli Directory Server
    - Generic LDAP servers
    """

    def __init__(self, server_type: str | None = None) -> None:
        """Initialize quirks adapter with Phase 1 context enrichment.

        Args:
            server_type: Optional explicit server type (auto-detected if not provided)

        """
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._quirks_manager = FlextLdifQuirksManager(server_type=server_type)
        self._entry_quirks = FlextLdifEntryQuirks()
        self._detected_server_type: str | None = server_type
        self._quirks_cache: FlextTypes.Dict = {}

    def execute(self) -> FlextResult[FlextTypes.Dict]:
        """Execute method required by FlextService.

        Returns:
            FlextResult containing quirks adapter status

        """
        return FlextResult[FlextTypes.Dict].ok({
            "service": "FlextLdapQuirksAdapter",
            "server_type": self._detected_server_type,
            "quirks_loaded": bool(self._quirks_cache),
        })

    @property
    def server_type(self) -> str | None:
        """Get detected server type."""
        return self._detected_server_type

    @property
    def quirks_manager(self) -> FlextLdifQuirksManager:
        """Get FlextLdif quirks manager instance."""
        return self._quirks_manager

    def detect_server_type_from_entries(
        self, entries: list[FlextLdifModels.Entry]
    ) -> FlextResult[str]:
        """Detect LDAP server type from entries using FlextLdif quirks.

        Args:
            entries: List of FlextLdifModels.Entry to analyze

        Returns:
            FlextResult containing detected server type string

        """
        try:
            if not entries:
                self.logger.warning("No entries provided for server detection")
                return FlextResult[str].ok("generic")

            # Use FlextLdif quirks manager for detection
            detection_result = self._quirks_manager.detect_server_type(entries)
            if detection_result.is_failure:
                self.logger.warning(
                    "Server detection failed, using generic",
                    extra={"error": detection_result.error},
                )
                return FlextResult[str].ok("generic")

            detected_type = detection_result.unwrap()
            self._detected_server_type = detected_type

            self.logger.info(
                "Server type detected",
                extra={"server_type": detected_type},
            )

            return FlextResult[str].ok(detected_type)

        except Exception as e:
            self.logger.exception(
                "Server type detection error",
                extra={"error": str(e)},
            )
            return FlextResult[str].fail(f"Server detection failed: {e}")

    def get_server_quirks(
        self, server_type: str | None = None
    ) -> FlextResult[FlextTypes.Dict]:
        """Get server-specific quirks configuration.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextResult containing quirks configuration dict

        """
        target_type = server_type or self._detected_server_type or "generic"

        try:
            # Check cache first
            if target_type in self._quirks_cache:
                return FlextResult[FlextTypes.Dict].ok(self._quirks_cache[target_type])

            # Get quirks from FlextLdif manager
            quirks = self._quirks_manager.quirks_registry.get(target_type, {})

            if not quirks:
                self.logger.warning(
                    "No quirks found for server type, using generic",
                    extra={"server_type": target_type},
                )
                quirks = self._quirks_manager.quirks_registry.get("generic", {})

            # Cache the quirks
            self._quirks_cache[target_type] = quirks

            return FlextResult[FlextTypes.Dict].ok(quirks)

        except Exception as e:
            self.logger.exception(
                "Failed to get server quirks",
                extra={"server_type": target_type, "error": str(e)},
            )
            return FlextResult[FlextTypes.Dict].fail(f"Failed to get quirks: {e}")

    def get_acl_attribute_name(
        self, server_type: str | None = None
    ) -> FlextResult[str]:
        """Get ACL attribute name for server type.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextResult containing ACL attribute name

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextResult[str].fail(quirks_result.error or "Failed to get quirks")

        quirks = quirks_result.unwrap()
        acl_attr = quirks.get("acl_attribute", "aci")

        return FlextResult[str].ok(str(acl_attr))

    def get_acl_format(self, server_type: str | None = None) -> FlextResult[str]:
        """Get ACL format for server type.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextResult containing ACL format string

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextResult[str].fail(quirks_result.error or "Failed to get quirks")

        quirks = quirks_result.unwrap()
        acl_format = quirks.get("acl_format", "generic")

        return FlextResult[str].ok(str(acl_format))

    def get_schema_subentry(self, server_type: str | None = None) -> FlextResult[str]:
        """Get schema subentry DN for server type.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextResult containing schema subentry DN

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextResult[str].fail(quirks_result.error or "Failed to get quirks")

        quirks = quirks_result.unwrap()
        schema_subentry = quirks.get("schema_subentry", "cn=subschema")

        return FlextResult[str].ok(str(schema_subentry))

    def supports_operational_attributes(
        self, server_type: str | None = None
    ) -> FlextResult[bool]:
        """Check if server supports operational attributes.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextResult containing boolean support indicator

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextResult[bool].ok(True)  # Assume support by default

        quirks = quirks_result.unwrap()
        supports = quirks.get("supports_operational_attrs", True)

        return FlextResult[bool].ok(bool(supports))

    def get_max_page_size(self, server_type: str | None = None) -> FlextResult[int]:
        """Get maximum page size for paged searches.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextResult containing max page size

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextResult[int].ok(1000)  # Default page size

        quirks = quirks_result.unwrap()
        max_page = quirks.get("max_page_size", 1000)

        return FlextResult[int].ok(int(max_page))

    def get_default_timeout(self, server_type: str | None = None) -> FlextResult[int]:
        """Get default timeout for server operations.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextResult containing default timeout in seconds

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextResult[int].ok(30)  # Default timeout

        quirks = quirks_result.unwrap()
        timeout = quirks.get("default_timeout", 30)

        return FlextResult[int].ok(int(timeout))

    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server_type: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for target server type using FlextLdif entry quirks.

        Args:
            entry: FlextLdifModels.Entry to normalize
            target_server_type: Target server type for normalization

        Returns:
            FlextResult containing normalized entry

        """
        try:
            # Use FlextLdif entry quirks for normalization
            # This would handle server-specific attribute transformations
            # For now, return the entry as-is (to be enhanced with actual quirks)

            self.logger.debug(
                "Entry normalization",
                extra={
                    "dn": str(entry.dn),
                    "target_server": target_server_type,
                },
            )

            return FlextResult[FlextLdifModels.Entry].ok(entry)

        except Exception as e:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry normalization failed: {e}"
            )

    def get_connection_defaults(
        self, server_type: str | None = None
    ) -> FlextResult[FlextTypes.Dict]:
        """Get default connection parameters for server type.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextResult containing connection defaults

        """
        try:
            target_type = server_type or self._detected_server_type or "generic"

            # Server-specific connection defaults
            defaults: FlextTypes.Dict = {
                "openldap": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "openldap1": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "openldap2": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "oid": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "oud": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "389ds": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "ad": {"port": 389, "use_ssl": True, "supports_starttls": False},
                "generic": {"port": 389, "use_ssl": False, "supports_starttls": True},
            }

            config: FlextTypes.Dict = defaults.get(target_type) or defaults["generic"]
            return FlextResult[FlextTypes.Dict].ok(config)

        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(
                f"Failed to get connection defaults: {e}"
            )
