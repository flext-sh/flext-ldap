"""Quirks Integration for FlextLdif server-specific handling.

This module integrates FlextLdif's quirks system into flext-ldap, providing
server-specific handling for schemas, ACLs, and entries across different
LDAP server implementations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextCore
from flext_ldif import FlextLdifModels
from flext_ldif.quirks import FlextLdifEntryQuirks, FlextLdifQuirksManager

from flext_ldap.constants import FlextLdapConstants


class FlextLdapQuirksIntegration(FlextCore.Service[FlextCore.Types.Dict]):
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
        # Logger and container inherited from FlextCore.Service via FlextCore.Mixins
        self._quirks_manager = FlextLdifQuirksManager(server_type=server_type)
        self._entry_quirks = FlextLdifEntryQuirks()
        self._detected_server_type: str | None = server_type
        self._quirks_cache: FlextCore.Types.Dict = {}

    def execute(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Execute method required by FlextCore.Service.

        Returns:
            FlextCore.Result containing quirks adapter status

        """
        return FlextCore.Result[FlextCore.Types.Dict].ok({
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
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextCore.Result[str]:
        """Detect LDAP server type from entries using FlextLdif quirks.

        Args:
            entries: List of FlextLdifModels.Entry to analyze

        Returns:
            FlextCore.Result containing detected server type string

        """
        try:
            if not entries:
                self.logger.warning("No entries provided for server detection")
                return FlextCore.Result[str].ok("generic")

            # Use FlextLdif quirks manager for detection
            detection_result = self._quirks_manager.detect_server_type(entries)
            if detection_result.is_failure:
                self.logger.warning(
                    "Server detection failed, using generic",
                    extra={"error": detection_result.error},
                )
                return FlextCore.Result[str].ok("generic")

            detected_type = detection_result.unwrap()
            self._detected_server_type = detected_type

            self.logger.info(
                "Server type detected",
                extra={"server_type": detected_type},
            )

            return FlextCore.Result[str].ok(detected_type)

        except Exception as e:
            self.logger.exception(
                "Server type detection error",
                extra={"error": str(e)},
            )
            return FlextCore.Result[str].fail(f"Server detection failed: {e}")

    def get_server_quirks(
        self,
        server_type: str | None = None,
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Get server-specific quirks configuration.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextCore.Result containing quirks configuration dict

        """
        target_type = server_type or self._detected_server_type or "generic"

        try:
            # Check cache first
            if target_type in self._quirks_cache:
                cached_quirks = self._quirks_cache[target_type]
                if isinstance(cached_quirks, dict):
                    return FlextCore.Result[FlextCore.Types.Dict].ok(cached_quirks)
                # Invalid cache entry, remove it
                del self._quirks_cache[target_type]

            # Get quirks from FlextLdif manager
            quirks = self._quirks_manager.quirks_registry.get(target_type, {})

            if not quirks:
                self.logger.warning(
                    "No quirks found for server type, using generic",
                    extra={"server_type": target_type},
                )
                quirks = self._quirks_manager.quirks_registry.get(
                    FlextLdapConstants.DictKeys.GENERIC,
                    {},
                )

            # Cache the quirks
            self._quirks_cache[target_type] = quirks

            return FlextCore.Result[FlextCore.Types.Dict].ok(quirks)

        except Exception as e:
            self.logger.exception(
                "Failed to get server quirks",
                extra={"server_type": target_type, "error": str(e)},
            )
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to get quirks: {e}"
            )

    def get_acl_attribute_name(
        self,
        server_type: str | None = None,
    ) -> FlextCore.Result[str]:
        """Get ACL attribute name for server type.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextCore.Result containing ACL attribute name

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextCore.Result[str].fail(
                quirks_result.error or "Failed to get quirks"
            )

        quirks = quirks_result.unwrap()
        acl_attr = quirks.get(FlextLdapConstants.DictKeys.ACL_ATTRIBUTE, "aci")

        return FlextCore.Result[str].ok(str(acl_attr))

    def get_acl_format(self, server_type: str | None = None) -> FlextCore.Result[str]:
        """Get ACL format for server type.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextCore.Result containing ACL format string

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextCore.Result[str].fail(
                quirks_result.error or "Failed to get quirks"
            )

        quirks = quirks_result.unwrap()
        acl_format = quirks.get(FlextLdapConstants.DictKeys.ACL_FORMAT, "generic")

        return FlextCore.Result[str].ok(str(acl_format))

    def get_schema_subentry(
        self, server_type: str | None = None
    ) -> FlextCore.Result[str]:
        """Get schema subentry DN for server type.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextCore.Result containing schema subentry DN

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextCore.Result[str].fail(
                quirks_result.error or "Failed to get quirks"
            )

        quirks = quirks_result.unwrap()
        schema_subentry = quirks.get(
            FlextLdapConstants.DictKeys.SCHEMA_SUBENTRY,
            "cn=subschema",
        )

        return FlextCore.Result[str].ok(str(schema_subentry))

    def supports_operational_attributes(
        self,
        server_type: str | None = None,
    ) -> FlextCore.Result[bool]:
        """Check if server supports operational attributes.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextCore.Result containing boolean support indicator

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextCore.Result[bool].ok(True)  # Assume support by default

        quirks = quirks_result.unwrap()
        supports = quirks.get(
            FlextLdapConstants.DictKeys.SUPPORTS_OPERATIONAL_ATTRS,
            True,
        )

        return FlextCore.Result[bool].ok(bool(supports))

    def get_max_page_size(
        self, server_type: str | None = None
    ) -> FlextCore.Result[int]:
        """Get maximum page size for paged searches.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextCore.Result containing max page size

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextCore.Result[int].ok(1000)  # Default page size

        quirks = quirks_result.unwrap()
        max_page_raw = quirks.get(FlextLdapConstants.DictKeys.MAX_PAGE_SIZE, 1000)

        try:
            max_page = int(max_page_raw) if max_page_raw is not None else 1000
            return FlextCore.Result[int].ok(max_page)
        except (TypeError, ValueError):
            return FlextCore.Result[int].ok(1000)  # Default on conversion error

    def get_default_timeout(
        self, server_type: str | None = None
    ) -> FlextCore.Result[int]:
        """Get default timeout for server operations.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextCore.Result containing default timeout in seconds

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextCore.Result[int].ok(30)  # Default timeout

        quirks = quirks_result.unwrap()
        timeout_raw = quirks.get(FlextLdapConstants.DictKeys.DEFAULT_TIMEOUT, 30)

        try:
            timeout = int(timeout_raw) if timeout_raw is not None else 30
            return FlextCore.Result[int].ok(timeout)
        except (TypeError, ValueError):
            return FlextCore.Result[int].ok(30)  # Default on conversion error

    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server_type: str,
    ) -> FlextCore.Result[FlextLdifModels.Entry]:
        """Normalize entry for target server type using FlextLdif entry quirks.

        Args:
            entry: FlextLdifModels.Entry to normalize
            target_server_type: Target server type for normalization

        Returns:
            FlextCore.Result containing normalized entry

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

            return FlextCore.Result[FlextLdifModels.Entry].ok(entry)

        except Exception as e:
            return FlextCore.Result[FlextLdifModels.Entry].fail(
                f"Entry normalization failed: {e}",
            )

    def get_connection_defaults(
        self,
        server_type: str | None = None,
    ) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Get default connection parameters for server type.

        Args:
            server_type: Server type (uses detected type if not provided)

        Returns:
            FlextCore.Result containing connection defaults

        """
        try:
            target_type = server_type or self._detected_server_type or "generic"

            # Server-specific connection defaults
            defaults: FlextCore.Types.Dict = {
                "openldap": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "openldap1": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "openldap2": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "oid": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "oud": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "389ds": {"port": 389, "use_ssl": False, "supports_starttls": True},
                "ad": {"port": 389, "use_ssl": True, "supports_starttls": False},
                "generic": {"port": 389, "use_ssl": False, "supports_starttls": True},
            }

            config_raw = defaults.get(target_type) or defaults["generic"]
            if isinstance(config_raw, dict):
                config: FlextCore.Types.Dict = config_raw
            else:
                config = defaults["generic"]
            return FlextCore.Result[FlextCore.Types.Dict].ok(config)

        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to get connection defaults: {e}",
            )
