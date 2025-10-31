"""Quirks integration for server-specific LDAP handling.

Integrates FlextLdif quirks system providing server-specific handling
for schemas, ACLs, and entries across different LDAP implementations
(OpenLDAP, Oracle OID/OUD, Active Directory).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.services import FlextLdifEntrys, FlextLdifRegistry

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapQuirksIntegration(FlextService[dict[str, object]]):
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
        self._ldif = FlextLdif.get_instance()
        self._quirks_manager = FlextLdifRegistry.get_global_instance()
        self._entrys = FlextLdifEntrys()
        self._detected_server_type: str | None = server_type
        self._quirks_cache: dict[str, object] = {}

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute method required by FlextService.

        Returns:
        FlextResult containing quirks adapter status

        """
        return FlextResult[dict[str, object]].ok({
            "service": "FlextLdapQuirksAdapter",
            "server_type": self._detected_server_type,
            "quirks_loaded": bool(self._quirks_cache),
        })

    @property
    def server_type(self) -> str | None:
        """Get detected server type."""
        return self._detected_server_type

    @property
    def quirks_manager(self) -> FlextLdifRegistry:
        """Get FlextLdif quirks manager instance."""
        return self._quirks_manager

    def detect_server_type_from_entries(
        self,
        entries: list[FlextLdifModels.Entry],
    ) -> FlextResult[str]:
        """Detect LDAP server type from entries using FlextLdif detection.

        Args:
        entries: List of FlextLdifModels.Entry to analyze

        Returns:
        FlextResult containing detected server type string

        """
        if not entries:
            self.logger.warning("No entries provided for server detection")
            return FlextResult[str].ok(FlextLdapConstants.Defaults.SERVER_TYPE)

        # Convert entries to LDIF content
        ldif_write_result = self._ldif.write(entries)
        if ldif_write_result.is_failure:
            self.logger.warning(
                "Entries to LDIF conversion failed, using generic",
                extra={"error": ldif_write_result.error},
            )
            return FlextResult[str].ok(FlextLdapConstants.Defaults.SERVER_TYPE)

        ldif_content = ldif_write_result.unwrap()

        # Use FlextLdif API for server detection
        api = FlextLdif.get_instance()
        detection_result = api.detect_server_type(ldif_content=ldif_content)
        if detection_result.is_failure:
            self.logger.warning(
                "Server detection failed, using generic",
                extra={"error": detection_result.error},
            )
            return FlextResult[str].ok(FlextLdapConstants.Defaults.SERVER_TYPE)

        detected_result = detection_result.unwrap()
        detected_type = detected_result.detected_server_type
        self._detected_server_type = detected_type

        self.logger.info(
            "Server type detected",
            extra={"server_type": detected_type},
        )

        return FlextResult[str].ok(detected_type)

    def get_server_quirks(
        self,
        server_type: str | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Get server-specific quirks configuration.

        Args:
        server_type: Server type (uses detected type if not provided)

        Returns:
        FlextResult containing quirks configuration dict

        """
        target_type = (
            server_type
            or self._detected_server_type
            or FlextLdapConstants.Defaults.SERVER_TYPE
        )

        try:
            # Check cache first
            if target_type in self._quirks_cache:
                cached_quirks = self._quirks_cache[target_type]
                if isinstance(cached_quirks, dict):
                    return FlextResult[dict[str, object]].ok(cached_quirks)
                # Invalid cache entry, remove it
                del self._quirks_cache[target_type]

            # Get quirks from FlextLdif manager
            quirks = self._quirks_manager.get_all_quirks_for_server(target_type)

            if not quirks:
                self.logger.warning(
                    "No quirks found for server type, using generic",
                    extra={"server_type": target_type},
                )
                quirks = self._quirks_manager.get_all_quirks_for_server(
                    FlextLdapConstants.LdapDictKeys.GENERIC,
                )

            # Cache the quirks
            self._quirks_cache[target_type] = quirks

            # Cast registry value from object to dict[str, object] for type safety
            quirks_typed = cast("dict[str, object]", quirks)
            return FlextResult[dict[str, object]].ok(quirks_typed)

        except Exception as e:
            self.logger.exception(
                "Failed to get server quirks",
                extra={"server_type": target_type, "error": str(e)},
            )
            return FlextResult[dict[str, object]].fail(f"Failed to get quirks: {e}")

    def get_acl_attribute_name(
        self,
        server_type: str | None = None,
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
        acl_attr = quirks.get(FlextLdapConstants.LdapDictKeys.ACL_ATTRIBUTE, "aci")

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
        acl_format = quirks.get(
            FlextLdapConstants.LdapDictKeys.ACL_FORMAT,
            FlextLdapConstants.Defaults.SERVER_TYPE,
        )

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
        schema_subentry = quirks.get(
            FlextLdapConstants.LdapDictKeys.SCHEMA_SUBENTRY,
            FlextLdapConstants.Defaults.SCHEMA_SUBENTRY,
        )

        return FlextResult[str].ok(str(schema_subentry))

    def supports_operational_attributes(
        self,
        server_type: str | None = None,
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
        supports = quirks.get(
            FlextLdapConstants.LdapDictKeys.SUPPORTS_OPERATIONAL_ATTRS,
            True,
        )

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
            return FlextResult[int].ok(FlextLdapConstants.Defaults.DEFAULT_PAGE_SIZE)

        quirks = quirks_result.unwrap()
        max_page_raw = quirks.get(
            FlextLdapConstants.LdapDictKeys.MAX_PAGE_SIZE,
            FlextLdapConstants.Defaults.DEFAULT_PAGE_SIZE,
        )

        try:
            max_page = (
                int(cast("int | str", max_page_raw))
                if max_page_raw is not None
                else 1000
            )
            return FlextResult[int].ok(max_page)
        except (TypeError, ValueError):
            return FlextResult[int].ok(1000)  # Default on conversion error

    def get_default_timeout(self, server_type: str | None = None) -> FlextResult[int]:
        """Get default timeout for server operations.

        Args:
        server_type: Server type (uses detected type if not provided)

        Returns:
        FlextResult containing default timeout in seconds

        """
        quirks_result = self.get_server_quirks(server_type)
        if quirks_result.is_failure:
            return FlextResult[int].ok(FlextLdapConstants.Defaults.DEFAULT_TIMEOUT)

        quirks = quirks_result.unwrap()
        timeout_raw = quirks.get(
            FlextLdapConstants.LdapDictKeys.DEFAULT_TIMEOUT,
            FlextLdapConstants.Defaults.DEFAULT_TIMEOUT,
        )

        try:
            timeout = (
                int(cast("int | str", timeout_raw))
                if timeout_raw is not None
                else FlextLdapConstants.Defaults.DEFAULT_TIMEOUT
            )
            return FlextResult[int].ok(timeout)
        except (TypeError, ValueError):
            return FlextResult[int].ok(
                FlextLdapConstants.Defaults.DEFAULT_TIMEOUT,
            )  # Default on conversion error

    def normalize_entry_for_server(
        self,
        entry: FlextLdifModels.Entry,
        target_server_type: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Normalize entry for target server type - delegates to FlextLdifEntrys.

        Args:
        entry: FlextLdifModels.Entry to normalize
        target_server_type: Target server type for normalization

        Returns:
        FlextResult containing normalized entry

        """
        # Delegate to FlextLdifEntrys for server-specific normalization
        adapt_result = self._entrys.adapt_entry(
            entry,
            target_server_type,
        )
        if adapt_result.is_failure:
            self.logger.warning(
                f"Entry normalization failed: {adapt_result.error}",
                extra={
                    "dn": str(entry.dn),
                    "target_server": target_server_type,
                },
            )
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        return adapt_result

    def get_connection_defaults(
        self,
        server_type: str | None = None,
    ) -> FlextResult[FlextLdapModels.ConnectionConfig]:
        """Get default connection parameters for server type.

        Args:
        server_type: Server type (uses detected type if not provided)

        Returns:
        FlextResult containing ConnectionConfig model with connection defaults

        """
        try:
            target_type = (
                server_type
                or self._detected_server_type
                or FlextLdapConstants.Defaults.SERVER_TYPE
            )

            # Server-specific connection defaults
            if target_type == FlextLdapConstants.ServerTypes.AD:
                config = FlextLdapModels.ConnectionConfig(
                    server="",  # Will be set by caller
                    port=FlextLdapConstants.Defaults.DEFAULT_PORT,
                    use_ssl=True,
                    bind_dn=None,
                    bind_password=None,
                    base_dn="",
                    timeout=FlextLdapConstants.Defaults.DEFAULT_TIMEOUT,
                )
            else:
                # Default for OpenLDAP, OID, OUD, DS389, and generic
                config = FlextLdapModels.ConnectionConfig(
                    server="",  # Will be set by caller
                    port=FlextLdapConstants.Defaults.DEFAULT_PORT,
                    use_ssl=False,
                    bind_dn=None,
                    bind_password=None,
                    base_dn="",
                    timeout=FlextLdapConstants.Defaults.DEFAULT_TIMEOUT,
                )

            return FlextResult[FlextLdapModels.ConnectionConfig].ok(config)

        except Exception as e:
            return FlextResult[FlextLdapModels.ConnectionConfig].fail(
                f"Failed to get connection defaults: {e}",
            )
