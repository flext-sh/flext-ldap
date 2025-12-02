"""Detect LDAP server type from a bound ``ldap3`` connection.

The service inspects ``rootDSE`` attributes and applies lightweight heuristics
so callers can classify a live directory server without relying on external
detectors. Results are returned as :class:`flext_core.FlextResult` instances.
"""

from __future__ import annotations

from collections.abc import Callable

from flext_core import FlextResult, FlextRuntime
from ldap3 import Connection

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.typings import FlextLdapTypes


class FlextLdapServerDetector(FlextLdapServiceBase[str]):
    """Identify a directory server by querying ``rootDSE`` attributes.

    The detector queries the base DN on a bound :class:`ldap3.Connection`,
    extracts vendor attributes, and applies internal heuristics to return a
    normalized server label (for example, ``openldap`` or ``ad``).
    """

    def execute(self, **_kwargs: str | float | bool | None) -> FlextResult[str]:
        """Detect server type using a provided ``ldap3.Connection`` instance."""
        connection = _kwargs.get("connection")
        if connection is None:
            return FlextResult[str].fail("connection parameter required")
        if not isinstance(connection, Connection):
            return FlextResult[str].fail(
                f"connection must be ldap3.Connection, got {type(connection).__name__}",
            )
        return self.detect_from_connection(connection)

    def detect_from_connection(self, connection: Connection) -> FlextResult[str]:
        """Query ``rootDSE`` and return a detected server label."""
        self.logger.debug(
            "Detecting server type from connection",
            operation=FlextLdapConstants.LdapOperationNames.DETECT_FROM_CONNECTION.value,
            connection_bound=connection.bound,
        )

        root_dse_result = FlextLdapServerDetector._query_root_dse(connection)
        if root_dse_result.is_failure:
            return FlextResult[str].fail(
                f"Failed to query rootDSE: {root_dse_result.error}",
            )

        root_dse_attrs = root_dse_result.unwrap()
        return FlextLdapServerDetector._detect_from_attributes(
            vendor_name=FlextLdapServerDetector._get_first_value(
                root_dse_attrs, "vendorName",
            ),
            vendor_version=FlextLdapServerDetector._get_first_value(
                root_dse_attrs, "vendorVersion",
            ),
            naming_contexts=list(root_dse_attrs.get("namingContexts", [])),
            supported_controls=list(root_dse_attrs.get("supportedControl", [])),
            supported_extensions=list(root_dse_attrs.get("supportedExtension", [])),
        )

    @staticmethod
    def _query_root_dse(
        connection: Connection,
    ) -> FlextResult[FlextLdapTypes.Ldap.Attributes]:
        """Fetch ``rootDSE`` attributes from the active connection."""
        # ldap3 expects Literal["BASE", "LEVEL", "SUBTREE"] - use StrEnum value directly
        search_scope: FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral = "BASE"
        if not connection.search(
            search_base="",
            search_filter=str(FlextLdapConstants.Filters.ALL_ENTRIES_FILTER),
            search_scope=search_scope,
            attributes=str(FlextLdapConstants.LdapAttributeNames.ALL_ATTRIBUTES),
        ):
            return FlextResult[FlextLdapTypes.Ldap.Attributes].fail(
                f"rootDSE query failed: {connection.result}",
            )

        if not connection.entries:
            return FlextResult[FlextLdapTypes.Ldap.Attributes].fail(
                "rootDSE query returned no entries",
            )

        root_dse_entry = connection.entries[0]
        attrs_dict = root_dse_entry.entry_attributes_as_dict
        attributes: dict[str, list[str]] = {
            attr_name: (
                [str(v) for v in attr_value]
                if FlextRuntime.is_list_like(attr_value)
                else [str(attr_value)]
            )
            for attr_name, attr_value in attrs_dict.items()
            if attr_value is not None
        }

        return FlextResult[FlextLdapTypes.Ldap.Attributes].ok(attributes)

    @staticmethod
    def _get_first_value(attrs: FlextLdapTypes.Ldap.Attributes, key: str) -> str | None:
        """Return the first attribute value for ``key`` when present."""
        values = attrs.get(key)
        if not values:
            return None
        return str(values[0])

    @staticmethod
    def _detect_from_attributes(
        vendor_name: str | None,
        vendor_version: str | None,
        naming_contexts: list[str],
        supported_controls: list[str],
        supported_extensions: list[str],
    ) -> FlextResult[str]:
        """Classify the server using collected ``rootDSE`` attributes."""
        pseudo_ldif_lines: list[str] = []
        if vendor_name:
            pseudo_ldif_lines.append(f"vendorName: {vendor_name}")
        if vendor_version:
            pseudo_ldif_lines.append(f"vendorVersion: {vendor_version}")
        pseudo_ldif_lines.extend(f"namingContexts: {nc}" for nc in naming_contexts)
        pseudo_ldif_lines.extend(
            f"supportedControl: {control}" for control in supported_controls
        )
        pseudo_ldif_lines.extend(
            f"supportedExtension: {extension}" for extension in supported_extensions
        )

        # Simple server type detection based on common attributes
        # This avoids dependency on the broken flext-ldif detector
        detected_type = (
            FlextLdapServerDetector._detect_server_type_from_attributes_simple(
                supported_extensions,
                naming_contexts,
                vendor_name,
                vendor_version,
            )
        )
        return FlextResult[str].ok(detected_type)

    @staticmethod
    def _detect_server_type_from_attributes_simple(
        supported_extensions: list[str],
        naming_contexts: list[str],
        vendor_name: str | None = None,
        vendor_version: str | None = None,
    ) -> str:
        """Apply heuristic detection to map attributes to a server label."""
        # Check vendor info first (most reliable)
        vendor_parts = [v for v in [vendor_name, vendor_version] if v]
        vendor_info = " ".join(vendor_parts).lower() if vendor_parts else ""

        # Vendor-based detection (priority order)
        vendor_checks: list[tuple[str, Callable[[str], bool]]] = [
            (
                "oid",
                lambda v: "oracle" in v and ("internet directory" in v or "oid" in v),
            ),
            ("oud", lambda v: "oracle" in v and "unified directory" in v),
            ("openldap", lambda v: "openldap" in v),
            ("ad", lambda v: "microsoft" in v or "active directory" in v),
            ("ds389", lambda v: "389" in v or "dirsrv" in v),
        ]

        for server_type, vendor_check_func in vendor_checks:
            if vendor_info and vendor_check_func(vendor_info):
                return server_type

        # Check extensions and naming contexts for server type indicators
        ext_str = " ".join(ext.lower() for ext in supported_extensions)
        context_str = " ".join(naming_contexts).lower()

        # Extension/context-based detection (priority order)
        extension_checks: list[tuple[str, Callable[[str, str], bool]]] = [
            ("openldap", lambda e, _c: "openldap" in e),
            ("oid", lambda e, c: "oracle" in e or "oid" in e or "oracle" in c),
            ("oud", lambda e, _c: "oud" in e),
            (
                "ad",
                lambda e, c: "microsoft" in e
                or "windows" in e
                or "microsoft" in c
                or "windows" in c,
            ),
            ("ds389", lambda e, _c: "389" in e or "dirsrv" in e),
        ]

        for server_type, extension_check_func in extension_checks:
            if extension_check_func(ext_str, context_str):
                return server_type

        # Default to RFC-compliant generic server
        return "rfc"
