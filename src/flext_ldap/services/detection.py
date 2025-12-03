"""Detect LDAP server type from a bound ``ldap3`` connection.

The service inspects ``rootDSE`` attributes and applies lightweight heuristics
so callers can classify a live directory server without relying on external
detectors. Results are returned as :class:`flext_core.FlextResult` instances.

Business Rules:
    - Connection MUST be bound before detection (queries rootDSE base DN "")
    - Vendor-based detection is prioritized over extension/context checks
    - Detection priority order: OID > OUD > OpenLDAP > AD > DS389 > RFC
    - Defaults to "rfc" (RFC-compliant generic server) if no match
    - Case-insensitive matching for all vendor info and extensions

Audit Implications:
    - Detection queries are logged at DEBUG level (not ERROR on failure)
    - Server type affects LDIF parsing quirks and entry normalization
    - Detection results enable server-specific optimizations and audit trails
    - Failed rootDSE queries return error result with connection.result details

Architecture Notes:
    - Uses static methods for testability (_query_root_dse, _detect_from_attributes)
    - Returns FlextResult pattern - no exceptions raised from detection logic
    - Extends FlextLdapServiceBase[str] for health check capability
    - Detection is non-blocking (failures don't affect connection state)
    - ldap3 Connection import is required here (infrastructure layer)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from flext_core import FlextRuntime
from flext_core.result import FlextResult as r
from ldap3 import Connection

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.constants import FlextLdapConstants as c
from flext_ldap.typings import FlextLdapTypes as t
from flext_ldap.utilities import FlextLdapUtilities as u


class FlextLdapServerDetector(FlextLdapServiceBase[str]):
    """Identify a directory server by querying ``rootDSE`` attributes.

    The detector queries the base DN on a bound :class:`ldap3.Connection`,
    extracts vendor attributes, and applies internal heuristics to return a
    normalized server label (for example, ``openldap`` or ``ad``).
    """

    def execute(self, **_kwargs: str | float | bool | None) -> r[str]:
        """Detect server type using a provided ``ldap3.Connection`` instance.

        Business Rules:
            - Requires 'connection' parameter in kwargs (ldap3.Connection instance)
            - Delegates to detect_from_connection() for actual detection logic
            - Returns r.fail() if connection parameter missing or invalid type
            - Connection must be bound before detection (validated by detect_from_connection)

        Audit Implications:
            - Detection queries are logged at DEBUG level
            - Server type detection affects quirk application for entry parsing
            - Failed detection returns error message for troubleshooting

        Architecture:
            - Entry point for FlextService.execute() protocol compliance
            - Delegates to detect_from_connection() for actual implementation
            - Uses FlextResult pattern for consistent error handling
        """
        # Use u.get() mnemonic: extract from kwargs with default
        connection = u.get(_kwargs, "connection")
        if connection is None:
            return r[str].fail("connection parameter required")
        # Use isinstance for type validation (u.guard doesn't support external types)
        if not isinstance(connection, Connection):
            return r[str].fail(f"connection must be ldap3.Connection, got {type(connection).__name__}")
        return self.detect_from_connection(connection)

    def detect_from_connection(self, connection: Connection) -> r[str]:
        """Query ``rootDSE`` and return a detected server label.

        Business Rules:
            - Connection must be bound before detection (queries rootDSE)
            - Queries base DN "" with BASE scope to fetch rootDSE attributes
            - Extracts vendorName, vendorVersion, namingContexts, supportedControl, supportedExtension
            - Applies heuristic detection based on vendor info and extensions
            - Returns normalized server type string (oid, oud, openldap, ad, ds389, rfc)
            - Defaults to "rfc" if no vendor-specific indicators found

        Audit Implications:
            - Detection queries are logged at DEBUG level
            - Failed rootDSE queries return error result (not logged at ERROR)
            - Detection results enable server-specific quirk application
            - Server type affects LDIF parsing and entry normalization

        Architecture:
            - Uses static methods for testability (_query_root_dse, _detect_from_attributes)
            - Returns FlextResult pattern - no exceptions raised
            - Detection is non-blocking (failures don't affect connection)

        Args:
            connection: Active ldap3.Connection instance (must be bound).

        Returns:
            r[str]: Normalized server type string (oid, oud, openldap, ad, ds389, rfc)
            or error if rootDSE query fails.

        """
        self.logger.debug(
            "Detecting server type from connection",
            operation=c.LdapOperationNames.DETECT_FROM_CONNECTION.value,
            connection_bound=connection.bound,
        )

        root_dse_result = FlextLdapServerDetector._query_root_dse(connection)
        if root_dse_result.is_failure:
            return r[str].fail(
                f"Failed to query rootDSE: {root_dse_result.error}",
            )

        root_dse_attrs = root_dse_result.unwrap()
        # Use u.extract for safer nested access
        naming_contexts_result: r[list[str] | None] = u.extract(
            root_dse_attrs,
            "namingContexts",
            default=[],
        )
        supported_controls_result: r[list[str] | None] = u.extract(
            root_dse_attrs,
            "supportedControl",
            default=[],
        )
        supported_extensions_result: r[list[str] | None] = u.extract(
            root_dse_attrs,
            "supportedExtension",
            default=[],
        )
        # Extract values from results
        naming_contexts: list[str] = (
            list(naming_contexts_result.value)
            if naming_contexts_result.is_success
            and naming_contexts_result.value is not None
            else []
        )
        supported_controls: list[str] = (
            list(supported_controls_result.value)
            if supported_controls_result.is_success
            and supported_controls_result.value is not None
            else []
        )
        supported_extensions: list[str] = (
            list(supported_extensions_result.value)
            if supported_extensions_result.is_success
            and supported_extensions_result.value is not None
            else []
        )
        return FlextLdapServerDetector._detect_from_attributes(
            vendor_name=FlextLdapServerDetector._get_first_value(
                root_dse_attrs,
                "vendorName",
            ),
            vendor_version=FlextLdapServerDetector._get_first_value(
                root_dse_attrs,
                "vendorVersion",
            ),
            naming_contexts=naming_contexts,
            _supported_controls=supported_controls,
            supported_extensions=supported_extensions,
        )

    @staticmethod
    def _query_root_dse(
        connection: Connection,
    ) -> r[t.Ldap.Attributes]:
        """Fetch ``rootDSE`` attributes from the active connection.

        Business Rules:
            - Queries base DN "" with BASE scope to fetch rootDSE
            - Uses (objectClass=*) filter to match all entries
            - Requests ALL_ATTRIBUTES to get complete rootDSE information
            - Normalizes attribute values to list[str] format
            - Filters out None values from attribute dict
            - Returns failure if search fails or no entries returned

        Audit Implications:
            - rootDSE queries are logged at DEBUG level
            - Failed queries return error with connection.result details
            - Attribute normalization preserves original values

        Architecture:
            - Uses ldap3 Connection.search() directly
            - Uses FlextRuntime.is_list_like() for type-safe value handling
            - Returns FlextResult pattern - no exceptions raised

        Args:
            connection: Active ldap3.Connection instance (must be bound).

        Returns:
            r[Attributes]: Dict mapping attribute names to list[str] values
            or error if rootDSE query fails.

        """
        # ldap3 expects Literal["BASE", "LEVEL", "SUBTREE"] - use StrEnum value directly
        search_scope: c.LiteralTypes.Ldap3ScopeLiteral = "BASE"
        if not connection.search(
            search_base="",
            search_filter=str(c.Filters.ALL_ENTRIES_FILTER),
            search_scope=search_scope,
            attributes=str(c.LdapAttributeNames.ALL_ATTRIBUTES),
        ):
            return u.fail(
                f"rootDSE query failed: {connection.result}",
            )

        # Use u.empty() mnemonic: check if collection is empty
        if u.empty(connection.entries):
            return r[t.Ldap.Attributes].fail("rootDSE query returned no entries")

        root_dse_entry = connection.entries[0]
        attrs_dict = root_dse_entry.entry_attributes_as_dict

        # DSL pattern: builder for not-none filtering
        filtered_attrs = u.filter_not_none(attrs_dict)
        attributes = u.map(
            cast("dict[str, object]", filtered_attrs),
            mapper=lambda _k, v: cast(
                "list[str]",
                u.ensure(
                    cast("t.GeneralValueType", v), target_type="str_list", default=[]
                ),
            )
            if FlextRuntime.is_list_like(cast("t.GeneralValueType", v))
            else [str(v)],
        )

        return u.ok(attributes)

    @staticmethod
    def _get_first_value(attrs: t.Ldap.Attributes, key: str) -> str | None:
        """Return the first attribute value for ``key`` when present.

        Uses u.extract for safer nested access.
        """
        # Use u.extract for safer nested access
        values_result: r[list[str] | None] = u.extract(
            attrs,
            key,
            default=None,
        )
        # Use u.val() mnemonic: extract value with default
        values: list[str] | None = u.val(values_result, default=None)
        # DSL pattern: use empty for collection check, then extract first
        if values is None or u.empty(values):
            return None
        # DSL pattern: conditional value extraction with when
        return u.when(
            condition=not u.empty(values),
            then_value=str(values[0]) if values else None,
            else_value=None,
        )

    @staticmethod
    def _detect_from_attributes(
        vendor_name: str | None,
        vendor_version: str | None,
        naming_contexts: list[str],
        _supported_controls: list[str],
        supported_extensions: list[str],
    ) -> r[str]:
        """Classify the server using collected ``rootDSE`` attributes.

        Business Rules:
            - Delegates to _detect_server_type_from_attributes_simple() for heuristics
            - Vendor info is prioritized over extension/context checks
            - Returns normalized server type string (oid, oud, openldap, ad, ds389, rfc)
            - Always returns success (defaults to "rfc" if no match)

        Audit Implications:
            - Detection logic is deterministic (no randomness)
            - Server type affects LDIF parsing quirks and entry normalization
            - Detection results enable server-specific optimizations

        Architecture:
            - Uses static method for testability
            - Always returns success (no failures from detection logic)
            - Delegates to simple detection to avoid broken flext-ldif detector

        Args:
            vendor_name: Vendor name from rootDSE (e.g., "Oracle Corporation").
            vendor_version: Vendor version from rootDSE (e.g., "12.2.1.4.0").
            naming_contexts: List of naming contexts from rootDSE.
            _supported_controls: List of supported LDAP controls (unused, kept for API compatibility).
            supported_extensions: List of supported LDAP extensions.

        Returns:
            r[str]: Always success with normalized server type string.

        """
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
        return u.ok(detected_type)

    @staticmethod
    def _detect_server_type_from_attributes_simple(
        supported_extensions: list[str],
        naming_contexts: list[str],
        vendor_name: str | None = None,
        vendor_version: str | None = None,
    ) -> str:
        """Apply heuristic detection to map attributes to a server label.

        Business Rules:
            - Vendor-based detection is checked FIRST (most reliable)
            - Extension/context-based detection is checked SECOND (fallback)
            - Priority order: OID > OUD > OpenLDAP > AD > DS389 > RFC
            - Case-insensitive matching for vendor info and extensions
            - Defaults to "rfc" if no vendor-specific indicators found

        Audit Implications:
            - Detection results affect LDIF parsing quirks
            - Server type enables server-specific optimizations
            - Detection is deterministic (no randomness)

        Architecture:
            - Uses lambda functions for vendor/extension checks
            - Priority order ensures consistent detection
            - Returns normalized string (not enum) for flexibility

        Args:
            supported_extensions: List of supported LDAP extensions from rootDSE.
            naming_contexts: List of naming contexts from rootDSE.
            vendor_name: Optional vendor name from rootDSE.
            vendor_version: Optional vendor version from rootDSE.

        Returns:
            str: Normalized server type (oid, oud, openldap, ad, ds389, rfc).

        """
        # DSL pattern: builder for filtering vendor parts
        vendor_parts: list[str] = cast(
            "list[str]",
            u.filter_truthy(cast("dict[str, object] | list[object]", u.to_str_list([vendor_name, vendor_version]))),
        )
        # Use u.normalize() for consistent case handling
        vendor_info = (
            u.normalize(" ".join(vendor_parts), case="lower") if vendor_parts else ""
        )

        # Vendor-based detection (priority order)
        # Use u.find() for efficient vendor check detection
        if vendor_info and isinstance(vendor_info, str):
            vendor_checks: list[tuple[str, Callable[[str], bool]]] = [
                (
                    "oid",
                    lambda v: "oracle" in v
                    and ("internet directory" in v or "oid" in v),
                ),
                ("oud", lambda v: "oracle" in v and "unified directory" in v),
                ("openldap", lambda v: "openldap" in v),
                ("ad", lambda v: "microsoft" in v or "active directory" in v),
                ("ds389", lambda v: "389" in v or "dirsrv" in v),
            ]

            # DSL pattern: builder for callable matching
            found_check = u.find_callable(vendor_checks, vendor_info)
            if found_check is not None:
                return found_check

        # DSL pattern: builder for string mapping with normalization and join
        ext_str = u.map_str(supported_extensions, case="lower", join=" ")
        # DSL pattern: builder for normalization and join
        context_str = u.norm_join(naming_contexts, case="lower")

        # Extension/context-based detection (priority order)
        # DSL pattern: server_type -> predicate function, find first match
        extension_checks: dict[str, Callable[[str, str], bool]] = {
            "openldap": lambda e, _c: "openldap" in e,
            "oid": lambda e, c: "oracle" in e or "oid" in e or "oracle" in c,
            "oud": lambda e, _c: "oud" in e,
            "ad": lambda e, c: "microsoft" in e
            or "windows" in e
            or "microsoft" in c
            or "windows" in c,
            "ds389": lambda e, _c: "389" in e or "dirsrv" in e,
        }

        # DSL pattern: builder for callable matching
        found = u.find_callable(extension_checks, ext_str, context_str)

        # Return found server type or default to RFC-compliant generic server
        # DSL pattern: use when for conditional default
        # DSL pattern: conditional default
        return found if found is not None else "rfc"
