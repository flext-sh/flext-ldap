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
from typing import Literal, ParamSpec

from flext_core import FlextLogger, FlextRuntime, r
from ldap3 import Connection

from flext_ldap.base import s
from flext_ldap.constants import c
from flext_ldap.typings import t
from flext_ldap.utilities import u

P = ParamSpec("P")


class FlextLdapServerDetector(s[str]):
    """Identify a directory server by querying ``rootDSE`` attributes.

    The detector queries the base DN on a bound :class:`ldap3.Connection`,
    extracts vendor attributes, and applies internal heuristics to return a
    normalized server label (for example, ``openldap`` or ``ad``).
    """

    def execute(self, **_kwargs: object) -> r[str]:
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
        # Extract connection from kwargs
        connection_raw = _kwargs.get("connection")
        if connection_raw is None:
            return r[str].fail("connection parameter required")
        # Use isinstance for type validation (u.guard doesn't support external types)
        if not isinstance(connection_raw, Connection):
            return r[str].fail(
                f"connection must be ldap3.Connection, got {type(connection_raw).__name__}",
            )
        # Type narrowing: connection_raw is Connection after isinstance check
        connection: Connection = connection_raw
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
            operation=c.Ldap.LdapOperationNames.DETECT_FROM_CONNECTION.value,
            connection_bound=connection.bound,
        )

        root_dse_result = FlextLdapServerDetector._query_root_dse(connection)
        if root_dse_result.is_failure:
            return r[str].fail(
                f"Failed to query rootDSE: {root_dse_result.error}",
            )

        root_dse_attrs = root_dse_result.unwrap()
        # Extract values from rootDSE attributes
        naming_contexts_raw = root_dse_attrs.get("namingContexts", [])
        supported_controls_raw = root_dse_attrs.get("supportedControl", [])
        supported_extensions_raw = root_dse_attrs.get("supportedExtension", [])
        # Convert to list[str]
        naming_contexts: list[str] = []
        if naming_contexts_raw:
            if FlextRuntime.is_list_like(naming_contexts_raw):
                naming_contexts = [str(item) for item in naming_contexts_raw]
            else:
                naming_contexts = [str(naming_contexts_raw)]
        supported_controls: list[str] = []
        if supported_controls_raw:
            if FlextRuntime.is_list_like(supported_controls_raw):
                supported_controls = [str(item) for item in supported_controls_raw]
            else:
                supported_controls = [str(supported_controls_raw)]
        supported_extensions: list[str] = []
        if supported_extensions_raw:
            if FlextRuntime.is_list_like(supported_extensions_raw):
                supported_extensions = [str(item) for item in supported_extensions_raw]
            else:
                supported_extensions = [str(supported_extensions_raw)]
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
    ) -> r[t.Ldap.Operation.AttributeDict]:
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
        search_scope: Literal["BASE", "LEVEL", "SUBTREE"] = (
            "BASE"  # c.Ldap.LiteralTypes.Ldap3ScopeLiteral
        )
        if not connection.search(
            search_base="",
            search_filter=str(c.Ldap.Filters.ALL_ENTRIES_FILTER),
            search_scope=search_scope,
            attributes=str(c.Ldap.LdapAttributeNames.ALL_ATTRIBUTES),
        ):
            return r[t.Ldap.Operation.AttributeDict].fail(
                f"rootDSE query failed: {connection.result}",
            )

        if not connection.entries:
            return r[dict[str, list[str]]].fail("rootDSE query returned no entries")

        root_dse_entry = connection.entries[0]
        attrs_dict = root_dse_entry.entry_attributes_as_dict

        # Filter None values and convert to list[str]
        filtered_attrs = u.mapper().filter_dict(
            attrs_dict,
            lambda _k, v: v is not None,
        )
        attributes: dict[str, list[str]] = {}
        for k, v in filtered_attrs.items():
            if FlextRuntime.is_list_like(v):
                attributes[k] = [str(item) for item in v]
            else:
                attributes[k] = [str(v)]

        return r[dict[str, list[str]]].ok(attributes)

    @staticmethod
    def _get_first_value(attrs: t.Ldap.Operation.AttributeDict, key: str) -> str | None:
        """Return the first attribute value for ``key`` when present.

        Extract value from attributes dict.
        """
        # Extract value from attributes dict
        values_raw = attrs.get(key)
        values: list[str] | None = None
        if values_raw is not None:
            if FlextRuntime.is_list_like(values_raw):
                values = [str(item) for item in values_raw]
            else:
                values = [str(values_raw)]
        # Check if collection is empty
        if values is None or not values:
            return None
        return str(values[0])

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
        return r[str].ok(detected_type)

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
        # Try vendor-based detection first (most reliable)
        cls = FlextLdapServerDetector
        vendor_result = cls._detect_from_vendor(
            vendor_name,
            vendor_version,
        )
        if vendor_result:
            return vendor_result

        # Fallback to extension/context-based detection
        extension_result = cls._detect_from_extensions(
            supported_extensions,
            naming_contexts,
        )
        # Ensure we always return a string (fallback to "rfc")
        return extension_result if extension_result is not None else "rfc"

    @staticmethod
    def _detect_from_vendor(
        vendor_name: str | None,
        vendor_version: str | None,
    ) -> str | None:
        """Detect server type from vendor information."""
        # DSL pattern: builder for filtering vendor parts
        vendor_list = u.to_str_list([vendor_name, vendor_version])
        # filter_truthy accepts list[object] | dict[str, object]
        # Cast list[str] to list[object] for compatibility
        vendor_list_object: list[object] = [str(item) for item in vendor_list]
        vendor_parts_raw = u.Ldap.filter_truthy(vendor_list_object)
        # filter_truthy returns list[object] | dict[str, object]
        # Type narrowing: vendor_list_object is list[object], so result is list[object]
        vendor_parts: list[str] = (
            [str(item) for item in vendor_parts_raw]
            if isinstance(vendor_parts_raw, list)
            else []
        )
        # Normalize vendor info to lowercase for consistent matching
        vendor_info = " ".join(vendor_parts).lower() if vendor_parts else ""

        if not vendor_info:
            return None

        # Vendor-based detection (priority order)
        vendor_checks: list[tuple[str, Callable[[str], bool]]] = [
            ("oud", lambda v: "oracle" in v and "unified directory" in v),
            (
                "oid",
                lambda v: "oracle" in v
                and (
                    "internet directory" in v
                    or "oid" in v
                    or "corporation" in v
                    or (
                        "unified directory" not in v
                        and len(v.split())
                        <= c.Ldap.ServerTypeMappings.VENDOR_STRING_MAX_TOKENS
                    )
                ),
            ),
            ("openldap", lambda v: "openldap" in v),
            ("ad", lambda v: "microsoft" in v or "active directory" in v),
            ("ds389", lambda v: "389" in v or "dirsrv" in v),
        ]

        # Find matching vendor check
        for detected_vendor_name, check_func in vendor_checks:
            if check_func(vendor_info):
                return detected_vendor_name

        return None

    @staticmethod
    def _detect_from_extensions(
        supported_extensions: list[str],
        naming_contexts: list[str],
    ) -> str:
        """Detect server type from extensions and naming contexts."""
        # DSL pattern: builder for string mapping with normalization and join
        # map_str returns str when join is provided
        ext_str_raw = u.Ldap.map_str(supported_extensions, case="lower", join=" ")
        ext_str = ext_str_raw if isinstance(ext_str_raw, str) else " ".join(ext_str_raw)
        # DSL pattern: builder for normalization and join
        context_str = u.Ldap.norm_join(naming_contexts, case="lower")

        # Extension/context-based detection (priority order)
        # Extension checks as typed variadic callables for find_callable ParamSpec[P] compatibility
        def check_openldap(*args: str) -> bool:
            """Check for OpenLDAP."""
            e = args[0] if args else ""
            return "openldap" in e.lower()

        def check_oid(*args: str) -> bool:
            """Check for Oracle Internet Directory."""
            e = args[0] if args else ""
            c = args[1] if len(args) > 1 else ""
            return "oracle" in e or "oid" in e or "oracle" in c

        def check_oud(*args: str) -> bool:
            """Check for Oracle Unified Directory."""
            e = args[0] if args else ""
            return "oud" in e

        def check_ad(*args: str) -> bool:
            """Check for Active Directory."""
            e = args[0] if args else ""
            c = args[1] if len(args) > 1 else ""
            return (
                "microsoft" in e or "windows" in e or "microsoft" in c or "windows" in c
            )

        def check_ds389(*args: str) -> bool:
            """Check for 389 Directory Server."""
            e = args[0] if args else ""
            return "389" in e or "dirsrv" in e

        # Extension checks - manually find matching server type
        # Avoids ParamSpec[P] complexity of find_callable
        extension_checks = [
            ("openldap", check_openldap),
            ("oid", check_oid),
            ("oud", check_oud),
            ("ad", check_ad),
            ("ds389", check_ds389),
        ]
        found: str | None = None
        logger = FlextLogger(__name__)
        for server_name, check_func in extension_checks:
            try:
                if check_func(ext_str, context_str):
                    found = server_name
                    break
            except Exception as e:
                # Continue if check function raises exception
                logger.debug(
                    f"Server type check failed for {server_name}: {e}",
                    server_name=server_name,
                    error=str(e),
                )
                continue

        # Return found server type or default to RFC-compliant generic server
        return found if found is not None else "rfc"
