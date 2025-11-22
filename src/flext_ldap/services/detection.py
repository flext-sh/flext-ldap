"""LDAP server detection service via rootDSE introspection.

Provides server type detection from live LDAP connections by querying rootDSE
and using flext-ldif server quirks detection patterns.

This is the flext-ldap complement to flext-ldif's LDIF content detection:
- flext-ldif: Detects server from LDIF file content
- flext-ldap: Detects server from live LDAP connection (rootDSE)

Both use the SAME detection constants from flext-ldif servers/quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextRuntime
from flext_ldif import FlextLdifDetector
from ldap3 import Connection

from flext_ldap.base import FlextLdapServiceBase


class FlextLdapServerDetector(FlextLdapServiceBase[str]):
    """Detect LDAP server type from live connection via rootDSE.

    Uses flext-ldif server quirks detection constants to identify server types.
    This provides the "live LDAP" complement to flext-ldif's "LDIF file" detection.

    Architecture:
    - Queries rootDSE (base DN "", scope BASE) from live LDAP connection
    - Extracts server-identifying attributes (vendorName, vendorVersion, etc.)
    - Uses detection patterns from flext-ldif servers/quirks Constants
    - Returns detected server type string (oid, oud, openldap, ad, etc.)

    Supported Servers:
    - Oracle Internet Directory (OID)
    - Oracle Unified Directory (OUD)
    - OpenLDAP 1.x/2.x
    - Active Directory (AD)
    - 389 Directory Server
    - Apache Directory Server
    - Novell eDirectory
    - IBM Tivoli Directory Server

    Example:
        >>> detector = FlextLdapServerDetector()
        >>> connection = Connection(server, user="...", password="...")
        >>> connection.bind()
        >>> result = detector.detect_from_connection(connection)
        >>> if result.is_success:
        ...     server_type = result.unwrap()
        ...     print(f"Detected: {server_type}")

    """

    def execute(self, **kwargs: object) -> FlextResult[str]:
        """Execute server detection from connection parameter.

        Args:
            **kwargs: Must contain 'connection' key with ldap3.Connection

        Returns:
            FlextResult[str] with detected server type or error

        """
        connection = kwargs.get("connection")
        if connection is None:  # pragma: no cover
            # Defensive: execute() called directly with proper kwargs in practice
            return FlextResult[str].fail("connection parameter required")

        # Type narrowing: verify connection is ldap3.Connection
        if not isinstance(connection, Connection):  # pragma: no cover
            # Defensive: type passed to execute() is validated by caller
            return FlextResult[str].fail(
                f"connection must be ldap3.Connection, got {type(connection).__name__}",
            )

        return self.detect_from_connection(connection)

    def detect_from_connection(self, connection: Connection) -> FlextResult[str]:
        """Detect server type from live LDAP connection via rootDSE query.

        Queries rootDSE and uses flext-ldif server quirks detection patterns
        to identify the server type.

        Args:
            connection: Active ldap3.Connection (must be bound)

        Returns:
            FlextResult[str] with detected server type or RFC fallback

        Architecture:
            1. Query rootDSE (base="", scope=BASE)
            2. Extract identifying attributes
            3. Score against flext-ldif quirks detection patterns
            4. Return highest confidence match or "rfc" fallback

        """
        self.logger.debug(
            "Detecting server type from connection",
            operation="detect_from_connection",
            connection_bound=connection.bound,
        )

        if not connection.bound:  # pragma: no cover
            # Defensive: connection is always bound before detection
            self.logger.error(  # pragma: no cover
                "Server detection failed - connection not bound",
                operation="detect_from_connection",
            )
            return FlextResult[str].fail(  # pragma: no cover
                "Connection must be bound before server detection",
            )

        root_dse_result = self._query_root_dse(connection)
        if root_dse_result.is_failure:  # pragma: no cover
            # Defensive: rootDSE query typically succeeds for LDAP servers
            self.logger.error(  # pragma: no cover
                "Server detection failed - rootDSE query failed",
                operation="detect_from_connection",
                error=str(root_dse_result.error),
                error_type=type(root_dse_result.error).__name__
                if root_dse_result.error
                else "Unknown",
            )
            return FlextResult[str].fail(  # pragma: no cover
                f"Failed to query rootDSE: {root_dse_result.error}",
            )

        root_dse_attrs = root_dse_result.unwrap()

        self.logger.debug(
            "rootDSE queried successfully",
            operation="detect_from_connection",
            rootdse_attributes_count=len(root_dse_attrs),
            rootdse_attribute_names=list(root_dse_attrs.keys())[:20]
            if root_dse_attrs
            else [],
        )

        vendor_name = (
            root_dse_attrs.get("vendorName", [])[0]
            if root_dse_attrs.get("vendorName")
            else None
        )
        vendor_version = (
            root_dse_attrs.get("vendorVersion", [])[0]
            if root_dse_attrs.get("vendorVersion")
            else None
        )
        naming_contexts = root_dse_attrs.get("namingContexts", [])
        supported_controls = root_dse_attrs.get("supportedControl", [])
        supported_extensions = root_dse_attrs.get("supportedExtension", [])

        self.logger.debug(
            "Extracted rootDSE attributes",
            operation="detect_from_connection",
            vendor_name=vendor_name,
            vendor_version=vendor_version,
            naming_contexts_count=len(naming_contexts),
            naming_contexts=naming_contexts[:10] if naming_contexts else [],
            supported_controls_count=len(supported_controls),
            supported_controls=supported_controls[:10] if supported_controls else [],
            supported_extensions_count=len(supported_extensions),
            supported_extensions=supported_extensions[:10]
            if supported_extensions
            else [],
        )

        result = self._detect_from_attributes(
            vendor_name=vendor_name,
            vendor_version=vendor_version,
            naming_contexts=naming_contexts,
            supported_controls=supported_controls,
            supported_extensions=supported_extensions,
        )

        if result.is_success:
            detected_type = result.unwrap()
            self.logger.info(
                "Server type detected",
                operation="detect_from_connection",
                detected_server_type=detected_type,
            )
        else:
            self.logger.error(
                "Server type detection failed",
                operation="detect_from_connection",
                error=str(result.error),
                error_type=type(result.error).__name__ if result.error else "Unknown",
            )

        return result

    def _query_root_dse(
        self,
        connection: Connection,
    ) -> FlextResult[dict[str, list[str]]]:
        """Query rootDSE from LDAP server.

        rootDSE is queried with:
        - Base DN: "" (empty string)
        - Scope: BASE
        - Filter: (objectClass=*)
        - Attributes: ALL (*)

        Args:
            connection: Active bound ldap3.Connection

        Returns:
            FlextResult with rootDSE attributes dict

        """
        self.logger.debug(
            "Querying rootDSE",
            operation="detect_from_connection",
            search_base="",
            search_filter="(objectClass=*)",
            search_scope="BASE",
        )

        try:
            success = connection.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes="*",
            )

            if not success:  # pragma: no cover
                # Defensive: rootDSE search typically succeeds
                self.logger.error(  # pragma: no cover
                    "rootDSE query failed",
                    operation="detect_from_connection",
                    connection_result=str(connection.result)[:200],
                )
                return FlextResult[dict[str, list[str]]].fail(  # pragma: no cover
                    f"rootDSE query failed: {connection.result}",
                )

            if (
                not connection.entries or len(connection.entries) == 0
            ):  # pragma: no cover
                # Defensive: rootDSE should always return an entry
                self.logger.error(  # pragma: no cover
                    "rootDSE query returned no entries",
                    operation="detect_from_connection",
                )
                return FlextResult[dict[str, list[str]]].fail(  # pragma: no cover
                    "rootDSE query returned no entries",
                )

            root_dse_entry = connection.entries[0]

            attributes: dict[str, list[str]] = {}
            for attr_name in root_dse_entry.entry_attributes:
                attr_value = getattr(root_dse_entry, attr_name, None)
                if attr_value is not None:
                    if FlextRuntime.is_list_like(attr_value):
                        # Type narrowing: is_list_like ensures list[object], convert to list[str]
                        attributes[attr_name] = [str(v) for v in attr_value]
                    else:
                        attributes[attr_name] = [str(attr_value)]

            self.logger.debug(
                "rootDSE entry converted to attributes",
                operation="detect_from_connection",
                attributes_count=len(attributes),
                attribute_names=list(attributes.keys())[:20] if attributes else [],
            )

            return FlextResult[dict[str, list[str]]].ok(attributes)

        except Exception as e:  # pragma: no cover
            # Defensive: rootDSE query should not raise exceptions
            self.logger.exception(  # pragma: no cover
                "Exception querying rootDSE",
                operation="detect_from_connection",
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[dict[str, list[str]]].fail(  # pragma: no cover
                f"Exception querying rootDSE: {e!s}",
            )

    def _detect_from_attributes(
        self,
        vendor_name: str | None,
        vendor_version: str | None,
        naming_contexts: list[str],
        supported_controls: list[str],
        supported_extensions: list[str],
    ) -> FlextResult[str]:
        """Detect server type from rootDSE attributes using flext-ldif patterns.

        Uses the same detection constants from flext-ldif servers/quirks.

        Args:
            vendor_name: vendorName attribute value
            vendor_version: vendorVersion attribute value
            naming_contexts: namingContexts attribute values
            supported_controls: supportedControl OID values
            supported_extensions: supportedExtension OID values

        Returns:
            FlextResult[str] with detected server type

        """
        # Build "pseudo-LDIF content" for flext-ldif detector
        # This allows us to reuse flext-ldif's detection logic
        pseudo_ldif_lines: list[str] = []

        if vendor_name:
            pseudo_ldif_lines.append(f"vendorName: {vendor_name}")
        if vendor_version:
            pseudo_ldif_lines.append(f"vendorVersion: {vendor_version}")

        # Use list.extend for better performance
        pseudo_ldif_lines.extend(f"namingContexts: {nc}" for nc in naming_contexts)
        pseudo_ldif_lines.extend(
            f"supportedControl: {control}" for control in supported_controls
        )
        pseudo_ldif_lines.extend(
            f"supportedExtension: {extension}" for extension in supported_extensions
        )

        pseudo_ldif_content = "\n".join(pseudo_ldif_lines)

        try:
            detector = FlextLdifDetector()
            detection_result = detector.detect_server_type(
                ldif_content=pseudo_ldif_content,
            )

            if detection_result.is_success:
                detection_info = detection_result.unwrap()
                detected_type = detection_info.detected_server_type

                self.logger.info(
                    "Server type detected from attributes",
                    operation="detect_from_connection",
                    detected_type=detected_type,
                    confidence=detection_info.confidence,
                    patterns_found=detection_info.patterns_found,
                )

                return FlextResult[str].ok(detected_type)

            self.logger.error(
                "Server type detection from attributes failed",
                operation="detect_from_connection",
                error=str(detection_result.error),
                error_type=type(detection_result.error).__name__
                if detection_result.error
                else "Unknown",
            )
            return FlextResult[str].fail(f"Detection failed: {detection_result.error}")

        except Exception as e:
            self.logger.exception(
                "Exception during server type detection",
                operation="detect_from_connection",
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[str].fail(f"Detection exception: {e!s}")
