"""LDAP server detection service via rootDSE introspection.

Provides server type detection from live LDAP connections by querying rootDSE
and using flext-ldif server quirks detection patterns.

This is the flext-ldap complement to flext-ldif's LDIF content detection:
- flext-ldif: Detects server from LDIF file content
- flext-ldap: Detects server from live LDAP connection (rootDSE)

Both use the SAME detection constants from flext-ldif servers/quirks.

Module: FlextLdapServerDetector
Scope: Server type detection from live LDAP connections via rootDSE
Pattern: Service extending FlextLdapServiceBase, delegates to flext-ldif detector

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextResult, FlextRuntime
from flext_ldif import FlextLdif
from ldap3 import Connection

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.typings import FlextLdapTypes


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

    def execute(self, **_kwargs: object) -> FlextResult[str]:
        """Execute server detection from connection parameter.

        Args:
            **_kwargs: Must contain 'connection' key with ldap3.Connection

        Returns:
            FlextResult[str] with detected server type or error

        """
        connection = _kwargs.get("connection")
        if connection is None:
            return FlextResult[str].fail("connection parameter required")
        if not isinstance(connection, Connection):
            return FlextResult[str].fail(
                f"connection must be ldap3.Connection, got {type(connection).__name__}"
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

        root_dse_result = self._query_root_dse(connection)
        if root_dse_result.is_failure:
            return FlextResult[str].fail(
                f"Failed to query rootDSE: {root_dse_result.error}"
            )

        root_dse_attrs = root_dse_result.unwrap()
        return self._detect_from_attributes(
            vendor_name=self._get_first_value(root_dse_attrs, "vendorName"),
            vendor_version=self._get_first_value(root_dse_attrs, "vendorVersion"),
            naming_contexts=list(root_dse_attrs.get("namingContexts", [])),
            supported_controls=list(root_dse_attrs.get("supportedControl", [])),
            supported_extensions=list(root_dse_attrs.get("supportedExtension", [])),
        )

    def _query_root_dse(
        self,
        connection: Connection,
    ) -> FlextResult[FlextLdapTypes.LdapAttributes]:
        """Query rootDSE from LDAP server using FlextUtilities for generalization."""
        if not connection.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope="BASE",
            attributes="*",
        ):
            return FlextResult[FlextLdapTypes.LdapAttributes].fail(
                f"rootDSE query failed: {connection.result}"
            )

        if not connection.entries:
            return FlextResult[FlextLdapTypes.LdapAttributes].fail(
                "rootDSE query returned no entries"
            )

        root_dse_entry = connection.entries[0]
        attributes: dict[str, list[str]] = {}
        for attr_name in root_dse_entry.entry_attributes:
            attr_value = getattr(root_dse_entry, attr_name, None)
            if attr_value is not None:
                attributes[attr_name] = (
                    [str(v) for v in attr_value]
                    if FlextRuntime.is_list_like(attr_value)
                    else [str(attr_value)]
                )

        return FlextResult[FlextLdapTypes.LdapAttributes].ok(attributes)

    @staticmethod
    def _get_first_value(attrs: FlextLdapTypes.LdapAttributes, key: str) -> str | None:
        """Extract first value from attribute list if present."""
        values = attrs.get(key)
        if not values:
            return None
        return str(values[0])

    def _detect_from_attributes(
        self,
        vendor_name: str | None,
        vendor_version: str | None,
        naming_contexts: list[str],
        supported_controls: list[str],
        supported_extensions: list[str],
    ) -> FlextResult[str]:
        """Detect server type from rootDSE attributes using flext-ldif patterns."""
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

        detection_result = FlextLdif.get_instance().detector.detect_server_type(
            ldif_content="\n".join(pseudo_ldif_lines),
        )

        if detection_result.is_success:
            return FlextResult[str].ok(detection_result.unwrap().detected_server_type)
        return FlextResult[str].fail(f"Detection failed: {detection_result.error}")
