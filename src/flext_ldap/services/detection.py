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

from collections.abc import Callable
from typing import TYPE_CHECKING, cast

from flext_core import (
    FlextConfig,
    FlextExceptions,
    FlextLogger,
    FlextResult,
    FlextService,
)
from flext_ldif.services.detector import FlextLdifDetector
from pydantic import computed_field

if TYPE_CHECKING:
    from ldap3 import Connection

logger = FlextLogger.create_module_logger(__name__)


class FlextLdapServerDetector(FlextService[str]):
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

    @computed_field  # type: ignore[misc]
    def service_config(self) -> FlextConfig:
        """Automatic config binding via Pydantic v2 computed_field."""
        return FlextConfig.get_global_instance()

    @property
    def project_config(self) -> FlextConfig:
        """Auto-resolve project-specific configuration by naming convention."""
        try:
            return cast(
                "FlextConfig",
                self._resolve_project_component(
                    "Config",
                    lambda obj: isinstance(obj, FlextConfig),
                ),
            )
        except Exception:
            # Fast fail: return global config if project config not found
            return FlextConfig.get_global_instance()

    def _resolve_project_component(
        self,
        component_suffix: str,
        type_check_func: Callable[[object], bool],
    ) -> object:
        """Resolve project component by naming convention (DRY helper)."""
        service_class_name = self.__class__.__name__
        component_class_name = service_class_name.replace("Service", component_suffix)

        # Fast fail: container must be accessible
        container = self.container

        # Fast fail: component must exist in container
        result = container.get(component_class_name)
        if result.is_failure:
            raise FlextExceptions.NotFoundError(
                message=f"Component '{component_class_name}' not found in container",
                resource_type="component",
                resource_id=component_class_name,
            )

        obj = result.unwrap()
        if not type_check_func(obj):
            msg = (
                f"Component '{component_class_name}' found but type check failed. "
                f"Expected type validated by {type_check_func.__name__}"
            )
            raise FlextExceptions.TypeError(
                message=msg,
                expected_type=component_class_name,
                actual_type=type(obj).__name__,
            )
        return obj

    def execute(self, **kwargs: object) -> FlextResult[str]:
        """Execute server detection from connection parameter.

        Args:
            **kwargs: Must contain 'connection' key with ldap3.Connection

        Returns:
            FlextResult[str] with detected server type or error

        """
        connection = kwargs.get("connection")
        if not connection:
            return FlextResult[str].fail("connection parameter required")

        # Type narrowing: verify connection has required attributes
        # Check for ldap3.Connection attributes instead of isinstance (Connection is TYPE_CHECKING only)
        if not hasattr(connection, "bound") or not hasattr(connection, "search"):
            return FlextResult[str].fail(
                f"connection must be ldap3.Connection, got {type(connection).__name__}"
            )

        # Cast to Connection type for type checker
        connection_typed: Connection = cast("Connection", connection)
        return self.detect_from_connection(connection_typed)

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
        logger.debug(
            "Detecting server type from connection",
            operation="detect_from_connection",
            connection_bound=connection.bound,
        )
        
        if not connection.bound:
            logger.error(
                "Server detection failed - connection not bound",
                operation="detect_from_connection",
            )
            return FlextResult[str].fail(
                "Connection must be bound before server detection"
            )

        root_dse_result = self._query_root_dse(connection)
        if root_dse_result.is_failure:
            logger.error(
                "Server detection failed - rootDSE query failed",
                operation="detect_from_connection",
                error=str(root_dse_result.error),
                error_type=type(root_dse_result.error).__name__ if root_dse_result.error else "Unknown",
            )
            return FlextResult[str].fail(
                f"Failed to query rootDSE: {root_dse_result.error}"
            )

        root_dse_attrs = root_dse_result.unwrap()
        
        logger.debug(
            "rootDSE queried successfully",
            operation="detect_from_connection",
            rootdse_attributes_count=len(root_dse_attrs),
            rootdse_attribute_names=list(root_dse_attrs.keys())[:20] if root_dse_attrs else [],
        )
        
        vendor_name = self._get_attribute_value(root_dse_attrs, "vendorName")
        vendor_version = self._get_attribute_value(root_dse_attrs, "vendorVersion")
        naming_contexts = self._get_attribute_values(root_dse_attrs, "namingContexts")
        supported_controls = self._get_attribute_values(
            root_dse_attrs, "supportedControl"
        )
        supported_extensions = self._get_attribute_values(
            root_dse_attrs, "supportedExtension"
        )

        logger.debug(
            "Extracted rootDSE attributes",
            operation="detect_from_connection",
            vendor_name=vendor_name,
            vendor_version=vendor_version,
            naming_contexts_count=len(naming_contexts),
            naming_contexts=naming_contexts[:10] if naming_contexts else [],
            supported_controls_count=len(supported_controls),
            supported_controls=supported_controls[:10] if supported_controls else [],
            supported_extensions_count=len(supported_extensions),
            supported_extensions=supported_extensions[:10] if supported_extensions else [],
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
            logger.info(
                "Server type detected",
                operation="detect_from_connection",
                detected_server_type=detected_type,
            )
        else:
            logger.error(
                "Server type detection failed",
                operation="detect_from_connection",
                error=str(result.error),
                error_type=type(result.error).__name__ if result.error else "Unknown",
            )
        
        return result

    def _query_root_dse(
        self, connection: Connection
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
        logger.debug(
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

            if not success:
                logger.error(
                    "rootDSE query failed",
                    operation="detect_from_connection",
                    connection_result=str(connection.result)[:200],
                )
                return FlextResult[dict[str, list[str]]].fail(
                    f"rootDSE query failed: {connection.result}"
                )

            if not connection.entries or len(connection.entries) == 0:
                logger.error(
                    "rootDSE query returned no entries",
                    operation="detect_from_connection",
                )
                return FlextResult[dict[str, list[str]]].fail(
                    "rootDSE query returned no entries"
                )

            root_dse_entry = connection.entries[0]

            attributes: dict[str, list[str]] = {}
            for attr_name in root_dse_entry.entry_attributes:
                attr_value = getattr(root_dse_entry, attr_name, None)
                if attr_value is not None:
                    if isinstance(attr_value, list):
                        attributes[attr_name] = [str(v) for v in attr_value]
                    else:
                        attributes[attr_name] = [str(attr_value)]
            
            logger.debug(
                "rootDSE entry converted to attributes",
                operation="detect_from_connection",
                attributes_count=len(attributes),
                attribute_names=list(attributes.keys())[:20] if attributes else [],
            )

            return FlextResult[dict[str, list[str]]].ok(attributes)

        except Exception as e:
            logger.exception(
                "Exception querying rootDSE",
                operation="detect_from_connection",
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[dict[str, list[str]]].fail(
                f"Exception querying rootDSE: {e!s}"
            )

    def _get_attribute_value(
        self, attributes: dict[str, list[str]], attr_name: str
    ) -> str | None:
        """Get single attribute value from attributes dict.

        Args:
            attributes: Attributes dict from rootDSE
            attr_name: Attribute name to retrieve

        Returns:
            First value if exists, None otherwise

        """
        values = attributes.get(attr_name, [])
        return values[0] if values else None

    def _get_attribute_values(
        self, attributes: dict[str, list[str]], attr_name: str
    ) -> list[str]:
        """Get all attribute values from attributes dict.

        Args:
            attributes: Attributes dict from rootDSE
            attr_name: Attribute name to retrieve

        Returns:
            List of values (empty list if attribute doesn't exist)

        """
        return attributes.get(attr_name, [])

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
                ldif_content=pseudo_ldif_content
            )
            
            if detection_result.is_success:
                detection_info = detection_result.unwrap()
                detected_type = detection_info.detected_server_type

                logger.info(
                    "Server type detected from attributes",
                    operation="detect_from_connection",
                    detected_type=detected_type,
                    confidence=detection_info.confidence,
                    patterns_found=detection_info.patterns_found,
                )

                return FlextResult[str].ok(detected_type)
            
            logger.error(
                "Server type detection from attributes failed",
                operation="detect_from_connection",
                error=str(detection_result.error),
                error_type=type(detection_result.error).__name__ if detection_result.error else "Unknown",
            )
            return FlextResult[str].fail(f"Detection failed: {detection_result.error}")

        except Exception as e:
            logger.exception(
                "Exception during server type detection",
                operation="detect_from_connection",
                error=str(e),
                error_type=type(e).__name__,
            )
            return FlextResult[str].fail(f"Detection exception: {e!s}")
