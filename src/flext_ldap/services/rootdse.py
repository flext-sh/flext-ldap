"""LDAP Root DSE Service Implementation.

This module provides comprehensive Root DSE (Directory Service Entry) functionality
for discovering LDAP server capabilities, supported extensions, and configuration.
Based on perl-ldap Net::LDAP::RootDSE with enhanced Python patterns.

The Root DSE is a special LDAP entry that contains information about the LDAP
server's capabilities, supported features, and configuration. It's essential
for building intelligent LDAP clients that adapt to server capabilities.

Architecture:
    - RootDSEService: Main service for Root DSE operations
    - ServerInfo: Comprehensive server information model
    - ExtensionInfo: Detailed extension capability information
    - ControlInfo: LDAP control support information

Usage Example:
    >>> from flext_ldap.services.rootdse import RootDSEService
    >>>
    >>> # Basic server discovery
    >>> service = RootDSEService(connection)
    >>> info = await service.discover_capabilities()
    >>>
    >>> print(f"Server vendor: {info.vendor}")
    >>> print(f"LDAP version: {info.ldap_version}")
    >>> print(f"Naming contexts: {info.naming_contexts}")
    >>>
    >>> # Check specific capabilities
    >>> if service.supports_extension("1.3.6.1.4.1.4203.1.11.3"):
    ...     print("WhoAmI extension supported")
    >>>
    >>> if service.supports_control("2.16.840.1.113730.3.4.2"):
    ...     print("ManageDsaIT control supported")

References:
    - perl-ldap: lib/Net/LDAP/RootDSE.pm
    - RFC 4512: LDAP Directory Information Models
    - RFC 4513: LDAP Authentication Methods and Security Mechanisms
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, ClassVar

from pydantic import BaseModel, Field


class LDAPVersion(Enum):
    """Supported LDAP protocol versions."""

    V2 = "2"
    V3 = "3"


class ServerVendor(Enum):
    """Known LDAP server vendors."""

    OPENLDAP = "OpenLDAP"
    MICROSOFT_AD = "Microsoft Active Directory"
    IBM_DOMINO = "IBM Domino"
    NOVELL_EDIRECTORY = "Novell eDirectory"
    SUN_DIRECTORY = "Sun Directory Server"
    ORACLE_DIRECTORY = "Oracle Internet Directory"
    APACHE_DIRECTORY = "Apache Directory Server"
    UNKNOWN = "Unknown"


class ExtensionInfo(BaseModel):
    """Information about supported LDAP extensions."""

    oid: str = Field(description="Extension OID")

    name: str | None = Field(
        default=None,
        description="Human-readable extension name",
    )

    description: str | None = Field(
        default=None,
        description="Extension description",
    )

    rfc: str | None = Field(default=None, description="RFC specification reference")

    is_critical: bool = Field(
        default=False,
        description="Whether extension is critical for operation",
    )


class ControlInfo(BaseModel):
    """Information about supported LDAP controls."""

    oid: str = Field(description="Control OID")

    name: str | None = Field(default=None, description="Human-readable control name")

    description: str | None = Field(default=None, description="Control description")

    criticality: bool = Field(default=False, description="Whether control is critical")


class ServerInfo(BaseModel):
    """Comprehensive LDAP server information."""

    # Basic server identification
    vendor: ServerVendor = Field(
        default=ServerVendor.UNKNOWN,
        description="Server vendor/implementation",
    )

    version: str | None = Field(default=None, description="Server version string")

    ldap_version: list[LDAPVersion] = Field(
        default_factory=list,
        description="Supported LDAP protocol versions",
    )

    # Directory structure
    naming_contexts: list[str] = Field(
        default_factory=list,
        description="Available naming contexts (base DNs)",
    )

    default_naming_context: str | None = Field(
        default=None,
        description="Default naming context",
    )

    schema_naming_context: str | None = Field(
        default=None,
        description="Schema naming context",
    )

    config_naming_context: str | None = Field(
        default=None,
        description="Configuration naming context",
    )

    # Capabilities
    supported_extensions: list[ExtensionInfo] = Field(
        default_factory=list,
        description="Supported LDAP extensions",
    )

    supported_controls: list[ControlInfo] = Field(
        default_factory=list,
        description="Supported LDAP controls",
    )

    supported_sasl_mechanisms: list[str] = Field(
        default_factory=list,
        description="Supported SASL authentication mechanisms",
    )

    supported_features: list[str] = Field(
        default_factory=list,
        description="Additional supported features",
    )

    # Security and policies
    supports_tls: bool = Field(
        default=False,
        description="Whether server supports TLS/SSL",
    )

    requires_authentication: bool = Field(
        default=True,
        description="Whether server requires authentication",
    )

    password_policy_enabled: bool = Field(
        default=False,
        description="Whether password policy is enabled",
    )

    # Server-specific attributes
    server_name: str | None = Field(default=None, description="Server name/hostname")

    domain_name: str | None = Field(default=None, description="Domain name")

    forest_name: str | None = Field(
        default=None,
        description="Forest name (Active Directory)",
    )

    # Timestamps and metadata
    discovered_at: datetime = Field(
        default_factory=datetime.now,
        description="When server info was discovered",
    )

    raw_attributes: dict[str, Any] = Field(
        default_factory=dict,
        description="Raw Root DSE attributes from server",
    )

    def get_extension_by_oid(self, oid: str) -> ExtensionInfo | None:
        """Get extension information by OID."""
        for ext in self.supported_extensions:
            if ext.oid == oid:
                return ext
        return None

    def get_control_by_oid(self, oid: str) -> ControlInfo | None:
        """Get control information by OID."""
        for ctrl in self.supported_controls:
            if ctrl.oid == oid:
                return ctrl
        return None

    def supports_extension(self, oid: str) -> bool:
        """Check if server supports specific extension."""
        return self.get_extension_by_oid(oid) is not None

    def supports_control(self, oid: str) -> bool:
        """Check if server supports specific control."""
        return self.get_control_by_oid(oid) is not None

    def supports_sasl_mechanism(self, mechanism: str) -> bool:
        """Check if server supports specific SASL mechanism."""
        return mechanism.upper() in [m.upper() for m in self.supported_sasl_mechanisms]

    def is_active_directory(self) -> bool:
        """Check if server is Microsoft Active Directory."""
        return self.vendor == ServerVendor.MICROSOFT_AD

    def is_openldap(self) -> bool:
        """Check if server is OpenLDAP."""
        return self.vendor == ServerVendor.OPENLDAP

    def get_primary_naming_context(self) -> str | None:
        """Get the primary/default naming context."""
        if self.default_naming_context:
            return self.default_naming_context

        if self.naming_contexts:
            return self.naming_contexts[0]

        return None

    def get_capabilities_summary(self) -> dict[str, Any]:
        """Get summary of server capabilities."""
        return {
            "vendor": self.vendor.value,
            "version": self.version,
            "ldap_versions": [v.value for v in self.ldap_version],
            "extensions_count": len(self.supported_extensions),
            "controls_count": len(self.supported_controls),
            "sasl_mechanisms_count": len(self.supported_sasl_mechanisms),
            "supports_tls": self.supports_tls,
            "naming_contexts_count": len(self.naming_contexts),
        }


class RootDSEService:
    """Service for Root DSE discovery and server capability detection.

    This service provides comprehensive Root DSE functionality for discovering
    LDAP server capabilities, supported extensions, and configuration information.

    Example:
        >>> service = RootDSEService(connection)
        >>> info = await service.discover_capabilities()
        >>> print(f"Server: {info.vendor.value} {info.version}")
        >>>
        >>> if service.supports_extension("1.3.6.1.4.1.4203.1.11.3"):
        ...     print("WhoAmI extension available")
    """

    # Well-known extension OIDs and their names
    KNOWN_EXTENSIONS: ClassVar[dict[str, dict[str, str]]] = {
        "1.3.6.1.4.1.4203.1.11.3": {
            "name": "Who Am I",
            "description": "RFC 4532 - LDAP Who Am I Operation",
            "rfc": "RFC 4532",
        },
        "1.3.6.1.4.1.4203.1.11.1": {
            "name": "Password Modify",
            "description": "RFC 3062 - LDAP Password Modify Extended Operation",
            "rfc": "RFC 3062",
        },
        "1.3.6.1.4.1.1466.20037": {
            "name": "Start TLS",
            "description": "RFC 4511 - Start TLS Operation",
            "rfc": "RFC 4511",
        },
        "1.3.6.1.1.8": {
            "name": "Cancel",
            "description": "RFC 3909 - LDAP Cancel Operation",
            "rfc": "RFC 3909",
        },
        "1.3.6.1.4.1.4203.1.11.2": {
            "name": "Refresh",
            "description": "RFC 4525 - LDAP Modify-Increment Extension",
            "rfc": "RFC 4525",
        },
    }

    # Well-known control OIDs and their names
    KNOWN_CONTROLS: ClassVar[dict[str, dict[str, str]]] = {
        "2.16.840.1.113730.3.4.2": {
            "name": "ManageDsaIT",
            "description": "RFC 3296 - Named Subordinate References in LDAP",
        },
        "1.2.840.113556.1.4.319": {
            "name": "Paged Results",
            "description": "RFC 2696 - LDAP Control Extension for Simple Paged Results",
        },
        "2.16.840.1.113730.3.4.18": {
            "name": "Proxy Authorization",
            "description": "RFC 4370 - LDAP Proxied Authorization Control",
        },
        "1.2.840.113556.1.4.473": {
            "name": "Sort",
            "description": "RFC 2891 - LDAP Control Extension for Server Side Sorting",
        },
        "1.3.6.1.4.1.42.2.27.8.5.1": {
            "name": "Password Policy",
            "description": "Password Policy Control for LDAP",
        },
    }

    def __init__(self, connection: Any) -> None:
        """Initialize Root DSE service.

        Args:
            connection: Active LDAP connection
        """
        self._connection = connection
        self._cached_info: ServerInfo | None = None

    async def discover_capabilities(self, force_refresh: bool = False) -> ServerInfo:
        """Discover comprehensive server capabilities.

        Args:
            force_refresh: Force refresh of cached information

        Returns:
            Complete server information

        Raises:
            NotImplementedError: Connection integration not yet implemented
        """
        if self._cached_info and not force_refresh:
            return self._cached_info

        # TODO: Implement actual Root DSE query
        # This is a stub implementation
        msg = (
            "Root DSE discovery requires connection manager integration. "
            "Implement search for '' (empty DN) with base scope."
        )
        raise NotImplementedError(msg)

    def supports_extension(self, oid: str) -> bool:
        """Check if server supports specific extension.

        Args:
            oid: Extension OID to check

        Returns:
            True if extension is supported
        """
        if self._cached_info:
            return self._cached_info.supports_extension(oid)
        return False

    def supports_control(self, oid: str) -> bool:
        """Check if server supports specific control.

        Args:
            oid: Control OID to check

        Returns:
            True if control is supported
        """
        if self._cached_info:
            return self._cached_info.supports_control(oid)
        return False

    def get_naming_contexts(self) -> list[str]:
        """Get available naming contexts.

        Returns:
            List of naming context DNs
        """
        if self._cached_info:
            return self._cached_info.naming_contexts
        return []

    def get_schema_dn(self) -> str | None:
        """Get schema naming context DN.

        Returns:
            Schema DN or None if not available
        """
        if self._cached_info:
            return self._cached_info.schema_naming_context
        return None

    def _parse_root_dse_attributes(self, attributes: dict[str, Any]) -> ServerInfo:
        """Parse Root DSE attributes into ServerInfo model.

        Args:
            attributes: Raw Root DSE attributes

        Returns:
            Parsed server information
        """
        # Extract basic information
        naming_contexts = self._extract_list_attribute(attributes, "namingContexts")
        supported_extensions_oids = self._extract_list_attribute(
            attributes,
            "supportedExtension",
        )
        supported_controls_oids = self._extract_list_attribute(
            attributes,
            "supportedControl",
        )
        supported_sasl = self._extract_list_attribute(
            attributes,
            "supportedSASLMechanisms",
        )
        supported_ldap_versions = self._extract_list_attribute(
            attributes,
            "supportedLDAPVersion",
        )

        # Parse extensions
        extensions = []
        for oid in supported_extensions_oids:
            ext_info = self.KNOWN_EXTENSIONS.get(oid, {})
            extensions.append(
                ExtensionInfo(
                    oid=oid,
                    name=ext_info.get("name"),
                    description=ext_info.get("description"),
                    rfc=ext_info.get("rfc"),
                ),
            )

        # Parse controls
        controls = []
        for oid in supported_controls_oids:
            ctrl_info = self.KNOWN_CONTROLS.get(oid, {})
            controls.append(
                ControlInfo(
                    oid=oid,
                    name=ctrl_info.get("name"),
                    description=ctrl_info.get("description"),
                ),
            )

        # Detect server vendor and version
        vendor, version = self._detect_server_vendor(attributes)

        # Parse LDAP versions
        ldap_versions = []
        for ver_str in supported_ldap_versions:
            if ver_str == "2":
                ldap_versions.append(LDAPVersion.V2)
            elif ver_str == "3":
                ldap_versions.append(LDAPVersion.V3)

        # Build ServerInfo
        return ServerInfo(
            vendor=vendor,
            version=version,
            ldap_version=ldap_versions,
            naming_contexts=naming_contexts,
            default_naming_context=self._extract_single_attribute(
                attributes,
                "defaultNamingContext",
            ),
            schema_naming_context=self._extract_single_attribute(
                attributes,
                "schemaNamingContext",
            ),
            config_naming_context=self._extract_single_attribute(
                attributes,
                "configurationNamingContext",
            ),
            supported_extensions=extensions,
            supported_controls=controls,
            supported_sasl_mechanisms=supported_sasl,
            supports_tls=self._detect_tls_support(attributes),
            server_name=self._extract_single_attribute(attributes, "serverName"),
            domain_name=self._extract_single_attribute(
                attributes,
                "defaultNamingContext",
            ),
            raw_attributes=attributes,
        )

    def _extract_single_attribute(
        self,
        attributes: dict[str, Any],
        attr_name: str,
    ) -> str | None:
        """Extract single-valued attribute."""
        value = attributes.get(attr_name)
        if isinstance(value, list) and value:
            return str(value[0])
        if value:
            return str(value)
        return None

    def _extract_list_attribute(
        self,
        attributes: dict[str, Any],
        attr_name: str,
    ) -> list[str]:
        """Extract multi-valued attribute as list."""
        value = attributes.get(attr_name, [])
        if isinstance(value, list):
            return [str(v) for v in value]
        if value:
            return [str(value)]
        return []

    def _detect_server_vendor(
        self,
        attributes: dict[str, Any],
    ) -> tuple[ServerVendor, str | None]:
        """Detect server vendor and version from attributes."""
        vendor_string = self._extract_single_attribute(attributes, "vendorName") or ""
        version_string = (
            self._extract_single_attribute(attributes, "vendorVersion") or ""
        )

        # Microsoft Active Directory
        if "Microsoft" in vendor_string or "Windows" in vendor_string:
            return ServerVendor.MICROSOFT_AD, version_string

        # OpenLDAP
        if "OpenLDAP" in vendor_string or "openldap" in version_string.lower():
            return ServerVendor.OPENLDAP, version_string

        # IBM Domino
        if "IBM" in vendor_string or "Domino" in vendor_string:
            return ServerVendor.IBM_DOMINO, version_string

        # Novell eDirectory
        if "Novell" in vendor_string or "eDirectory" in vendor_string:
            return ServerVendor.NOVELL_EDIRECTORY, version_string

        # Sun/Oracle Directory Server
        if any(x in vendor_string for x in ["Sun", "Oracle", "iPlanet"]):
            return ServerVendor.SUN_DIRECTORY, version_string

        # Apache Directory Server
        if "Apache" in vendor_string:
            return ServerVendor.APACHE_DIRECTORY, version_string

        return ServerVendor.UNKNOWN, version_string

    def _detect_tls_support(self, attributes: dict[str, Any]) -> bool:
        """Detect TLS/SSL support from Root DSE attributes."""
        # Check for Start TLS extension
        extensions = self._extract_list_attribute(attributes, "supportedExtension")
        return "1.3.6.1.4.1.1466.20037" in extensions


# Convenience functions
async def discover_server_info(connection: Any) -> ServerInfo:
    """Convenience function to discover server information.

    Args:
        connection: LDAP connection

    Returns:
        Server information
    """
    service = RootDSEService(connection)
    return await service.discover_capabilities()


def create_extension_info(
    oid: str,
    name: str | None = None,
    description: str | None = None,
) -> ExtensionInfo:
    """Create extension information object.

    Args:
        oid: Extension OID
        name: Optional extension name
        description: Optional description

    Returns:
        ExtensionInfo object
    """
    return ExtensionInfo(oid=oid, name=name, description=description)


def create_control_info(
    oid: str,
    name: str | None = None,
    description: str | None = None,
) -> ControlInfo:
    """Create control information object.

    Args:
        oid: Control OID
        name: Optional control name
        description: Optional description

    Returns:
        ControlInfo object
    """
    return ControlInfo(oid=oid, name=name, description=description)


# TODO: Integration points for implementation:
#
# 1. Connection Manager Integration:
#    - Implement Root DSE search (base DN = "", scope = base)
#    - Handle anonymous access for Root DSE discovery
#    - Support both authenticated and unauthenticated Root DSE queries
#
# 2. Caching and Performance:
#    - Implement intelligent caching of Root DSE information
#    - Cache invalidation strategies based on connection lifecycle
#    - Background refresh for long-running connections
#
# 3. Extended Server Detection:
#    - Enhanced vendor detection algorithms
#    - Version parsing and comparison utilities
#    - Feature matrix generation based on server type and version
#
# 4. Schema Integration:
#    - Automatic schema discovery from Root DSE
#    - Schema validation using discovered capabilities
#    - Dynamic schema loading based on server features
#
# 5. Security and Authentication:
#    - SASL mechanism negotiation based on server capabilities
#    - TLS requirement detection and enforcement
#    - Password policy detection and integration
#
# 6. Monitoring and Diagnostics:
#    - Server capability change detection
#    - Performance monitoring of Root DSE queries
#    - Alerting for unsupported feature usage attempts
#
# 7. Testing Requirements:
#    - Unit tests for all server vendor detection scenarios
#    - Integration tests with different LDAP server implementations
#    - Performance tests for Root DSE discovery operations
#    - Edge case tests for malformed or incomplete Root DSE entries
