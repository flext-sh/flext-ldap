"""LDAP Capability Detection Service Implementation.

This module provides comprehensive LDAP server capability detection functionality
following perl-ldap patterns with enterprise-grade feature detection and
compatibility checking.

The CapabilityDetection service enables intelligent client behavior by discovering
and analyzing server capabilities, supported features, and operational constraints.

Architecture:
    - CapabilityDetection: Main service for capability analysis
    - FeatureMatrix: Comprehensive feature compatibility matrix
    - ServerCapabilities: Structured server capability representation
    - CompatibilityCheck: Feature compatibility validation

Usage Example:
    >>> from ldap_core_shared.services.capabilities import CapabilityDetection
    >>>
    >>> # Detect server capabilities
    >>> detector = CapabilityDetection(connection)
    >>> capabilities = await detector.detect_capabilities()
    >>> print(f"Server supports paging: {capabilities.supports_paging}")
    >>> print(f"Max page size: {capabilities.max_page_size}")
    >>>
    >>> # Check feature compatibility
    >>> if detector.is_feature_supported("password_policy"):
    ...     print("Password policy is available")

References:
    - perl-ldap: Feature detection patterns in Net::LDAP
    - RFC 4512: LDAP Directory Information Models
    - RFC 4511: LDAP Protocol Operations
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class FeatureCategory(Enum):
    """Categories of LDAP features."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CONTROLS = "controls"
    EXTENSIONS = "extensions"
    PAGING = "paging"
    PASSWORD_POLICY = "password_policy"  # noqa: S105
    SCHEMA = "schema"
    SECURITY = "security"
    SORTING = "sorting"
    SYNC = "sync"
    TRANSACTIONS = "transactions"


class FeatureSupport(Enum):
    """Levels of feature support."""

    FULL = "full"
    PARTIAL = "partial"
    LIMITED = "limited"
    NONE = "none"
    UNKNOWN = "unknown"


class ServerType(Enum):
    """Known LDAP server types."""

    ACTIVE_DIRECTORY = "active_directory"
    OPENLDAP = "openldap"
    IBM_DOMINO = "ibm_domino"
    NOVELL_EDIRECTORY = "novell_edirectory"
    SUN_DIRECTORY = "sun_directory"
    ORACLE_DIRECTORY = "oracle_directory"
    APACHE_DIRECTORY = "apache_directory"
    UNKNOWN = "unknown"


class FeatureInfo(BaseModel):
    """Information about a specific feature."""

    name: str = Field(description="Feature name")

    category: FeatureCategory = Field(description="Feature category")

    support_level: FeatureSupport = Field(description="Level of support")

    version_required: Optional[str] = Field(
        default=None, description="Minimum server version required"
    )

    dependencies: list[str] = Field(
        default_factory=list, description="Required dependencies"
    )

    limitations: list[str] = Field(
        default_factory=list, description="Known limitations"
    )

    configuration_required: bool = Field(
        default=False, description="Whether feature requires configuration"
    )

    description: Optional[str] = Field(default=None, description="Feature description")

    is_experimental: bool = Field(
        default=False, description="Whether feature is experimental"
    )

    def is_supported(self) -> bool:
        """Check if feature is supported (any level except NONE)."""
        return self.support_level != FeatureSupport.NONE

    def is_fully_supported(self) -> bool:
        """Check if feature is fully supported."""
        return self.support_level == FeatureSupport.FULL


class ServerCapabilities(BaseModel):
    """Comprehensive server capability information."""

    # Server identification
    server_type: ServerType = Field(description="Detected server type")

    server_version: Optional[str] = Field(
        default=None, description="Server version string"
    )

    vendor_name: Optional[str] = Field(default=None, description="Vendor name")

    # Core protocol capabilities
    supported_ldap_versions: list[str] = Field(
        default_factory=list, description="Supported LDAP protocol versions"
    )

    max_connections: Optional[int] = Field(
        default=None, description="Maximum concurrent connections"
    )

    max_search_results: Optional[int] = Field(
        default=None, description="Maximum search results"
    )

    max_page_size: Optional[int] = Field(
        default=None, description="Maximum page size for paged results"
    )

    # Feature support matrix
    features: dict[str, FeatureInfo] = Field(
        default_factory=dict, description="Detected features by name"
    )

    # Authentication capabilities
    supported_sasl_mechanisms: list[str] = Field(
        default_factory=list, description="Supported SASL mechanisms"
    )

    supports_simple_auth: bool = Field(
        default=True, description="Supports simple bind authentication"
    )

    supports_anonymous_auth: bool = Field(
        default=False, description="Supports anonymous authentication"
    )

    requires_ssl_for_auth: bool = Field(
        default=False, description="Requires SSL/TLS for authentication"
    )

    # Security capabilities
    supports_ssl: bool = Field(default=False, description="Supports SSL/TLS")

    supports_start_tls: bool = Field(
        default=False, description="Supports StartTLS extension"
    )

    supports_password_policy: bool = Field(
        default=False, description="Supports password policy"
    )

    # Search and paging capabilities
    supports_paging: bool = Field(
        default=False, description="Supports paged results control"
    )

    supports_sorting: bool = Field(
        default=False, description="Supports server-side sorting"
    )

    supports_vlv: bool = Field(default=False, description="Supports Virtual List View")

    # Schema and metadata capabilities
    supports_schema_discovery: bool = Field(
        default=False, description="Supports schema discovery"
    )

    supports_root_dse: bool = Field(
        default=True, description="Supports Root DSE queries"
    )

    # Operational capabilities
    supports_persistent_search: bool = Field(
        default=False, description="Supports persistent search"
    )

    supports_sync_repl: bool = Field(
        default=False, description="Supports sync replication"
    )

    supports_transactions: bool = Field(
        default=False, description="Supports transaction controls"
    )

    # Detection metadata
    detected_at: datetime = Field(
        default_factory=datetime.now, description="When capabilities were detected"
    )

    detection_confidence: float = Field(
        default=1.0, description="Confidence level of detection (0.0-1.0)"
    )

    def get_feature(self, name: str) -> Optional[FeatureInfo]:
        """Get feature information by name."""
        return self.features.get(name)

    def is_feature_supported(self, name: str) -> bool:
        """Check if feature is supported."""
        feature = self.get_feature(name)
        return feature.is_supported() if feature else False

    def is_feature_fully_supported(self, name: str) -> bool:
        """Check if feature is fully supported."""
        feature = self.get_feature(name)
        return feature.is_fully_supported() if feature else False

    def get_features_by_category(self, category: FeatureCategory) -> list[FeatureInfo]:
        """Get all features in a category."""
        return [f for f in self.features.values() if f.category == category]

    def get_supported_features(self) -> list[FeatureInfo]:
        """Get all supported features."""
        return [f for f in self.features.values() if f.is_supported()]

    def get_unsupported_features(self) -> list[FeatureInfo]:
        """Get all unsupported features."""
        return [f for f in self.features.values() if not f.is_supported()]

    def get_capability_summary(self) -> dict[str, Any]:
        """Get summary of server capabilities."""
        supported_count = len(self.get_supported_features())
        total_count = len(self.features)

        return {
            "server_type": self.server_type.value,
            "server_version": self.server_version,
            "ldap_versions": self.supported_ldap_versions,
            "features_supported": supported_count,
            "features_total": total_count,
            "support_percentage": (supported_count / total_count * 100)
            if total_count > 0
            else 0,
            "authentication_methods": len(self.supported_sasl_mechanisms)
            + (1 if self.supports_simple_auth else 0),
            "security_level": self._calculate_security_level(),
        }

    def _calculate_security_level(self) -> str:
        """Calculate overall security level."""
        score = 0

        if self.supports_ssl:
            score += 3
        if self.supports_start_tls:
            score += 2
        if self.supports_password_policy:
            score += 2
        if self.requires_ssl_for_auth:
            score += 2
        if len(self.supported_sasl_mechanisms) > 0:
            score += 1

        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        if score >= 2:
            return "low"
        return "minimal"


class CompatibilityResult(BaseModel):
    """Result of compatibility checking."""

    is_compatible: bool = Field(description="Whether operation is compatible")

    required_features: list[str] = Field(
        default_factory=list, description="Features required for operation"
    )

    missing_features: list[str] = Field(
        default_factory=list, description="Missing required features"
    )

    warnings: list[str] = Field(
        default_factory=list, description="Compatibility warnings"
    )

    recommendations: list[str] = Field(
        default_factory=list, description="Compatibility recommendations"
    )

    def add_warning(self, message: str) -> None:
        """Add compatibility warning."""
        self.warnings.append(message)

    def add_recommendation(self, message: str) -> None:
        """Add compatibility recommendation."""
        self.recommendations.append(message)


class FeatureMatrix:
    """Feature compatibility matrix for different server types."""

    # Matrix of features by server type
    FEATURE_MATRIX = {
        ServerType.ACTIVE_DIRECTORY: {
            "paging": FeatureSupport.FULL,
            "sorting": FeatureSupport.FULL,
            "password_policy": FeatureSupport.FULL,
            "ssl_tls": FeatureSupport.FULL,
            "sasl_gssapi": FeatureSupport.FULL,
            "sasl_ntlm": FeatureSupport.FULL,
            "persistent_search": FeatureSupport.NONE,
            "sync_repl": FeatureSupport.PARTIAL,
            "vlv": FeatureSupport.LIMITED,
            "transactions": FeatureSupport.NONE,
        },
        ServerType.OPENLDAP: {
            "paging": FeatureSupport.FULL,
            "sorting": FeatureSupport.FULL,
            "password_policy": FeatureSupport.FULL,
            "ssl_tls": FeatureSupport.FULL,
            "sasl_gssapi": FeatureSupport.FULL,
            "sasl_digest_md5": FeatureSupport.FULL,
            "persistent_search": FeatureSupport.FULL,
            "sync_repl": FeatureSupport.FULL,
            "vlv": FeatureSupport.FULL,
            "transactions": FeatureSupport.PARTIAL,
        },
        ServerType.IBM_DOMINO: {
            "paging": FeatureSupport.PARTIAL,
            "sorting": FeatureSupport.LIMITED,
            "password_policy": FeatureSupport.LIMITED,
            "ssl_tls": FeatureSupport.FULL,
            "sasl_gssapi": FeatureSupport.LIMITED,
            "persistent_search": FeatureSupport.NONE,
            "sync_repl": FeatureSupport.NONE,
            "vlv": FeatureSupport.NONE,
            "transactions": FeatureSupport.NONE,
        },
        ServerType.ORACLE_DIRECTORY: {
            "paging": FeatureSupport.FULL,
            "sorting": FeatureSupport.FULL,
            "password_policy": FeatureSupport.FULL,
            "ssl_tls": FeatureSupport.FULL,
            "sasl_gssapi": FeatureSupport.FULL,
            "persistent_search": FeatureSupport.PARTIAL,
            "sync_repl": FeatureSupport.LIMITED,
            "vlv": FeatureSupport.FULL,
            "transactions": FeatureSupport.PARTIAL,
        },
    }

    @classmethod
    def get_feature_support(
        cls, server_type: ServerType, feature: str
    ) -> FeatureSupport:
        """Get feature support level for server type."""
        server_features = cls.FEATURE_MATRIX.get(server_type, {})
        return server_features.get(feature, FeatureSupport.UNKNOWN)

    @classmethod
    def is_feature_supported(cls, server_type: ServerType, feature: str) -> bool:
        """Check if feature is supported by server type."""
        support = cls.get_feature_support(server_type, feature)
        return support != FeatureSupport.NONE

    @classmethod
    def get_supported_features(cls, server_type: ServerType) -> list[str]:
        """Get all supported features for server type."""
        server_features = cls.FEATURE_MATRIX.get(server_type, {})
        return [
            feature
            for feature, support in server_features.items()
            if support != FeatureSupport.NONE
        ]


class CapabilityDetection:
    """Service for LDAP server capability detection and analysis.

    This service provides comprehensive capability detection for LDAP servers,
    enabling intelligent client behavior based on discovered features.

    Example:
        >>> detector = CapabilityDetection(connection)
        >>> capabilities = await detector.detect_capabilities()
        >>> print(f"Server type: {capabilities.server_type}")
        >>>
        >>> # Check specific capability
        >>> if capabilities.supports_paging:
        ...     print(f"Max page size: {capabilities.max_page_size}")
    """

    def __init__(self, connection: Any) -> None:
        """Initialize capability detection service.

        Args:
            connection: Active LDAP connection
        """
        self._connection = connection
        self._cached_capabilities: Optional[ServerCapabilities] = None

    async def detect_capabilities(
        self, force_refresh: bool = False
    ) -> ServerCapabilities:
        """Detect comprehensive server capabilities.

        Args:
            force_refresh: Force refresh of cached capabilities

        Returns:
            Complete server capabilities

        Raises:
            NotImplementedError: Capability detection not yet implemented
        """
        if self._cached_capabilities and not force_refresh:
            return self._cached_capabilities

        # TODO: Implement actual capability detection
        # This is a stub implementation
        msg = (
            "Capability detection requires Root DSE and extension integration. "
            "Implement server capability analysis and feature matrix population."
        )
        raise NotImplementedError(msg)

    def is_feature_supported(self, feature: str) -> bool:
        """Check if specific feature is supported.

        Args:
            feature: Feature name to check

        Returns:
            True if feature is supported
        """
        if not self._cached_capabilities:
            return False

        return self._cached_capabilities.is_feature_supported(feature)

    def check_compatibility(self, required_features: list[str]) -> CompatibilityResult:
        """Check compatibility for required features.

        Args:
            required_features: List of required feature names

        Returns:
            Compatibility check result
        """
        result = CompatibilityResult(required_features=required_features)

        if not self._cached_capabilities:
            result.is_compatible = False
            result.missing_features = required_features
            result.add_warning("Server capabilities not detected")
            return result

        # Check each required feature
        for feature in required_features:
            if not self._cached_capabilities.is_feature_supported(feature):
                result.missing_features.append(feature)

        # Determine overall compatibility
        result.is_compatible = len(result.missing_features) == 0

        # Add recommendations based on missing features
        if result.missing_features:
            result.add_recommendation(
                f"Consider alternative approaches for: {', '.join(result.missing_features)}"
            )

        return result

    def get_server_info(self) -> dict[str, Any]:
        """Get basic server information.

        Returns:
            Server information dictionary
        """
        if not self._cached_capabilities:
            return {"error": "Capabilities not detected"}

        return {
            "server_type": self._cached_capabilities.server_type.value,
            "server_version": self._cached_capabilities.server_version,
            "vendor_name": self._cached_capabilities.vendor_name,
            "ldap_versions": self._cached_capabilities.supported_ldap_versions,
        }

    def get_authentication_info(self) -> dict[str, Any]:
        """Get authentication capability information.

        Returns:
            Authentication information dictionary
        """
        if not self._cached_capabilities:
            return {"error": "Capabilities not detected"}

        return {
            "sasl_mechanisms": self._cached_capabilities.supported_sasl_mechanisms,
            "simple_auth": self._cached_capabilities.supports_simple_auth,
            "anonymous_auth": self._cached_capabilities.supports_anonymous_auth,
            "ssl_required": self._cached_capabilities.requires_ssl_for_auth,
            "ssl_support": self._cached_capabilities.supports_ssl,
            "start_tls": self._cached_capabilities.supports_start_tls,
        }

    def get_search_capabilities(self) -> dict[str, Any]:
        """Get search and paging capability information.

        Returns:
            Search capabilities dictionary
        """
        if not self._cached_capabilities:
            return {"error": "Capabilities not detected"}

        return {
            "paging": self._cached_capabilities.supports_paging,
            "max_page_size": self._cached_capabilities.max_page_size,
            "sorting": self._cached_capabilities.supports_sorting,
            "vlv": self._cached_capabilities.supports_vlv,
            "max_results": self._cached_capabilities.max_search_results,
        }

    def _detect_server_type(self, root_dse_info: dict[str, Any]) -> ServerType:
        """Detect server type from Root DSE information."""
        vendor = root_dse_info.get("vendorName", "").lower()
        version = root_dse_info.get("vendorVersion", "").lower()

        if "microsoft" in vendor or "windows" in vendor:
            return ServerType.ACTIVE_DIRECTORY
        if "openldap" in vendor or "openldap" in version:
            return ServerType.OPENLDAP
        if "ibm" in vendor or "domino" in vendor:
            return ServerType.IBM_DOMINO
        if "novell" in vendor or "edirectory" in vendor:
            return ServerType.NOVELL_EDIRECTORY
        if "sun" in vendor or "oracle" in vendor:
            return ServerType.ORACLE_DIRECTORY
        if "apache" in vendor:
            return ServerType.APACHE_DIRECTORY

        return ServerType.UNKNOWN

    def _detect_authentication_capabilities(
        self, root_dse_info: dict[str, Any]
    ) -> dict[str, Any]:
        """Detect authentication capabilities."""
        sasl_mechanisms = root_dse_info.get("supportedSASLMechanisms", [])
        extensions = root_dse_info.get("supportedExtension", [])

        return {
            "sasl_mechanisms": sasl_mechanisms,
            "simple_auth": True,  # Generally always supported
            "anonymous_auth": self._supports_anonymous_auth(root_dse_info),
            "start_tls": "1.3.6.1.4.1.1466.20037" in extensions,
        }

    def _detect_search_capabilities(
        self, root_dse_info: dict[str, Any]
    ) -> dict[str, Any]:
        """Detect search and paging capabilities."""
        controls = root_dse_info.get("supportedControl", [])

        return {
            "paging": "1.2.840.113556.1.4.319" in controls,
            "sorting": "1.2.840.113556.1.4.473" in controls,
            "vlv": "2.16.840.1.113730.3.4.9" in controls,
            "persistent_search": "2.16.840.1.113730.3.4.3" in controls,
        }

    def _supports_anonymous_auth(self, root_dse_info: dict[str, Any]) -> bool:
        """Check if server supports anonymous authentication."""
        # This is a heuristic - different servers handle this differently
        features = root_dse_info.get("supportedFeatures", [])
        return "1.3.6.1.4.1.4203.1.5.1" in features  # All Op Attrs feature

    def _calculate_detection_confidence(
        self, capabilities: ServerCapabilities
    ) -> float:
        """Calculate confidence level of detection."""
        confidence = 1.0

        # Reduce confidence for unknown server types
        if capabilities.server_type == ServerType.UNKNOWN:
            confidence -= 0.3

        # Reduce confidence if no version information
        if not capabilities.server_version:
            confidence -= 0.1

        # Reduce confidence if limited feature detection
        if len(capabilities.features) < 5:
            confidence -= 0.2

        return max(0.0, confidence)


# Convenience functions
async def detect_server_capabilities(connection: Any) -> ServerCapabilities:
    """Detect server capabilities.

    Args:
        connection: LDAP connection

    Returns:
        Server capabilities
    """
    detector = CapabilityDetection(connection)
    return await detector.detect_capabilities()


def check_feature_compatibility(
    capabilities: ServerCapabilities, required_features: list[str]
) -> CompatibilityResult:
    """Check feature compatibility.

    Args:
        capabilities: Server capabilities
        required_features: Required features

    Returns:
        Compatibility result
    """
    # Create temporary detector with pre-loaded capabilities
    detector = CapabilityDetection(None)
    detector._cached_capabilities = capabilities
    return detector.check_compatibility(required_features)


def get_feature_matrix_info(server_type: ServerType) -> dict[str, str]:
    """Get feature matrix information for server type.

    Args:
        server_type: Server type

    Returns:
        Feature support matrix
    """
    features = FeatureMatrix.FEATURE_MATRIX.get(server_type, {})
    return {feature: support.value for feature, support in features.items()}


# TODO: Integration points for implementation:
#
# 1. Root DSE Integration:
#    - Integrate with RootDSEService for server information
#    - Parse supported extensions and controls
#    - Extract vendor-specific capability information
#
# 2. Feature Detection Engine:
#    - Implement comprehensive feature detection algorithms
#    - Test feature availability through actual operations
#    - Handle edge cases and server-specific behaviors
#
# 3. Capability Testing:
#    - Safe feature testing without disrupting operations
#    - Capability validation through controlled operations
#    - Performance characteristic detection
#
# 4. Server-Specific Logic:
#    - Vendor-specific capability detection
#    - Version-specific feature availability
#    - Workarounds for known server limitations
#
# 5. Caching and Performance:
#    - Intelligent capability caching
#    - Background capability refresh
#    - Change detection for server updates
#
# 6. Integration Features:
#    - Schema integration for capability-aware validation
#    - Filter optimization based on server capabilities
#    - Operation planning using capability information
#
# 7. Testing Requirements:
#    - Unit tests for all server type detection scenarios
#    - Integration tests with different LDAP server versions
#    - Performance tests for capability detection operations
#    - Edge case tests for unknown or misconfigured servers
