"""Tests for LDAP Capability Detection Service Implementation.

This module provides comprehensive test coverage for the LDAP capability detection
service including server feature analysis, compatibility checking, and intelligent
client behavior enablement with enterprise-grade validation.

Test Coverage:
    - FeatureCategory: Feature categorization enumeration
    - FeatureSupport: Support level enumeration
    - ServerType: Server type identification enumeration
    - FeatureInfo: Individual feature information modeling
    - ServerCapabilities: Comprehensive server capability aggregation
    - CompatibilityResult: Feature compatibility validation results
    - FeatureMatrix: Server-specific feature compatibility matrix
    - CapabilityDetection: Main capability detection service

Integration Testing:
    - Server capability discovery and analysis workflows
    - Multi-vendor feature matrix validation
    - Authentication capability detection and validation
    - Search and paging capability assessment
    - Security level calculation and enforcement
    - Feature compatibility checking and recommendations

Performance Testing:
    - Capability detection optimization and caching
    - Large-scale feature matrix processing
    - Server type detection algorithm efficiency
    - Feature lookup and validation performance
    - Compatibility checking scalability

Security Testing:
    - Authentication capability validation and security
    - SSL/TLS requirement detection and enforcement
    - Password policy capability assessment
    - SASL mechanism security validation
    - Feature-based security level calculation
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from ldap_core_shared.services.capabilities import (
    CapabilityDetection,
    CompatibilityResult,
    FeatureCategory,
    FeatureInfo,
    FeatureMatrix,
    FeatureSupport,
    ServerCapabilities,
    ServerType,
    check_feature_compatibility,
    detect_server_capabilities,
    get_feature_matrix_info,
)


class TestFeatureCategory:
    """Test cases for FeatureCategory enumeration."""

    def test_feature_category_values(self) -> None:
        """Test feature category enumeration values."""
        assert FeatureCategory.AUTHENTICATION.value == "authentication"
        assert FeatureCategory.AUTHORIZATION.value == "authorization"
        assert FeatureCategory.CONTROLS.value == "controls"
        assert FeatureCategory.EXTENSIONS.value == "extensions"
        assert FeatureCategory.PAGING.value == "paging"
        assert FeatureCategory.PASSWORD_POLICY.value == "password_policy"
        assert FeatureCategory.SCHEMA.value == "schema"
        assert FeatureCategory.SECURITY.value == "security"
        assert FeatureCategory.SORTING.value == "sorting"
        assert FeatureCategory.SYNC.value == "sync"
        assert FeatureCategory.TRANSACTIONS.value == "transactions"

    def test_feature_category_completeness(self) -> None:
        """Test that all expected feature categories are defined."""
        expected_categories = {
            "AUTHENTICATION",
            "AUTHORIZATION",
            "CONTROLS",
            "EXTENSIONS",
            "PAGING",
            "PASSWORD_POLICY",
            "SCHEMA",
            "SECURITY",
            "SORTING",
            "SYNC",
            "TRANSACTIONS",
        }
        actual_categories = {member.name for member in FeatureCategory}
        assert actual_categories == expected_categories


class TestFeatureSupport:
    """Test cases for FeatureSupport enumeration."""

    def test_feature_support_values(self) -> None:
        """Test feature support enumeration values."""
        assert FeatureSupport.FULL.value == "full"
        assert FeatureSupport.PARTIAL.value == "partial"
        assert FeatureSupport.LIMITED.value == "limited"
        assert FeatureSupport.NONE.value == "none"
        assert FeatureSupport.UNKNOWN.value == "unknown"

    def test_feature_support_completeness(self) -> None:
        """Test that all expected support levels are defined."""
        expected_levels = {"FULL", "PARTIAL", "LIMITED", "NONE", "UNKNOWN"}
        actual_levels = {member.name for member in FeatureSupport}
        assert actual_levels == expected_levels


class TestServerType:
    """Test cases for ServerType enumeration."""

    def test_server_type_values(self) -> None:
        """Test server type enumeration values."""
        assert ServerType.ACTIVE_DIRECTORY.value == "active_directory"
        assert ServerType.OPENLDAP.value == "openldap"
        assert ServerType.IBM_DOMINO.value == "ibm_domino"
        assert ServerType.NOVELL_EDIRECTORY.value == "novell_edirectory"
        assert ServerType.SUN_DIRECTORY.value == "sun_directory"
        assert ServerType.ORACLE_DIRECTORY.value == "oracle_directory"
        assert ServerType.APACHE_DIRECTORY.value == "apache_directory"
        assert ServerType.UNKNOWN.value == "unknown"

    def test_server_type_completeness(self) -> None:
        """Test that all expected server types are defined."""
        expected_types = {
            "ACTIVE_DIRECTORY",
            "OPENLDAP",
            "IBM_DOMINO",
            "NOVELL_EDIRECTORY",
            "SUN_DIRECTORY",
            "ORACLE_DIRECTORY",
            "APACHE_DIRECTORY",
            "UNKNOWN",
        }
        actual_types = {member.name for member in ServerType}
        assert actual_types == expected_types


class TestFeatureInfo:
    """Test cases for FeatureInfo."""

    def test_feature_info_creation_minimal(self) -> None:
        """Test creating feature info with minimal required fields."""
        feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        assert feature.name == "paging"
        assert feature.category == FeatureCategory.PAGING
        assert feature.support_level == FeatureSupport.FULL
        assert feature.version_required is None
        assert feature.dependencies == []
        assert feature.limitations == []
        assert feature.configuration_required is False
        assert feature.description is None
        assert feature.is_experimental is False

    def test_feature_info_creation_complete(self) -> None:
        """Test creating feature info with all fields."""
        feature = FeatureInfo(
            name="password_policy",
            category=FeatureCategory.PASSWORD_POLICY,
            support_level=FeatureSupport.PARTIAL,
            version_required="2.5.0",
            dependencies=["ssl_tls", "sasl_auth"],
            limitations=["Limited to simple policies", "No custom rules"],
            configuration_required=True,
            description="Password policy enforcement",
            is_experimental=True,
        )

        assert feature.name == "password_policy"
        assert feature.category == FeatureCategory.PASSWORD_POLICY
        assert feature.support_level == FeatureSupport.PARTIAL
        assert feature.version_required == "2.5.0"
        assert feature.dependencies == ["ssl_tls", "sasl_auth"]
        assert feature.limitations == ["Limited to simple policies", "No custom rules"]
        assert feature.configuration_required is True
        assert feature.description == "Password policy enforcement"
        assert feature.is_experimental is True

    def test_is_supported_true(self) -> None:
        """Test is_supported returns True for supported features."""
        supported_levels = [
            FeatureSupport.FULL,
            FeatureSupport.PARTIAL,
            FeatureSupport.LIMITED,
            FeatureSupport.UNKNOWN,
        ]

        for level in supported_levels:
            feature = FeatureInfo(
                name="test",
                category=FeatureCategory.CONTROLS,
                support_level=level,
            )
            assert feature.is_supported() is True

    def test_is_supported_false(self) -> None:
        """Test is_supported returns False for unsupported features."""
        feature = FeatureInfo(
            name="test",
            category=FeatureCategory.CONTROLS,
            support_level=FeatureSupport.NONE,
        )
        assert feature.is_supported() is False

    def test_is_fully_supported_true(self) -> None:
        """Test is_fully_supported returns True for fully supported features."""
        feature = FeatureInfo(
            name="test",
            category=FeatureCategory.CONTROLS,
            support_level=FeatureSupport.FULL,
        )
        assert feature.is_fully_supported() is True

    def test_is_fully_supported_false(self) -> None:
        """Test is_fully_supported returns False for non-fully supported features."""
        non_full_levels = [
            FeatureSupport.PARTIAL,
            FeatureSupport.LIMITED,
            FeatureSupport.NONE,
            FeatureSupport.UNKNOWN,
        ]

        for level in non_full_levels:
            feature = FeatureInfo(
                name="test",
                category=FeatureCategory.CONTROLS,
                support_level=level,
            )
            assert feature.is_fully_supported() is False


class TestServerCapabilities:
    """Test cases for ServerCapabilities."""

    def test_server_capabilities_creation_minimal(self) -> None:
        """Test creating server capabilities with minimal configuration."""
        capabilities = ServerCapabilities(server_type=ServerType.OPENLDAP)

        assert capabilities.server_type == ServerType.OPENLDAP
        assert capabilities.server_version is None
        assert capabilities.vendor_name is None
        assert capabilities.supported_ldap_versions == []
        assert capabilities.max_connections is None
        assert capabilities.max_search_results is None
        assert capabilities.max_page_size is None
        assert capabilities.features == {}
        assert capabilities.supported_sasl_mechanisms == []
        assert capabilities.supports_simple_auth is True
        assert capabilities.supports_anonymous_auth is False
        assert capabilities.requires_ssl_for_auth is False
        assert capabilities.supports_ssl is False
        assert capabilities.supports_start_tls is False
        assert capabilities.supports_password_policy is False
        assert capabilities.supports_paging is False
        assert capabilities.supports_sorting is False
        assert capabilities.supports_vlv is False
        assert capabilities.supports_schema_discovery is False
        assert capabilities.supports_root_dse is True
        assert capabilities.supports_persistent_search is False
        assert capabilities.supports_sync_repl is False
        assert capabilities.supports_transactions is False
        assert isinstance(capabilities.detected_at, datetime)
        assert capabilities.detection_confidence == 1.0

    def test_server_capabilities_creation_complete(self) -> None:
        """Test creating server capabilities with complete configuration."""
        detection_time = datetime.now(UTC)

        features = {
            "paging": FeatureInfo(
                name="paging",
                category=FeatureCategory.PAGING,
                support_level=FeatureSupport.FULL,
            ),
            "sorting": FeatureInfo(
                name="sorting",
                category=FeatureCategory.SORTING,
                support_level=FeatureSupport.PARTIAL,
            ),
        }

        capabilities = ServerCapabilities(
            server_type=ServerType.ACTIVE_DIRECTORY,
            server_version="Windows Server 2019",
            vendor_name="Microsoft Corporation",
            supported_ldap_versions=["2", "3"],
            max_connections=1000,
            max_search_results=5000,
            max_page_size=1000,
            features=features,
            supported_sasl_mechanisms=["GSSAPI", "NTLM", "PLAIN"],
            supports_simple_auth=True,
            supports_anonymous_auth=False,
            requires_ssl_for_auth=True,
            supports_ssl=True,
            supports_start_tls=True,
            supports_password_policy=True,
            supports_paging=True,
            supports_sorting=True,
            supports_vlv=True,
            supports_schema_discovery=True,
            supports_root_dse=True,
            supports_persistent_search=False,
            supports_sync_repl=True,
            supports_transactions=False,
            detected_at=detection_time,
            detection_confidence=0.95,
        )

        assert capabilities.server_type == ServerType.ACTIVE_DIRECTORY
        assert capabilities.server_version == "Windows Server 2019"
        assert capabilities.vendor_name == "Microsoft Corporation"
        assert capabilities.supported_ldap_versions == ["2", "3"]
        assert capabilities.max_connections == 1000
        assert capabilities.max_search_results == 5000
        assert capabilities.max_page_size == 1000
        assert len(capabilities.features) == 2
        assert capabilities.supported_sasl_mechanisms == ["GSSAPI", "NTLM", "PLAIN"]
        assert capabilities.supports_ssl is True
        assert capabilities.supports_paging is True
        assert capabilities.detected_at == detection_time
        assert capabilities.detection_confidence == 0.95

    def test_get_feature_found(self) -> None:
        """Test get_feature returns feature when found."""
        feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={"paging": feature},
        )

        result = capabilities.get_feature("paging")
        assert result is feature

    def test_get_feature_not_found(self) -> None:
        """Test get_feature returns None when not found."""
        capabilities = ServerCapabilities(server_type=ServerType.OPENLDAP)

        result = capabilities.get_feature("nonexistent")
        assert result is None

    def test_is_feature_supported_true(self) -> None:
        """Test is_feature_supported returns True for supported feature."""
        feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={"paging": feature},
        )

        assert capabilities.is_feature_supported("paging") is True

    def test_is_feature_supported_false(self) -> None:
        """Test is_feature_supported returns False for unsupported feature."""
        feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.NONE,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={"paging": feature},
        )

        assert capabilities.is_feature_supported("paging") is False

    def test_is_feature_supported_missing(self) -> None:
        """Test is_feature_supported returns False for missing feature."""
        capabilities = ServerCapabilities(server_type=ServerType.OPENLDAP)

        assert capabilities.is_feature_supported("nonexistent") is False

    def test_is_feature_fully_supported_true(self) -> None:
        """Test is_feature_fully_supported returns True for fully supported feature."""
        feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={"paging": feature},
        )

        assert capabilities.is_feature_fully_supported("paging") is True

    def test_is_feature_fully_supported_false(self) -> None:
        """Test is_feature_fully_supported returns False for partially supported feature."""
        feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.PARTIAL,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={"paging": feature},
        )

        assert capabilities.is_feature_fully_supported("paging") is False

    def test_get_features_by_category(self) -> None:
        """Test get_features_by_category returns features in category."""
        paging_feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        sorting_feature = FeatureInfo(
            name="sorting",
            category=FeatureCategory.SORTING,
            support_level=FeatureSupport.PARTIAL,
        )

        auth_feature = FeatureInfo(
            name="sasl_gssapi",
            category=FeatureCategory.AUTHENTICATION,
            support_level=FeatureSupport.FULL,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={
                "paging": paging_feature,
                "sorting": sorting_feature,
                "sasl_gssapi": auth_feature,
            },
        )

        # Test paging category
        paging_features = capabilities.get_features_by_category(FeatureCategory.PAGING)
        assert len(paging_features) == 1
        assert paging_features[0] is paging_feature

        # Test authentication category
        auth_features = capabilities.get_features_by_category(
            FeatureCategory.AUTHENTICATION
        )
        assert len(auth_features) == 1
        assert auth_features[0] is auth_feature

        # Test empty category
        security_features = capabilities.get_features_by_category(
            FeatureCategory.SECURITY
        )
        assert len(security_features) == 0

    def test_get_supported_features(self) -> None:
        """Test get_supported_features returns only supported features."""
        supported_feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        unsupported_feature = FeatureInfo(
            name="transactions",
            category=FeatureCategory.TRANSACTIONS,
            support_level=FeatureSupport.NONE,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={
                "paging": supported_feature,
                "transactions": unsupported_feature,
            },
        )

        supported = capabilities.get_supported_features()
        assert len(supported) == 1
        assert supported[0] is supported_feature

    def test_get_unsupported_features(self) -> None:
        """Test get_unsupported_features returns only unsupported features."""
        supported_feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        unsupported_feature = FeatureInfo(
            name="transactions",
            category=FeatureCategory.TRANSACTIONS,
            support_level=FeatureSupport.NONE,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={
                "paging": supported_feature,
                "transactions": unsupported_feature,
            },
        )

        unsupported = capabilities.get_unsupported_features()
        assert len(unsupported) == 1
        assert unsupported[0] is unsupported_feature

    def test_get_capability_summary(self) -> None:
        """Test get_capability_summary returns correct summary."""
        supported_feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        unsupported_feature = FeatureInfo(
            name="transactions",
            category=FeatureCategory.TRANSACTIONS,
            support_level=FeatureSupport.NONE,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            server_version="2.5.13",
            supported_ldap_versions=["2", "3"],
            features={
                "paging": supported_feature,
                "transactions": unsupported_feature,
            },
            supported_sasl_mechanisms=["PLAIN", "EXTERNAL"],
            supports_simple_auth=True,
            supports_ssl=True,
            supports_start_tls=True,
            supports_password_policy=True,
        )

        summary = capabilities.get_capability_summary()

        assert summary["server_type"] == "openldap"
        assert summary["server_version"] == "2.5.13"
        assert summary["ldap_versions"] == ["2", "3"]
        assert summary["features_supported"] == 1
        assert summary["features_total"] == 2
        assert summary["support_percentage"] == 50.0  # 1/2 * 100
        assert summary["authentication_methods"] == 3  # 2 SASL + 1 simple
        assert (
            summary["security_level"] == "high"
        )  # Should be high based on capabilities

    def test_calculate_security_level_high(self) -> None:
        """Test _calculate_security_level returns high for secure server."""
        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            supports_ssl=True,  # +3
            supports_start_tls=True,  # +2
            supports_password_policy=True,  # +2
            requires_ssl_for_auth=True,  # +2
            supported_sasl_mechanisms=["GSSAPI", "PLAIN"],  # +1
        )
        # Total: 10, should be "high"

        assert capabilities._calculate_security_level() == "high"

    def test_calculate_security_level_medium(self) -> None:
        """Test _calculate_security_level returns medium for moderately secure server."""
        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            supports_ssl=True,  # +3
            supports_start_tls=True,  # +2
            supported_sasl_mechanisms=["PLAIN"],  # +1
        )
        # Total: 6, should be "medium"

        assert capabilities._calculate_security_level() == "medium"

    def test_calculate_security_level_low(self) -> None:
        """Test _calculate_security_level returns low for minimally secure server."""
        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            supports_start_tls=True,  # +2
        )
        # Total: 2, should be "low"

        assert capabilities._calculate_security_level() == "low"

    def test_calculate_security_level_minimal(self) -> None:
        """Test _calculate_security_level returns minimal for insecure server."""
        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            # No security features enabled
        )
        # Total: 0, should be "minimal"

        assert capabilities._calculate_security_level() == "minimal"


class TestCompatibilityResult:
    """Test cases for CompatibilityResult."""

    def test_compatibility_result_creation_default(self) -> None:
        """Test creating compatibility result with default values."""
        result = CompatibilityResult(is_compatible=True)

        assert result.is_compatible is True
        assert result.required_features == []
        assert result.missing_features == []
        assert result.warnings == []
        assert result.recommendations == []

    def test_compatibility_result_creation_complete(self) -> None:
        """Test creating compatibility result with all fields."""
        result = CompatibilityResult(
            is_compatible=False,
            required_features=["paging", "sorting"],
            missing_features=["sorting"],
            warnings=["Feature partially supported"],
            recommendations=["Use alternative approach"],
        )

        assert result.is_compatible is False
        assert result.required_features == ["paging", "sorting"]
        assert result.missing_features == ["sorting"]
        assert result.warnings == ["Feature partially supported"]
        assert result.recommendations == ["Use alternative approach"]

    def test_add_warning(self) -> None:
        """Test add_warning method."""
        result = CompatibilityResult(is_compatible=True)

        result.add_warning("First warning")
        result.add_warning("Second warning")

        assert len(result.warnings) == 2
        assert result.warnings[0] == "First warning"
        assert result.warnings[1] == "Second warning"

    def test_add_recommendation(self) -> None:
        """Test add_recommendation method."""
        result = CompatibilityResult(is_compatible=True)

        result.add_recommendation("First recommendation")
        result.add_recommendation("Second recommendation")

        assert len(result.recommendations) == 2
        assert result.recommendations[0] == "First recommendation"
        assert result.recommendations[1] == "Second recommendation"


class TestFeatureMatrix:
    """Test cases for FeatureMatrix."""

    def test_feature_matrix_completeness(self) -> None:
        """Test that feature matrix has entries for major server types."""
        expected_servers = {
            ServerType.ACTIVE_DIRECTORY,
            ServerType.OPENLDAP,
            ServerType.IBM_DOMINO,
            ServerType.ORACLE_DIRECTORY,
        }

        actual_servers = set(FeatureMatrix.FEATURE_MATRIX.keys())
        assert expected_servers.issubset(actual_servers)

    def test_get_feature_support_known(self) -> None:
        """Test get_feature_support for known feature."""
        support = FeatureMatrix.get_feature_support(
            ServerType.ACTIVE_DIRECTORY,
            "paging",
        )
        assert support == FeatureSupport.FULL

    def test_get_feature_support_unknown_feature(self) -> None:
        """Test get_feature_support for unknown feature."""
        support = FeatureMatrix.get_feature_support(
            ServerType.ACTIVE_DIRECTORY,
            "nonexistent_feature",
        )
        assert support == FeatureSupport.UNKNOWN

    def test_get_feature_support_unknown_server(self) -> None:
        """Test get_feature_support for unknown server type."""
        support = FeatureMatrix.get_feature_support(
            ServerType.UNKNOWN,
            "paging",
        )
        assert support == FeatureSupport.UNKNOWN

    def test_is_feature_supported_true(self) -> None:
        """Test is_feature_supported returns True for supported feature."""
        # OpenLDAP supports paging fully
        assert (
            FeatureMatrix.is_feature_supported(
                ServerType.OPENLDAP,
                "paging",
            )
            is True
        )

        # Active Directory supports sorting
        assert (
            FeatureMatrix.is_feature_supported(
                ServerType.ACTIVE_DIRECTORY,
                "sorting",
            )
            is True
        )

    def test_is_feature_supported_false(self) -> None:
        """Test is_feature_supported returns False for unsupported feature."""
        # Active Directory doesn't support persistent search
        assert (
            FeatureMatrix.is_feature_supported(
                ServerType.ACTIVE_DIRECTORY,
                "persistent_search",
            )
            is False
        )

        # IBM Domino doesn't support transactions
        assert (
            FeatureMatrix.is_feature_supported(
                ServerType.IBM_DOMINO,
                "transactions",
            )
            is False
        )

    def test_get_supported_features(self) -> None:
        """Test get_supported_features returns all supported features."""
        # Test OpenLDAP supported features
        openldap_features = FeatureMatrix.get_supported_features(ServerType.OPENLDAP)

        # OpenLDAP should support most features
        expected_openldap = [
            "paging",
            "sorting",
            "password_policy",
            "ssl_tls",
            "sasl_gssapi",
            "sasl_digest_md5",
            "persistent_search",
            "sync_repl",
            "vlv",
            "transactions",
        ]

        for feature in expected_openldap:
            assert feature in openldap_features

        # Test IBM Domino supported features (more limited)
        domino_features = FeatureMatrix.get_supported_features(ServerType.IBM_DOMINO)

        # Should include paging (partial) but not persistent search
        assert "paging" in domino_features
        assert "persistent_search" not in domino_features

    def test_feature_matrix_consistency(self) -> None:
        """Test feature matrix consistency across server types."""
        # All server types should have entries for common features
        common_features = ["paging", "sorting", "ssl_tls"]

        for server_type in [ServerType.ACTIVE_DIRECTORY, ServerType.OPENLDAP]:
            server_features = FeatureMatrix.FEATURE_MATRIX.get(server_type, {})
            for feature in common_features:
                assert feature in server_features


class TestCapabilityDetection:
    """Test cases for CapabilityDetection."""

    def test_capability_detection_initialization(self) -> None:
        """Test capability detection service initialization."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        assert detector._connection is mock_connection
        assert detector._cached_capabilities is None

    async def test_detect_capabilities_not_implemented(self) -> None:
        """Test detect_capabilities raises NotImplementedError."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        with pytest.raises(
            NotImplementedError, match="Capability detection requires Root DSE"
        ):
            await detector.detect_capabilities()

    async def test_detect_capabilities_uses_cache(self) -> None:
        """Test detect_capabilities uses cached capabilities."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        # Set cached capabilities
        cached_capabilities = ServerCapabilities(server_type=ServerType.OPENLDAP)
        detector._cached_capabilities = cached_capabilities

        result = await detector.detect_capabilities()
        assert result is cached_capabilities

    async def test_detect_capabilities_force_refresh(self) -> None:
        """Test detect_capabilities with force_refresh bypasses cache."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        # Set cached capabilities
        cached_capabilities = ServerCapabilities(server_type=ServerType.OPENLDAP)
        detector._cached_capabilities = cached_capabilities

        with pytest.raises(NotImplementedError):
            await detector.detect_capabilities(force_refresh=True)

    def test_is_feature_supported_with_cache(self) -> None:
        """Test is_feature_supported with cached capabilities."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        # Create capabilities with a supported feature
        feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={"paging": feature},
        )
        detector._cached_capabilities = capabilities

        assert detector.is_feature_supported("paging") is True
        assert detector.is_feature_supported("nonexistent") is False

    def test_is_feature_supported_no_cache(self) -> None:
        """Test is_feature_supported without cached capabilities."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        assert detector.is_feature_supported("paging") is False

    def test_check_compatibility_all_supported(self) -> None:
        """Test check_compatibility when all features are supported."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        # Create capabilities with supported features
        paging_feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        sorting_feature = FeatureInfo(
            name="sorting",
            category=FeatureCategory.SORTING,
            support_level=FeatureSupport.PARTIAL,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={"paging": paging_feature, "sorting": sorting_feature},
        )
        detector._cached_capabilities = capabilities

        result = detector.check_compatibility(["paging", "sorting"])

        assert result.is_compatible is True
        assert result.required_features == ["paging", "sorting"]
        assert result.missing_features == []

    def test_check_compatibility_missing_features(self) -> None:
        """Test check_compatibility when some features are missing."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        # Create capabilities with only paging supported
        paging_feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={"paging": paging_feature},
        )
        detector._cached_capabilities = capabilities

        result = detector.check_compatibility(["paging", "sorting", "transactions"])

        assert result.is_compatible is False
        assert result.required_features == ["paging", "sorting", "transactions"]
        assert result.missing_features == ["sorting", "transactions"]
        assert len(result.recommendations) > 0

    def test_check_compatibility_no_cache(self) -> None:
        """Test check_compatibility without cached capabilities."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        result = detector.check_compatibility(["paging", "sorting"])

        assert result.is_compatible is False
        assert result.required_features == ["paging", "sorting"]
        assert result.missing_features == ["paging", "sorting"]
        assert len(result.warnings) > 0

    def test_get_server_info_with_cache(self) -> None:
        """Test get_server_info with cached capabilities."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            server_version="2.5.13",
            vendor_name="OpenLDAP Foundation",
            supported_ldap_versions=["2", "3"],
        )
        detector._cached_capabilities = capabilities

        info = detector.get_server_info()

        assert info["server_type"] == "openldap"
        assert info["server_version"] == "2.5.13"
        assert info["vendor_name"] == "OpenLDAP Foundation"
        assert info["ldap_versions"] == ["2", "3"]

    def test_get_server_info_no_cache(self) -> None:
        """Test get_server_info without cached capabilities."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        info = detector.get_server_info()
        assert "error" in info

    def test_get_authentication_info_with_cache(self) -> None:
        """Test get_authentication_info with cached capabilities."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            supported_sasl_mechanisms=["PLAIN", "EXTERNAL", "GSSAPI"],
            supports_simple_auth=True,
            supports_anonymous_auth=False,
            requires_ssl_for_auth=True,
            supports_ssl=True,
            supports_start_tls=True,
        )
        detector._cached_capabilities = capabilities

        info = detector.get_authentication_info()

        assert info["sasl_mechanisms"] == ["PLAIN", "EXTERNAL", "GSSAPI"]
        assert info["simple_auth"] is True
        assert info["anonymous_auth"] is False
        assert info["ssl_required"] is True
        assert info["ssl_support"] is True
        assert info["start_tls"] is True

    def test_get_authentication_info_no_cache(self) -> None:
        """Test get_authentication_info without cached capabilities."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        info = detector.get_authentication_info()
        assert "error" in info

    def test_get_search_capabilities_with_cache(self) -> None:
        """Test get_search_capabilities with cached capabilities."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            supports_paging=True,
            max_page_size=1000,
            supports_sorting=True,
            supports_vlv=True,
            max_search_results=5000,
        )
        detector._cached_capabilities = capabilities

        info = detector.get_search_capabilities()

        assert info["paging"] is True
        assert info["max_page_size"] == 1000
        assert info["sorting"] is True
        assert info["vlv"] is True
        assert info["max_results"] == 5000

    def test_get_search_capabilities_no_cache(self) -> None:
        """Test get_search_capabilities without cached capabilities."""
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        info = detector.get_search_capabilities()
        assert "error" in info


class TestCapabilityDetectionParsing:
    """Test cases for capability detection parsing methods."""

    def test_detect_server_type_microsoft(self) -> None:
        """Test _detect_server_type for Microsoft servers."""
        detector = CapabilityDetection(Mock())

        # Test Microsoft in vendor name
        root_dse = {"vendorName": "Microsoft Corporation"}
        assert detector._detect_server_type(root_dse) == ServerType.ACTIVE_DIRECTORY

        # Test Windows in vendor name
        root_dse = {"vendorName": "Windows Server"}
        assert detector._detect_server_type(root_dse) == ServerType.ACTIVE_DIRECTORY

    def test_detect_server_type_openldap(self) -> None:
        """Test _detect_server_type for OpenLDAP."""
        detector = CapabilityDetection(Mock())

        # Test OpenLDAP in vendor name
        root_dse = {"vendorName": "OpenLDAP Foundation"}
        assert detector._detect_server_type(root_dse) == ServerType.OPENLDAP

        # Test openldap in version
        root_dse = {"vendorVersion": "openldap 2.5.13"}
        assert detector._detect_server_type(root_dse) == ServerType.OPENLDAP

    def test_detect_server_type_other_vendors(self) -> None:
        """Test _detect_server_type for other vendors."""
        detector = CapabilityDetection(Mock())

        vendor_tests = [
            ({"vendorName": "IBM Corporation"}, ServerType.IBM_DOMINO),
            ({"vendorName": "Novell, Inc."}, ServerType.NOVELL_EDIRECTORY),
            ({"vendorName": "Sun Microsystems"}, ServerType.ORACLE_DIRECTORY),
            ({"vendorName": "Oracle Corporation"}, ServerType.ORACLE_DIRECTORY),
            ({"vendorName": "Apache Software Foundation"}, ServerType.APACHE_DIRECTORY),
        ]

        for root_dse, expected_type in vendor_tests:
            assert detector._detect_server_type(root_dse) == expected_type

    def test_detect_server_type_unknown(self) -> None:
        """Test _detect_server_type for unknown vendor."""
        detector = CapabilityDetection(Mock())

        root_dse = {"vendorName": "Unknown Vendor"}
        assert detector._detect_server_type(root_dse) == ServerType.UNKNOWN

    def test_detect_authentication_capabilities(self) -> None:
        """Test _detect_authentication_capabilities parsing."""
        detector = CapabilityDetection(Mock())

        root_dse = {
            "supportedSASLMechanisms": ["PLAIN", "EXTERNAL", "GSSAPI"],
            "supportedExtension": ["1.3.6.1.4.1.1466.20037", "other.extension"],
            "supportedFeatures": ["1.3.6.1.4.1.4203.1.5.1"],
        }

        auth_caps = detector._detect_authentication_capabilities(root_dse)

        assert auth_caps["sasl_mechanisms"] == ["PLAIN", "EXTERNAL", "GSSAPI"]
        assert auth_caps["simple_auth"] is True
        assert auth_caps["anonymous_auth"] is True  # Has All Op Attrs feature
        assert auth_caps["start_tls"] is True  # Has Start TLS extension

    def test_detect_search_capabilities(self) -> None:
        """Test _detect_search_capabilities parsing."""
        detector = CapabilityDetection(Mock())

        root_dse = {
            "supportedControl": [
                "1.2.840.113556.1.4.319",  # Paged Results
                "1.2.840.113556.1.4.473",  # Sort
                "2.16.840.1.113730.3.4.9",  # VLV
                "2.16.840.1.113730.3.4.3",  # Persistent Search
            ],
        }

        search_caps = detector._detect_search_capabilities(root_dse)

        assert search_caps["paging"] is True
        assert search_caps["sorting"] is True
        assert search_caps["vlv"] is True
        assert search_caps["persistent_search"] is True

    def test_supports_anonymous_auth(self) -> None:
        """Test _supports_anonymous_auth detection."""
        detector = CapabilityDetection(Mock())

        # With All Op Attrs feature
        root_dse = {"supportedFeatures": ["1.3.6.1.4.1.4203.1.5.1"]}
        assert detector._supports_anonymous_auth(root_dse) is True

        # Without the feature
        root_dse = {"supportedFeatures": ["other.feature"]}
        assert detector._supports_anonymous_auth(root_dse) is False

        # No features
        root_dse = {}
        assert detector._supports_anonymous_auth(root_dse) is False

    def test_calculate_detection_confidence(self) -> None:
        """Test _calculate_detection_confidence calculation."""
        detector = CapabilityDetection(Mock())

        # High confidence scenario
        high_conf_caps = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            server_version="2.5.13",
            features={
                "paging": FeatureInfo(
                    name="paging",
                    category=FeatureCategory.PAGING,
                    support_level=FeatureSupport.FULL,
                ),
                "sorting": FeatureInfo(
                    name="sorting",
                    category=FeatureCategory.SORTING,
                    support_level=FeatureSupport.FULL,
                ),
                "ssl_tls": FeatureInfo(
                    name="ssl_tls",
                    category=FeatureCategory.SECURITY,
                    support_level=FeatureSupport.FULL,
                ),
                "password_policy": FeatureInfo(
                    name="password_policy",
                    category=FeatureCategory.PASSWORD_POLICY,
                    support_level=FeatureSupport.FULL,
                ),
                "transactions": FeatureInfo(
                    name="transactions",
                    category=FeatureCategory.TRANSACTIONS,
                    support_level=FeatureSupport.PARTIAL,
                ),
            },
        )

        confidence = detector._calculate_detection_confidence(high_conf_caps)
        assert confidence == 1.0

        # Low confidence scenario
        low_conf_caps = ServerCapabilities(
            server_type=ServerType.UNKNOWN,  # -0.3
            server_version=None,  # -0.1
            features={},  # <5 features: -0.2
        )

        confidence = detector._calculate_detection_confidence(low_conf_caps)
        assert confidence == 0.4  # 1.0 - 0.3 - 0.1 - 0.2


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    async def test_detect_server_capabilities(self) -> None:
        """Test detect_server_capabilities convenience function."""
        mock_connection = Mock()

        with pytest.raises(NotImplementedError):
            await detect_server_capabilities(mock_connection)

    def test_check_feature_compatibility(self) -> None:
        """Test check_feature_compatibility convenience function."""
        # Create capabilities with some features
        paging_feature = FeatureInfo(
            name="paging",
            category=FeatureCategory.PAGING,
            support_level=FeatureSupport.FULL,
        )

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features={"paging": paging_feature},
        )

        result = check_feature_compatibility(capabilities, ["paging", "sorting"])

        assert result.is_compatible is False
        assert result.required_features == ["paging", "sorting"]
        assert result.missing_features == ["sorting"]

    def test_get_feature_matrix_info(self) -> None:
        """Test get_feature_matrix_info convenience function."""
        # Test Active Directory matrix
        ad_matrix = get_feature_matrix_info(ServerType.ACTIVE_DIRECTORY)

        assert isinstance(ad_matrix, dict)
        assert "paging" in ad_matrix
        assert ad_matrix["paging"] == "full"  # AD supports paging fully

        # Test unknown server type
        unknown_matrix = get_feature_matrix_info(ServerType.UNKNOWN)
        assert unknown_matrix == {}


class TestIntegrationScenarios:
    """Integration test scenarios."""

    def test_complete_capability_detection_workflow(self) -> None:
        """Test complete capability detection workflow."""
        # This tests the workflow without actual connection
        mock_connection = Mock()
        detector = CapabilityDetection(mock_connection)

        # Create comprehensive server capabilities
        features = {
            "paging": FeatureInfo(
                name="paging",
                category=FeatureCategory.PAGING,
                support_level=FeatureSupport.FULL,
            ),
            "sorting": FeatureInfo(
                name="sorting",
                category=FeatureCategory.SORTING,
                support_level=FeatureSupport.FULL,
            ),
            "password_policy": FeatureInfo(
                name="password_policy",
                category=FeatureCategory.PASSWORD_POLICY,
                support_level=FeatureSupport.PARTIAL,
            ),
        }

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            server_version="2.5.13",
            vendor_name="OpenLDAP Foundation",
            supported_ldap_versions=["2", "3"],
            features=features,
            supported_sasl_mechanisms=["PLAIN", "EXTERNAL", "GSSAPI"],
            supports_ssl=True,
            supports_start_tls=True,
            supports_paging=True,
            supports_sorting=True,
        )

        # Set cached capabilities to simulate detection
        detector._cached_capabilities = capabilities

        # Test various queries
        assert detector.is_feature_supported("paging") is True
        assert detector.is_feature_supported("nonexistent") is False

        # Test server info
        server_info = detector.get_server_info()
        assert server_info["server_type"] == "openldap"
        assert server_info["server_version"] == "2.5.13"

        # Test authentication info
        auth_info = detector.get_authentication_info()
        assert len(auth_info["sasl_mechanisms"]) == 3
        assert auth_info["ssl_support"] is True

        # Test search capabilities
        search_info = detector.get_search_capabilities()
        assert search_info["paging"] is True
        assert search_info["sorting"] is True

        # Test compatibility checking
        result = detector.check_compatibility(["paging", "sorting"])
        assert result.is_compatible is True

    def test_feature_matrix_server_coverage(self) -> None:
        """Test feature matrix coverage across server types."""
        # Test that major server types have comprehensive feature coverage
        major_servers = [
            ServerType.ACTIVE_DIRECTORY,
            ServerType.OPENLDAP,
            ServerType.ORACLE_DIRECTORY,
        ]

        essential_features = [
            "paging",
            "sorting",
            "ssl_tls",
            "password_policy",
        ]

        for server_type in major_servers:
            FeatureMatrix.get_supported_features(server_type)

            # Each major server should support essential features
            for feature in essential_features:
                support = FeatureMatrix.get_feature_support(server_type, feature)
                # Should be supported (not NONE)
                assert support != FeatureSupport.NONE

    def test_security_level_calculation_scenarios(self) -> None:
        """Test security level calculation for different scenarios."""
        test_scenarios = [
            # (capabilities, expected_level)
            (
                {
                    "supports_ssl": True,
                    "supports_start_tls": True,
                    "supports_password_policy": True,
                    "requires_ssl_for_auth": True,
                    "supported_sasl_mechanisms": ["GSSAPI"],
                },
                "high",
            ),
            (
                {
                    "supports_ssl": True,
                    "supports_start_tls": True,
                    "supported_sasl_mechanisms": ["PLAIN"],
                },
                "medium",
            ),
            (
                {
                    "supports_start_tls": True,
                },
                "low",
            ),
            ({}, "minimal"),
        ]

        for caps_dict, expected_level in test_scenarios:
            capabilities = ServerCapabilities(
                server_type=ServerType.OPENLDAP,
                **caps_dict,
            )

            assert capabilities._calculate_security_level() == expected_level


class TestSecurityValidation:
    """Security-focused test cases."""

    def test_authentication_capability_security(self) -> None:
        """Test authentication capability security validation."""
        # Test secure authentication setup
        secure_capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            supported_sasl_mechanisms=["GSSAPI", "EXTERNAL"],
            supports_simple_auth=True,
            supports_anonymous_auth=False,  # Should be False for security
            requires_ssl_for_auth=True,  # Should be True for security
            supports_ssl=True,
            supports_start_tls=True,
        )

        assert secure_capabilities._calculate_security_level() == "high"

        # Test insecure authentication setup
        insecure_capabilities = ServerCapabilities(
            server_type=ServerType.UNKNOWN,
            supported_sasl_mechanisms=[],
            supports_simple_auth=True,
            supports_anonymous_auth=True,  # Security risk
            requires_ssl_for_auth=False,  # Security risk
            supports_ssl=False,  # Security risk
            supports_start_tls=False,  # Security risk
        )

        assert insecure_capabilities._calculate_security_level() == "minimal"

    def test_ssl_tls_requirement_detection(self) -> None:
        """Test SSL/TLS requirement detection for security."""
        # Create detector and test SSL/TLS detection
        detector = CapabilityDetection(Mock())

        # Root DSE with Start TLS extension
        root_dse_with_tls = {
            "supportedExtension": ["1.3.6.1.4.1.1466.20037", "other.extension"],
        }

        auth_caps = detector._detect_authentication_capabilities(root_dse_with_tls)
        assert auth_caps["start_tls"] is True

        # Root DSE without Start TLS
        root_dse_without_tls = {
            "supportedExtension": ["other.extension"],
        }

        auth_caps = detector._detect_authentication_capabilities(root_dse_without_tls)
        assert auth_caps["start_tls"] is False

    def test_sasl_mechanism_security_validation(self) -> None:
        """Test SASL mechanism security validation."""
        # Strong SASL mechanisms
        strong_mechanisms = ["GSSAPI", "EXTERNAL", "DIGEST-MD5"]
        secure_capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            supported_sasl_mechanisms=strong_mechanisms,
            supports_ssl=True,
        )

        # Should have reasonable security level
        assert secure_capabilities._calculate_security_level() in {"medium", "high"}

        # Weak SASL mechanisms
        weak_mechanisms = ["PLAIN", "LOGIN"]
        weak_capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            supported_sasl_mechanisms=weak_mechanisms,
            supports_ssl=False,
        )

        # Should have lower security level
        assert weak_capabilities._calculate_security_level() in {"minimal", "low"}

    def test_feature_security_implications(self) -> None:
        """Test security implications of various features."""
        # Password policy feature should improve security
        with_password_policy = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            supports_password_policy=True,
            supports_ssl=True,
        )

        without_password_policy = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            supports_password_policy=False,
            supports_ssl=True,
        )

        # With password policy should have higher security level
        with_policy_level = with_password_policy._calculate_security_level()
        without_policy_level = without_password_policy._calculate_security_level()

        # Should be same or better (password policy adds +2 to score)
        security_levels = ["minimal", "low", "medium", "high"]
        with_index = security_levels.index(with_policy_level)
        without_index = security_levels.index(without_policy_level)

        assert with_index >= without_index


class TestPerformanceValidation:
    """Performance-focused test cases."""

    def test_server_capabilities_creation_performance(self) -> None:
        """Test server capabilities creation performance."""
        import time

        start_time = time.time()

        # Create many server capabilities objects
        for i in range(1000):
            ServerCapabilities(
                server_type=ServerType.OPENLDAP,
                server_version=f"2.5.{i % 20}",
                supported_ldap_versions=["2", "3"],
                supported_sasl_mechanisms=["PLAIN", "EXTERNAL"],
            )

        creation_time = time.time() - start_time

        # Should create quickly
        assert creation_time < 1.0  # Less than 1 second for 1000 objects

    def test_feature_matrix_lookup_performance(self) -> None:
        """Test feature matrix lookup performance."""
        import time

        start_time = time.time()

        # Perform many feature lookups
        for _ in range(1000):
            for server_type in [ServerType.ACTIVE_DIRECTORY, ServerType.OPENLDAP]:
                for feature in ["paging", "sorting", "ssl_tls", "password_policy"]:
                    FeatureMatrix.get_feature_support(server_type, feature)

        lookup_time = time.time() - start_time

        # Should lookup quickly
        assert lookup_time < 1.0  # Less than 1 second for 8000 lookups

    def test_capability_summary_performance(self) -> None:
        """Test capability summary generation performance."""
        import time

        # Create capabilities with many features
        features = {
            f"feature_{i}": FeatureInfo(
                name=f"feature_{i}",
                category=FeatureCategory.CONTROLS,
                support_level=FeatureSupport.FULL,
            )
            for i in range(100)
        }

        capabilities = ServerCapabilities(
            server_type=ServerType.OPENLDAP,
            features=features,
        )

        start_time = time.time()

        # Generate many summaries
        for _ in range(1000):
            capabilities.get_capability_summary()

        summary_time = time.time() - start_time

        # Should generate quickly
        assert summary_time < 1.0  # Less than 1 second for 1000 summaries


class TestErrorHandling:
    """Error handling test cases."""

    def test_server_type_detection_with_empty_data(self) -> None:
        """Test server type detection with empty or invalid data."""
        detector = CapabilityDetection(Mock())

        # Empty root DSE
        assert detector._detect_server_type({}) == ServerType.UNKNOWN

        # None values
        root_dse = {"vendorName": None, "vendorVersion": None}
        assert detector._detect_server_type(root_dse) == ServerType.UNKNOWN

    def test_authentication_capabilities_with_missing_data(self) -> None:
        """Test authentication capability detection with missing data."""
        detector = CapabilityDetection(Mock())

        # Empty root DSE
        auth_caps = detector._detect_authentication_capabilities({})

        assert auth_caps["sasl_mechanisms"] == []
        assert auth_caps["simple_auth"] is True  # Default
        assert auth_caps["anonymous_auth"] is False  # Default
        assert auth_caps["start_tls"] is False

    def test_search_capabilities_with_missing_data(self) -> None:
        """Test search capability detection with missing data."""
        detector = CapabilityDetection(Mock())

        # Empty root DSE
        search_caps = detector._detect_search_capabilities({})

        assert search_caps["paging"] is False
        assert search_caps["sorting"] is False
        assert search_caps["vlv"] is False
        assert search_caps["persistent_search"] is False

    def test_feature_info_validation_edge_cases(self) -> None:
        """Test feature info validation with edge cases."""
        # Empty name should still work
        feature = FeatureInfo(
            name="",
            category=FeatureCategory.CONTROLS,
            support_level=FeatureSupport.FULL,
        )
        assert feature.name == ""
        assert feature.is_supported() is True

    def test_compatibility_check_edge_cases(self) -> None:
        """Test compatibility checking with edge cases."""
        detector = CapabilityDetection(Mock())

        # Empty required features list
        result = detector.check_compatibility([])
        assert result.is_compatible is True
        assert result.required_features == []
        assert result.missing_features == []

    def test_confidence_calculation_bounds(self) -> None:
        """Test confidence calculation boundary conditions."""
        detector = CapabilityDetection(Mock())

        # Worst case scenario
        worst_capabilities = ServerCapabilities(
            server_type=ServerType.UNKNOWN,
            server_version=None,
            features={},
        )

        confidence = detector._calculate_detection_confidence(worst_capabilities)
        assert 0.0 <= confidence <= 1.0  # Should be within bounds
        assert confidence == 0.4  # Should be exactly 0.4 for this scenario


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
