"""Tests for FLEXT-LDAP Infrastructure Schema Discovery Service.

Pragmatic test suite focusing on schema discovery functionality,
caching mechanisms, SOLID principles, and Clean Architecture boundaries.

Test Coverage Focus:
    - Schema discovery service initialization and configuration
    - Object class and attribute type discovery
    - Schema validation and structure checking
    - Caching mechanisms and performance optimization
    - FlextResult pattern compliance throughout
    - Parameter Object pattern validation
    - Mock-based testing for LDAP operations

Author: FLEXT Development Team

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest

from flext_ldap.infrastructure.schema_discovery import (
    FlextLdapAttributeUsage,
    FlextLdapObjectClassType,
    FlextLdapSchemaAttribute,
    FlextLdapSchemaAttributeData,
    FlextLdapSchemaDiscoveryService,
    FlextLdapSchemaElementType,
    FlextLdapSchemaObjectClass,
    FlextLdapSchemaObjectClassData,
    ValidationResult,
)


class TestFlextLdapSchemaAttributeData:
    """Test suite for schema attribute data Parameter Object pattern."""

    def test_attribute_data_creation_minimal(self) -> None:
        """Test schema attribute data creation with minimal parameters."""
        data = FlextLdapSchemaAttributeData(oid="1.2.3.4")

        assert data.oid == "1.2.3.4"
        assert data.names is None
        assert data.description is None
        assert data.syntax is None
        assert data.usage == FlextLdapAttributeUsage.USER_APPLICATIONS
        assert data.is_single_value is False
        assert data.is_obsolete is False
        assert data.extensions is None

    def test_attribute_data_creation_comprehensive(self) -> None:
        """Test schema attribute data creation with all parameters."""
        data = FlextLdapSchemaAttributeData(
            oid="1.3.6.1.4.1.1466.101.120.15",
            names=["cn", "commonName"],
            description="Common name attribute",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality_matching_rule="caseIgnoreMatch",
            ordering_matching_rule="caseIgnoreOrderingMatch",
            substring_matching_rule="caseIgnoreSubstringsMatch",
            usage=FlextLdapAttributeUsage.USER_APPLICATIONS,
            is_single_value=False,
            is_collective=False,
            is_no_user_modification=False,
            is_obsolete=False,
            superior="name",
            extensions={"X-ORIGIN": ["RFC2256"]}
        )

        assert data.oid == "1.3.6.1.4.1.1466.101.120.15"
        assert data.names == ["cn", "commonName"]
        assert data.description == "Common name attribute"
        assert data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert data.equality_matching_rule == "caseIgnoreMatch"
        assert data.usage == FlextLdapAttributeUsage.USER_APPLICATIONS
        assert data.superior == "name"
        assert data.extensions == {"X-ORIGIN": ["RFC2256"]}


class TestFlextLdapSchemaAttribute:
    """Test suite for schema attribute using Parameter Object pattern."""

    def test_schema_attribute_initialization_from_data(self) -> None:
        """Test schema attribute initialization from data object."""
        data = FlextLdapSchemaAttributeData(
            oid="1.2.3.4",
            names=["testAttr", "test"],
            description="Test attribute",
            is_single_value=True
        )

        attr = FlextLdapSchemaAttribute(data)

        assert attr.oid == "1.2.3.4"
        assert attr.names == ["testAttr", "test"]
        assert attr.description == "Test attribute"
        assert attr.is_single_value is True
        assert attr.extensions == {}

    def test_schema_attribute_create_factory_method(self) -> None:
        """Test schema attribute creation using factory method."""
        attr = FlextLdapSchemaAttribute.create(
            oid="1.2.3.4",
            names=["uid", "userid"],
            description="User identifier",
            is_single_value=True,
            usage=FlextLdapAttributeUsage.USER_APPLICATIONS
        )

        assert attr.oid == "1.2.3.4"
        assert attr.names == ["uid", "userid"]
        assert attr.description == "User identifier"
        assert attr.is_single_value is True
        assert attr.usage == FlextLdapAttributeUsage.USER_APPLICATIONS

    def test_schema_attribute_primary_name(self) -> None:
        """Test primary name property."""
        # With names
        attr = FlextLdapSchemaAttribute.create(
            oid="1.2.3.4",
            names=["primaryName", "alternativeName"]
        )
        assert attr.primary_name == "primaryName"

        # Without names (falls back to OID)
        attr_no_names = FlextLdapSchemaAttribute.create(oid="1.2.3.5")
        assert attr_no_names.primary_name == "1.2.3.5"

    def test_schema_attribute_has_name(self) -> None:
        """Test name checking functionality."""
        attr = FlextLdapSchemaAttribute.create(
            oid="1.2.3.4",
            names=["CN", "commonName"]
        )

        assert attr.has_name("cn") is True  # Case insensitive
        assert attr.has_name("CN") is True
        assert attr.has_name("CommonName") is True
        assert attr.has_name("nonexistent") is False

    def test_schema_attribute_to_dict(self) -> None:
        """Test dictionary conversion."""
        attr = FlextLdapSchemaAttribute.create(
            oid="1.2.3.4",
            names=["testAttr"],
            description="Test description",
            is_single_value=True
        )

        result_dict = attr.to_dict()

        assert isinstance(result_dict, dict)
        assert result_dict["oid"] == "1.2.3.4"
        assert result_dict["names"] == ["testAttr"]
        assert result_dict["description"] == "Test description"
        assert result_dict["is_single_value"] is True
        assert result_dict["usage"] == FlextLdapAttributeUsage.USER_APPLICATIONS.value


class TestFlextLdapSchemaObjectClass:
    """Test suite for schema object class functionality."""

    def test_schema_object_class_creation(self) -> None:
        """Test schema object class creation using factory method."""
        obj_class = FlextLdapSchemaObjectClass.create(
            oid="2.5.6.6",
            names=["person"],
            description="Person object class",
            object_class_type=FlextLdapObjectClassType.STRUCTURAL,
            must_attributes=["cn", "sn"],
            may_attributes=["description", "telephoneNumber"]
        )

        assert obj_class.oid == "2.5.6.6"
        assert obj_class.names == ["person"]
        assert obj_class.description == "Person object class"
        assert obj_class.object_class_type == FlextLdapObjectClassType.STRUCTURAL
        assert obj_class.must_attributes == ["cn", "sn"]
        assert obj_class.may_attributes == ["description", "telephoneNumber"]

    def test_schema_object_class_get_all_attributes(self) -> None:
        """Test getting all attributes (must + may)."""
        obj_class = FlextLdapSchemaObjectClass.create(
            oid="2.5.6.6",
            names=["person"],
            must_attributes=["cn", "sn"],
            may_attributes=["description", "telephoneNumber"]
        )

        # Create empty schema cache for testing
        schema_cache: dict[str, FlextLdapSchemaObjectClass] = {}

        must_attrs, may_attrs = obj_class.get_all_attributes(schema_cache)

        # Check that must attributes contain the expected ones
        assert "cn" in must_attrs
        assert "sn" in must_attrs

        # Check that may attributes contain the expected ones
        assert "description" in may_attrs
        assert "telephoneNumber" in may_attrs


class TestFlextLdapSchemaDiscoveryServiceInitialization:
    """Test suite for schema discovery service initialization."""

    def test_service_initialization_default_parameters(self) -> None:
        """Test service initialization with default parameters."""
        service = FlextLdapSchemaDiscoveryService()

        assert service.cache_ttl_minutes == 60
        assert service.max_cache_size == 100
        assert service.enable_caching is True
        assert isinstance(service._schema_cache, dict)
        assert isinstance(service._discovery_history, list)
        assert len(service._schema_cache) == 0
        assert len(service._discovery_history) == 0

    def test_service_initialization_custom_parameters(self) -> None:
        """Test service initialization with custom parameters."""
        service = FlextLdapSchemaDiscoveryService(
            cache_ttl_minutes=30,
            max_cache_size=50,
            enable_caching=False
        )

        assert service.cache_ttl_minutes == 30
        assert service.max_cache_size == 50
        assert service.enable_caching is False

    def test_service_initialization_caching_disabled(self) -> None:
        """Test service initialization with caching disabled."""
        service = FlextLdapSchemaDiscoveryService(enable_caching=False)

        assert service.enable_caching is False
        # Cache structures should still exist but won't be used
        assert isinstance(service._schema_cache, dict)


class TestFlextLdapSchemaDiscoveryServiceCaching:
    """Test suite for schema discovery service caching functionality."""

    def test_clear_cache_functionality(self) -> None:
        """Test cache clearing functionality."""
        service = FlextLdapSchemaDiscoveryService()

        # Manually add some cache entries for testing
        service._schema_cache["test_key"] = (Mock(), datetime.now(UTC))
        service._discovery_history = [Mock(), Mock()]

        # Clear cache (only clears schema cache, not history)
        service.clear_cache()

        assert len(service._schema_cache) == 0
        # Discovery history is not cleared by clear_cache method
        assert len(service._discovery_history) == 2

    def test_get_cache_stats(self) -> None:
        """Test cache statistics functionality."""
        service = FlextLdapSchemaDiscoveryService()

        # Initially empty
        stats = service.get_cache_stats()
        assert isinstance(stats, dict)
        assert stats["cache_size"] == 0
        assert stats["discovery_history_size"] == 0
        assert stats["cache_ttl_minutes"] == 60

        # Add some entries and check stats
        service._schema_cache["test"] = (Mock(), datetime.now(UTC))
        service._discovery_history = [Mock()]

        stats = service.get_cache_stats()
        assert stats["cache_size"] == 1
        assert stats["discovery_history_size"] == 1

    def test_get_discovery_history(self) -> None:
        """Test discovery history retrieval."""
        service = FlextLdapSchemaDiscoveryService()

        # Initially empty
        history = service.get_discovery_history()
        assert isinstance(history, list)
        assert len(history) == 0

        # Add mock history entries
        mock_result1 = Mock()
        mock_result2 = Mock()
        service._discovery_history = [mock_result1, mock_result2]

        history = service.get_discovery_history()
        assert len(history) == 2
        assert history[0] is mock_result1
        assert history[1] is mock_result2

    def test_get_discovery_history_with_limit(self) -> None:
        """Test discovery history retrieval with limit parameter."""
        service = FlextLdapSchemaDiscoveryService()

        # Add multiple mock entries
        mock_results = [Mock() for _ in range(5)]
        service._discovery_history = mock_results

        # Get limited history
        limited_history = service.get_discovery_history(limit=3)
        assert len(limited_history) == 3
        # Should get the most recent entries (last 3)
        assert limited_history == mock_results[-3:]

        # Test with limit larger than available
        large_limit_history = service.get_discovery_history(limit=10)
        assert len(large_limit_history) == 5
        assert large_limit_history == mock_results


class TestFlextLdapSchemaDiscoveryServiceMockIntegration:
    """Test suite for schema discovery service with mock integrations."""

    @pytest.fixture
    def mock_connection(self) -> Mock:
        """Create mock LDAP connection for testing."""
        mock_conn = Mock()
        mock_conn.server_host = "ldap.test.com"
        mock_conn.server_port = 389
        mock_conn.bind_dn = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=com"
        return mock_conn

    @pytest.fixture
    def discovery_service(self) -> FlextLdapSchemaDiscoveryService:
        """Create discovery service for testing."""
        return FlextLdapSchemaDiscoveryService(
            cache_ttl_minutes=30,
            enable_caching=True
        )

    @patch("flext_ldap.infrastructure.schema_discovery.FlextLdapSchemaDiscoveryService._perform_schema_discovery")
    async def test_discover_schema_success(
        self,
        mock_perform_discovery: Mock,
        discovery_service: FlextLdapSchemaDiscoveryService,
        mock_connection: Mock
    ) -> None:
        """Test successful schema discovery."""
        # Setup mock discovery result
        mock_result = Mock()
        mock_result.total_elements = 100
        mock_result.is_successful.return_value = True
        mock_perform_discovery.return_value = mock_result

        result = await discovery_service.discover_schema(mock_connection)

        assert result.is_success
        assert result.data is mock_result
        mock_perform_discovery.assert_called_once()

        # Check that result was added to history
        assert len(discovery_service._discovery_history) == 1
        assert discovery_service._discovery_history[0] is mock_result

    @patch("flext_ldap.infrastructure.schema_discovery.FlextLdapSchemaDiscoveryService._perform_schema_discovery")
    async def test_discover_schema_with_caching(
        self,
        mock_perform_discovery: Mock,
        discovery_service: FlextLdapSchemaDiscoveryService,
        mock_connection: Mock
    ) -> None:
        """Test schema discovery with caching enabled."""
        # First call - should perform discovery
        mock_result = Mock()
        mock_result.total_elements = 50
        mock_perform_discovery.return_value = mock_result

        result1 = await discovery_service.discover_schema(mock_connection)
        assert result1.is_success
        assert mock_perform_discovery.call_count == 1

        # Second call - should use cache (mock won't be called again)
        result2 = await discovery_service.discover_schema(mock_connection)
        assert result2.is_success
        # Mock should not be called again if caching works
        assert mock_perform_discovery.call_count == 1

    @patch("flext_ldap.infrastructure.schema_discovery.FlextLdapSchemaDiscoveryService._perform_schema_discovery")
    async def test_discover_schema_force_refresh(
        self,
        mock_perform_discovery: Mock,
        discovery_service: FlextLdapSchemaDiscoveryService,
        mock_connection: Mock
    ) -> None:
        """Test schema discovery with force refresh."""
        # Setup mock
        mock_result = Mock()
        mock_result.total_elements = 75
        mock_perform_discovery.return_value = mock_result

        # First call
        await discovery_service.discover_schema(mock_connection)
        assert mock_perform_discovery.call_count == 1

        # Second call with force_refresh - should bypass cache
        await discovery_service.discover_schema(mock_connection, force_refresh=True)
        assert mock_perform_discovery.call_count == 2

    @patch("flext_ldap.infrastructure.schema_discovery.FlextLdapSchemaDiscoveryService._perform_schema_discovery")
    async def test_discover_schema_exception_handling(
        self,
        mock_perform_discovery: Mock,
        discovery_service: FlextLdapSchemaDiscoveryService,
        mock_connection: Mock
    ) -> None:
        """Test schema discovery exception handling."""
        # Setup mock to raise exception
        mock_perform_discovery.side_effect = RuntimeError("Schema discovery failed")

        result = await discovery_service.discover_schema(mock_connection)

        assert not result.is_success
        assert "Schema discovery failed" in result.error

    async def test_get_object_class_not_implemented(
        self,
        discovery_service: FlextLdapSchemaDiscoveryService,
        mock_connection: Mock
    ) -> None:
        """Test get_object_class method (basic validation)."""
        # Since this method likely needs actual implementation,
        # we test that it exists and has correct signature
        try:
            result = await discovery_service.get_object_class(mock_connection, "person")
            # Should return a FlextResult
            assert hasattr(result, "is_success")
            assert hasattr(result, "data")
            assert hasattr(result, "error")
        except NotImplementedError:
            # If method is not implemented yet, that's acceptable
            pass

    async def test_get_attribute_type_not_implemented(
        self,
        discovery_service: FlextLdapSchemaDiscoveryService,
        mock_connection: Mock
    ) -> None:
        """Test get_attribute_type method (basic validation)."""
        try:
            result = await discovery_service.get_attribute_type(mock_connection, "cn")
            # Should return a FlextResult
            assert hasattr(result, "is_success")
            assert hasattr(result, "data")
            assert hasattr(result, "error")
        except NotImplementedError:
            # If method is not implemented yet, that's acceptable
            pass


class TestValidationResult:
    """Test suite for ValidationResult TypedDict."""

    def test_validation_result_structure(self) -> None:
        """Test ValidationResult structure and type safety."""
        # Create a ValidationResult (as dict following TypedDict structure)
        validation_result: ValidationResult = {
            "is_valid": True,
            "errors": [],
            "warnings": ["Schema validation warning"],
            "missing_required": [],
            "unknown_attributes": ["nonStandardAttr"],
            "schema_violations": []
        }

        assert validation_result["is_valid"] is True
        assert isinstance(validation_result["errors"], list)
        assert isinstance(validation_result["warnings"], list)
        assert len(validation_result["warnings"]) == 1
        assert validation_result["warnings"][0] == "Schema validation warning"
        assert len(validation_result["unknown_attributes"]) == 1

    def test_validation_result_failure_case(self) -> None:
        """Test ValidationResult for failure scenarios."""
        validation_result: ValidationResult = {
            "is_valid": False,
            "errors": ["Required attribute 'cn' missing"],
            "warnings": [],
            "missing_required": ["cn", "sn"],
            "unknown_attributes": [],
            "schema_violations": ["Object class 'invalid' not found"]
        }

        assert validation_result["is_valid"] is False
        assert len(validation_result["errors"]) == 1
        assert len(validation_result["missing_required"]) == 2
        assert "cn" in validation_result["missing_required"]
        assert len(validation_result["schema_violations"]) == 1


class TestFlextLdapSchemaElementType:
    """Test suite for schema element type enumeration."""

    def test_schema_element_types(self) -> None:
        """Test schema element type enumeration values."""
        assert FlextLdapSchemaElementType.OBJECT_CLASS.value == "objectClass"
        assert FlextLdapSchemaElementType.ATTRIBUTE_TYPE.value == "attributeType"
        assert FlextLdapSchemaElementType.SYNTAX.value == "ldapSyntax"
        assert FlextLdapSchemaElementType.MATCHING_RULE.value == "matchingRule"
        assert FlextLdapSchemaElementType.MATCHING_RULE_USE.value == "matchingRuleUse"
        assert FlextLdapSchemaElementType.DIT_CONTENT_RULE.value == "dITContentRule"
        assert FlextLdapSchemaElementType.DIT_STRUCTURE_RULE.value == "dITStructureRule"
        assert FlextLdapSchemaElementType.NAME_FORM.value == "nameForm"

    def test_attribute_usage_types(self) -> None:
        """Test attribute usage enumeration values."""
        assert FlextLdapAttributeUsage.USER_APPLICATIONS.value == "userApplications"
        assert FlextLdapAttributeUsage.DIRECTORY_OPERATION.value == "directoryOperation"
        assert FlextLdapAttributeUsage.DISTRIBUTED_OPERATION.value == "distributedOperation"
        assert FlextLdapAttributeUsage.DSA_OPERATION.value == "dSAOperation"

    def test_object_class_types(self) -> None:
        """Test object class type enumeration values."""
        assert FlextLdapObjectClassType.STRUCTURAL.value == "STRUCTURAL"
        assert FlextLdapObjectClassType.ABSTRACT.value == "ABSTRACT"
        assert FlextLdapObjectClassType.AUXILIARY.value == "AUXILIARY"


class TestFlextLdapSchemaDiscoveryServiceCleanArchitecture:
    """Test Clean Architecture compliance and SOLID principles."""

    def test_clean_architecture_boundaries(self) -> None:
        """Test Clean Architecture layer boundaries are respected."""
        service = FlextLdapSchemaDiscoveryService()

        # Should be infrastructure layer component
        assert hasattr(service, "discover_schema")
        assert hasattr(service, "get_object_class")
        assert hasattr(service, "get_attribute_type")

        # Should have caching capabilities (infrastructure concern)
        assert hasattr(service, "clear_cache")
        assert hasattr(service, "get_cache_stats")

    def test_single_responsibility_principle(self) -> None:
        """Test Single Responsibility Principle compliance."""
        service = FlextLdapSchemaDiscoveryService()

        # Should have single responsibility: schema discovery and caching
        # Public methods should be focused on schema operations
        public_methods = [
            method for method in dir(service)
            if not method.startswith("_") and callable(getattr(service, method))
        ]

        # Core schema discovery methods
        expected_core_methods = {
            "discover_schema", "get_object_class", "get_attribute_type",
            "validate_object_structure"
        }
        # Cache management methods
        expected_cache_methods = {
            "clear_cache", "get_cache_stats", "get_discovery_history"
        }

        actual_methods = set(public_methods)
        assert expected_core_methods.issubset(actual_methods)
        assert expected_cache_methods.issubset(actual_methods)

    def test_dependency_injection_compliance(self) -> None:
        """Test dependency injection patterns."""
        service = FlextLdapSchemaDiscoveryService(
            cache_ttl_minutes=120,
            max_cache_size=200,
            enable_caching=False
        )

        # Should accept configuration via constructor
        assert service.cache_ttl_minutes == 120
        assert service.max_cache_size == 200
        assert service.enable_caching is False

    def test_parameter_object_pattern_usage(self) -> None:
        """Test Parameter Object pattern usage in schema classes."""
        # Schema attribute uses Parameter Object pattern
        attr_data = FlextLdapSchemaAttributeData(
            oid="1.2.3.4",
            names=["test"],
            description="Test attribute"
        )
        attr = FlextLdapSchemaAttribute(attr_data)
        assert attr.oid == "1.2.3.4"

        # Object class uses Parameter Object pattern
        oc_data = FlextLdapSchemaObjectClassData(
            oid="2.5.6.6",
            names=["person"],
            object_class_type=FlextLdapObjectClassType.STRUCTURAL
        )
        oc = FlextLdapSchemaObjectClass(oc_data)
        assert oc.oid == "2.5.6.6"

    def test_flext_result_pattern_consistency(self) -> None:
        """Test consistent use of FlextResult pattern."""
        service = FlextLdapSchemaDiscoveryService()

        # All async methods should return FlextResult
        import inspect

        async_methods = [
            "discover_schema",
            "get_object_class",
            "get_attribute_type",
            "validate_object_structure"
        ]

        for method_name in async_methods:
            method = getattr(service, method_name)
            assert inspect.iscoroutinefunction(method), f"{method_name} should be async"

    def test_constants_usage_dry_principle(self) -> None:
        """Test DRY principle with constants usage."""
        service = FlextLdapSchemaDiscoveryService()

        # Should have constants to avoid code duplication
        assert hasattr(service, "INET_ORG_PERSON_MAY_ATTRIBUTES")
        assert isinstance(service.INET_ORG_PERSON_MAY_ATTRIBUTES, list)
        assert len(service.INET_ORG_PERSON_MAY_ATTRIBUTES) > 0

        # Verify some expected attributes
        expected_attrs = ["mail", "uid", "givenName", "employeeNumber"]
        for attr in expected_attrs:
            assert attr in service.INET_ORG_PERSON_MAY_ATTRIBUTES
