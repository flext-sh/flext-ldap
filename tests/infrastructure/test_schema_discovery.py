"""Tests for Schema Discovery Service Infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest

from flext_ldap.infrastructure.schema_discovery import (
    AttributeUsage,
    ObjectClassType,
    SchemaAttribute,
    SchemaDiscoveryResult,
    SchemaDiscoveryService,
    SchemaElementType,
    SchemaObjectClass,
)


class TestSchemaAttribute:
    """Test suite for SchemaAttribute class."""

    def test_schema_attribute_initialization(self) -> None:
        """Test SchemaAttribute initialization with defaults."""
        attr = SchemaAttribute(
            oid="2.5.4.3",
            names=["cn", "commonName"],
            description="Common name",
        )

        assert attr.oid == "2.5.4.3"
        assert attr.names == ["cn", "commonName"]
        assert attr.description == "Common name"
        assert attr.usage == AttributeUsage.USER_APPLICATIONS
        assert attr.is_single_value is False

    def test_schema_attribute_primary_name(self) -> None:
        """Test primary name property."""
        # With names
        attr1 = SchemaAttribute(oid="2.5.4.3", names=["cn", "commonName"])
        assert attr1.primary_name == "cn"

        # Without names
        attr2 = SchemaAttribute(oid="2.5.4.3")
        assert attr2.primary_name == "2.5.4.3"

    def test_schema_attribute_has_name(self) -> None:
        """Test has_name method."""
        attr = SchemaAttribute(oid="2.5.4.3", names=["cn", "commonName"])

        assert attr.has_name("cn") is True
        assert attr.has_name("CN") is True  # Case insensitive
        assert attr.has_name("commonName") is True
        assert attr.has_name("unknown") is False

    def test_schema_attribute_to_dict(self) -> None:
        """Test to_dict conversion."""
        attr = SchemaAttribute(
            oid="2.5.4.3",
            names=["cn", "commonName"],
            description="Common name",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            is_single_value=True,
            usage=AttributeUsage.DIRECTORY_OPERATION,
        )

        attr_dict = attr.to_dict()

        assert attr_dict["oid"] == "2.5.4.3"
        assert attr_dict["names"] == ["cn", "commonName"]
        assert attr_dict["description"] == "Common name"
        assert attr_dict["syntax"] == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr_dict["is_single_value"] is True
        assert attr_dict["usage"] == "directoryOperation"


class TestSchemaObjectClass:
    """Test suite for SchemaObjectClass class."""

    def test_schema_object_class_initialization(self) -> None:
        """Test SchemaObjectClass initialization with defaults."""
        oc = SchemaObjectClass(
            oid="2.5.6.6",
            names=["person"],
            description="A person",
        )

        assert oc.oid == "2.5.6.6"
        assert oc.names == ["person"]
        assert oc.description == "A person"
        assert oc.object_class_type == ObjectClassType.STRUCTURAL
        assert oc.superior_classes == []
        assert oc.must_attributes == []
        assert oc.may_attributes == []

    def test_schema_object_class_primary_name(self) -> None:
        """Test primary name property."""
        # With names
        oc1 = SchemaObjectClass(oid="2.5.6.6", names=["person", "individual"])
        assert oc1.primary_name == "person"

        # Without names
        oc2 = SchemaObjectClass(oid="2.5.6.6")
        assert oc2.primary_name == "2.5.6.6"

    def test_schema_object_class_has_name(self) -> None:
        """Test has_name method."""
        oc = SchemaObjectClass(oid="2.5.6.6", names=["person", "individual"])

        assert oc.has_name("person") is True
        assert oc.has_name("PERSON") is True  # Case insensitive
        assert oc.has_name("individual") is True
        assert oc.has_name("unknown") is False

    def test_schema_object_class_get_all_attributes(self) -> None:
        """Test get_all_attributes method with inheritance."""
        # Create schema cache
        schema_cache = {}

        # Top object class
        top_oc = SchemaObjectClass(
            oid="2.5.6.0",
            names=["top"],
            object_class_type=ObjectClassType.ABSTRACT,
            must_attributes=["objectClass"],
        )
        schema_cache["top"] = top_oc

        # Person object class inheriting from top
        person_oc = SchemaObjectClass(
            oid="2.5.6.6",
            names=["person"],
            superior_classes=["top"],
            must_attributes=["sn", "cn"],
            may_attributes=["description", "telephoneNumber"],
        )
        schema_cache["person"] = person_oc

        # Organizational person inheriting from person
        org_person_oc = SchemaObjectClass(
            oid="2.5.6.7",
            names=["organizationalPerson"],
            superior_classes=["person"],
            may_attributes=["title", "ou"],
        )

        # Test inheritance
        must_attrs, may_attrs = org_person_oc.get_all_attributes(schema_cache)

        # Should include attributes from all superior classes
        assert "objectClass" in must_attrs  # From top
        assert "sn" in must_attrs  # From person
        assert "cn" in must_attrs  # From person
        assert "description" in may_attrs  # From person
        assert "telephoneNumber" in may_attrs  # From person
        assert "title" in may_attrs  # From organizationalPerson
        assert "ou" in may_attrs  # From organizationalPerson

    def test_schema_object_class_to_dict(self) -> None:
        """Test to_dict conversion."""
        oc = SchemaObjectClass(
            oid="2.5.6.6",
            names=["person"],
            description="A person",
            object_class_type=ObjectClassType.STRUCTURAL,
            superior_classes=["top"],
            must_attributes=["sn", "cn"],
            may_attributes=["description"],
        )

        oc_dict = oc.to_dict()

        assert oc_dict["oid"] == "2.5.6.6"
        assert oc_dict["names"] == ["person"]
        assert oc_dict["description"] == "A person"
        assert oc_dict["object_class_type"] == "STRUCTURAL"
        assert oc_dict["superior_classes"] == ["top"]
        assert oc_dict["must_attributes"] == ["sn", "cn"]
        assert oc_dict["may_attributes"] == ["description"]


class TestSchemaDiscoveryResult:
    """Test suite for SchemaDiscoveryResult class."""

    def test_schema_discovery_result_initialization(self) -> None:
        """Test SchemaDiscoveryResult initialization with defaults."""
        result = SchemaDiscoveryResult()

        assert result.discovery_id is not None
        assert result.timestamp is not None
        assert result.server_info == {}
        assert result.object_classes == {}
        assert result.attributes == {}
        assert result.discovery_errors == []
        assert result.cache_hit is False

    def test_schema_discovery_result_successful(self) -> None:
        """Test is_successful property."""
        # Successful result
        result1 = SchemaDiscoveryResult()
        assert result1.is_successful is True

        # Failed result
        result2 = SchemaDiscoveryResult(discovery_errors=["Error 1", "Error 2"])
        assert result2.is_successful is False

    def test_schema_discovery_result_total_elements(self) -> None:
        """Test total_elements property."""
        oc = SchemaObjectClass(oid="2.5.6.6", names=["person"])
        attr = SchemaAttribute(oid="2.5.4.3", names=["cn"])

        result = SchemaDiscoveryResult(
            object_classes={"person": oc},
            attributes={"cn": attr},
            syntaxes={"syntax1": {}},
            matching_rules={"rule1": {}},
        )

        assert result.total_elements == 4

    def test_schema_discovery_result_to_dict(self) -> None:
        """Test to_dict conversion."""
        timestamp = datetime.now(UTC)
        oc = SchemaObjectClass(oid="2.5.6.6", names=["person"])
        attr = SchemaAttribute(oid="2.5.4.3", names=["cn"])

        result = SchemaDiscoveryResult(
            timestamp=timestamp,
            server_info={"vendor": "Test"},
            object_classes={"person": oc},
            attributes={"cn": attr},
            discovery_errors=["error1"],
            cache_hit=True,
            discovery_duration_ms=100,
        )

        result_dict = result.to_dict()

        assert result_dict["timestamp"] == timestamp.isoformat()
        assert result_dict["server_info"] == {"vendor": "Test"}
        assert "person" in result_dict["object_classes"]
        assert "cn" in result_dict["attributes"]
        assert result_dict["discovery_errors"] == ["error1"]
        assert result_dict["cache_hit"] is True
        assert result_dict["discovery_duration_ms"] == 100
        assert result_dict["total_elements"] == 2


class TestSchemaDiscoveryService:
    """Test suite for SchemaDiscoveryService class."""

    @pytest.fixture
    def discovery_service(self) -> SchemaDiscoveryService:
        """SchemaDiscoveryService instance."""
        return SchemaDiscoveryService(
            cache_ttl_minutes=60,
            max_cache_size=10,
            enable_caching=True,
        )

    @pytest.fixture
    def mock_connection(self) -> MagicMock:
        """Mock LDAP connection."""
        connection = MagicMock()
        connection.server.host = "ldap.example.com"
        return connection

    @pytest.mark.asyncio
    async def test_discover_schema_success(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test successful schema discovery."""
        result = await discovery_service.discover_schema(mock_connection)

        assert result.is_success
        assert result.data is not None
        assert result.data.is_successful is True
        assert result.data.total_elements > 0
        assert "person" in result.data.object_classes
        assert "cn" in result.data.attributes
        assert result.data.cache_hit is False

    @pytest.mark.asyncio
    async def test_discover_schema_caching(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test schema discovery caching."""
        # First discovery - should not be from cache
        result1 = await discovery_service.discover_schema(mock_connection)
        assert result1.is_success
        assert result1.data is not None
        assert result1.data.cache_hit is False

        # Second discovery - should be from cache
        result2 = await discovery_service.discover_schema(mock_connection)
        assert result2.is_success
        assert result2.data is not None
        assert result2.data.cache_hit is True

    @pytest.mark.asyncio
    async def test_discover_schema_force_refresh(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test forced schema refresh."""
        # First discovery
        await discovery_service.discover_schema(mock_connection)

        # Force refresh - should not use cache
        result = await discovery_service.discover_schema(
            mock_connection,
            force_refresh=True,
        )
        assert result.is_success
        assert result.data is not None
        assert result.data.cache_hit is False

    @pytest.mark.asyncio
    async def test_discover_schema_caching_disabled(
        self,
        mock_connection: MagicMock,
    ) -> None:
        """Test schema discovery with caching disabled."""
        service = SchemaDiscoveryService(enable_caching=False)

        # Multiple discoveries should not use cache
        result1 = await service.discover_schema(mock_connection)
        result2 = await service.discover_schema(mock_connection)

        assert result1.is_success
        assert result2.is_success
        assert result1.data is not None
        assert result2.data is not None
        assert result1.data.cache_hit is False
        assert result2.data.cache_hit is False

    @pytest.mark.asyncio
    async def test_get_object_class_found(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test getting existing object class."""
        result = await discovery_service.get_object_class(mock_connection, "person")

        assert result.is_success
        assert result.data is not None
        assert result.data.has_name("person")

    @pytest.mark.asyncio
    async def test_get_object_class_not_found(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test getting non-existing object class."""
        result = await discovery_service.get_object_class(
            mock_connection,
            "nonexistent",
        )

        assert result.is_success
        assert result.data is None

    @pytest.mark.asyncio
    async def test_get_attribute_type_found(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test getting existing attribute type."""
        result = await discovery_service.get_attribute_type(mock_connection, "cn")

        assert result.is_success
        assert result.data is not None
        assert result.data.has_name("cn")

    @pytest.mark.asyncio
    async def test_get_attribute_type_not_found(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test getting non-existing attribute type."""
        result = await discovery_service.get_attribute_type(
            mock_connection,
            "nonexistent",
        )

        assert result.is_success
        assert result.data is None

    @pytest.mark.asyncio
    async def test_validate_object_structure_valid(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test validation of valid object structure."""
        object_classes = ["person"]
        attributes = {
            "cn": "John Doe",
            "sn": "Doe",
            "description": "A person",
        }

        result = await discovery_service.validate_object_structure(
            mock_connection,
            object_classes,
            attributes,
        )

        assert result.is_success
        assert result.data is not None
        assert result.data["is_valid"] is True
        assert len(result.data["errors"]) == 0
        assert len(result.data["missing_required"]) == 0

    @pytest.mark.asyncio
    async def test_validate_object_structure_missing_required(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test validation with missing required attributes."""
        object_classes = ["person"]
        attributes = {
            "cn": "John Doe",
            # Missing required "sn" attribute
        }

        result = await discovery_service.validate_object_structure(
            mock_connection,
            object_classes,
            attributes,
        )

        assert result.is_success
        assert result.data is not None
        assert result.data["is_valid"] is False
        assert "sn" in result.data["missing_required"]

    @pytest.mark.asyncio
    async def test_validate_object_structure_unknown_attributes(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test validation with unknown attributes."""
        object_classes = ["person"]
        attributes = {
            "cn": "John Doe",
            "sn": "Doe",
            "unknownAttr": "value",  # Unknown attribute
        }

        result = await discovery_service.validate_object_structure(
            mock_connection,
            object_classes,
            attributes,
        )

        assert result.is_success
        assert result.data is not None
        assert "unknownAttr" in result.data["unknown_attributes"]
        assert len(result.data["warnings"]) > 0

    @pytest.mark.asyncio
    async def test_validate_object_structure_unknown_object_class(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test validation with unknown object class."""
        object_classes = ["unknownClass"]
        attributes: dict[str, Any] = {}

        result = await discovery_service.validate_object_structure(
            mock_connection,
            object_classes,
            attributes,
        )

        assert result.is_success
        assert result.data is not None
        assert result.data["is_valid"] is False
        assert len(result.data["errors"]) > 0
        assert any("Unknown object class" in error for error in result.data["errors"])

    def test_generate_cache_key(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test cache key generation."""
        cache_key = discovery_service._generate_cache_key(mock_connection)
        assert cache_key == "schema_ldap.example.com"

    def test_cache_management(self, discovery_service: SchemaDiscoveryService) -> None:
        """Test cache management functionality."""
        # Test cache size limit
        service = SchemaDiscoveryService(max_cache_size=2)

        # Create mock results
        result1 = SchemaDiscoveryResult()
        result2 = SchemaDiscoveryResult()
        result3 = SchemaDiscoveryResult()

        # Cache results
        service._cache_schema("key1", result1)
        service._cache_schema("key2", result2)
        assert len(service._schema_cache) == 2

        # Adding third should remove oldest
        service._cache_schema("key3", result3)
        assert len(service._schema_cache) == 2
        assert "key3" in service._schema_cache

    def test_cache_expiration(self, discovery_service: SchemaDiscoveryService) -> None:
        """Test cache expiration."""
        result = SchemaDiscoveryResult()

        # Cache with past timestamp to simulate expiration
        past_time = datetime.now(UTC) - timedelta(hours=2)
        discovery_service._schema_cache["test_key"] = (result, past_time)

        # Should return None for expired cache
        cached_result = discovery_service._get_cached_schema("test_key")
        assert cached_result is None
        assert "test_key" not in discovery_service._schema_cache

    def test_clear_cache(self, discovery_service: SchemaDiscoveryService) -> None:
        """Test cache clearing."""
        result = SchemaDiscoveryResult()
        discovery_service._cache_schema("test_key", result)

        assert len(discovery_service._schema_cache) == 1

        discovery_service.clear_cache()

        assert len(discovery_service._schema_cache) == 0

    def test_get_cache_stats(self, discovery_service: SchemaDiscoveryService) -> None:
        """Test cache statistics."""
        stats = discovery_service.get_cache_stats()

        assert "cache_size" in stats
        assert "max_cache_size" in stats
        assert "cache_ttl_minutes" in stats
        assert "discovery_history_size" in stats
        assert stats["max_cache_size"] == 10
        assert stats["cache_ttl_minutes"] == 60

    def test_get_discovery_history(
        self,
        discovery_service: SchemaDiscoveryService,
    ) -> None:
        """Test discovery history tracking."""
        # Initially empty
        history = discovery_service.get_discovery_history()
        assert len(history) == 0

        # Add some results to history
        result1 = SchemaDiscoveryResult()
        result2 = SchemaDiscoveryResult()
        discovery_service._discovery_history.extend([result1, result2])

        # Check history
        history = discovery_service.get_discovery_history()
        assert len(history) == 2

        # Test limit
        history_limited = discovery_service.get_discovery_history(limit=1)
        assert len(history_limited) == 1

    def test_enum_values(self) -> None:
        """Test enum value definitions."""
        # SchemaElementType
        assert SchemaElementType.OBJECT_CLASS.value == "objectClass"
        assert SchemaElementType.ATTRIBUTE_TYPE.value == "attributeType"

        # AttributeUsage
        assert AttributeUsage.USER_APPLICATIONS.value == "userApplications"
        assert AttributeUsage.DIRECTORY_OPERATION.value == "directoryOperation"

        # ObjectClassType
        assert ObjectClassType.STRUCTURAL.value == "STRUCTURAL"
        assert ObjectClassType.ABSTRACT.value == "ABSTRACT"
        assert ObjectClassType.AUXILIARY.value == "AUXILIARY"
