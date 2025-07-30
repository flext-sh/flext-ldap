"""Tests for Schema Discovery Service Infrastructure.

# Constants
EXPECTED_BULK_SIZE = 2

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest

# Constants
EXPECTED_BULK_SIZE = 2
EXPECTED_DATA_COUNT = 3
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

        if attr.oid != "2.5.4.3":
            raise AssertionError(f"Expected {'2.5.4.3'}, got {attr.oid}")
        assert attr.names == ["cn", "commonName"]
        if attr.description != "Common name":
            raise AssertionError(f"Expected {'Common name'}, got {attr.description}")
        assert attr.usage == AttributeUsage.USER_APPLICATIONS
        if attr.is_single_value:
            raise AssertionError(f"Expected False, got {attr.is_single_value}")

    def test_schema_attribute_primary_name(self) -> None:
        """Test primary name property."""
        # With names
        attr1 = SchemaAttribute(oid="2.5.4.3", names=["cn", "commonName"])
        if attr1.primary_name != "cn":
            raise AssertionError(f"Expected {'cn'}, got {attr1.primary_name}")

        # Without names
        attr2 = SchemaAttribute(oid="2.5.4.3")
        if attr2.primary_name != "2.5.4.3":
            raise AssertionError(f"Expected {'2.5.4.3'}, got {attr2.primary_name}")

    def test_schema_attribute_has_name(self) -> None:
        """Test has_name method."""
        attr = SchemaAttribute(oid="2.5.4.3", names=["cn", "commonName"])

        if not (attr.has_name("cn")):
            raise AssertionError(f"Expected True, got {attr.has_name('cn')}")
        assert attr.has_name("CN") is True  # Case insensitive
        if not (attr.has_name("commonName")):
            raise AssertionError(f"Expected True, got {attr.has_name('commonName')}")
        if attr.has_name("unknown"):
            raise AssertionError(f"Expected False, got {attr.has_name('unknown')}")

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

        if attr_dict["oid"] != "2.5.4.3":
            raise AssertionError(f"Expected {'2.5.4.3'}, got {attr_dict['oid']}")
        assert attr_dict["names"] == ["cn", "commonName"]
        if attr_dict["description"] != "Common name":
            raise AssertionError(
                f"Expected {'Common name'}, got {attr_dict['description']}"
            )
        assert attr_dict["syntax"] == "1.3.6.1.4.1.1466.115.121.1.15"
        if not (attr_dict["is_single_value"]):
            raise AssertionError(f"Expected True, got {attr_dict['is_single_value']}")
        if attr_dict["usage"] != "directoryOperation":
            raise AssertionError(
                f"Expected {'directoryOperation'}, got {attr_dict['usage']}"
            )


class TestSchemaObjectClass:
    """Test suite for SchemaObjectClass class."""

    def test_schema_object_class_initialization(self) -> None:
        """Test SchemaObjectClass initialization with defaults."""
        oc = SchemaObjectClass(
            oid="2.5.6.6",
            names=["person"],
            description="A person",
        )

        if oc.oid != "2.5.6.6":
            raise AssertionError(f"Expected {'2.5.6.6'}, got {oc.oid}")
        assert oc.names == ["person"]
        if oc.description != "A person":
            raise AssertionError(f"Expected {'A person'}, got {oc.description}")
        assert oc.object_class_type == ObjectClassType.STRUCTURAL
        if oc.superior_classes != []:
            raise AssertionError(f"Expected {[]}, got {oc.superior_classes}")
        assert oc.must_attributes == []
        if oc.may_attributes != []:
            raise AssertionError(f"Expected {[]}, got {oc.may_attributes}")

    def test_schema_object_class_primary_name(self) -> None:
        """Test primary name property."""
        # With names
        oc1 = SchemaObjectClass(oid="2.5.6.6", names=["person", "individual"])
        if oc1.primary_name != "person":
            raise AssertionError(f"Expected {'person'}, got {oc1.primary_name}")

        # Without names
        oc2 = SchemaObjectClass(oid="2.5.6.6")
        if oc2.primary_name != "2.5.6.6":
            raise AssertionError(f"Expected {'2.5.6.6'}, got {oc2.primary_name}")

    def test_schema_object_class_has_name(self) -> None:
        """Test has_name method."""
        oc = SchemaObjectClass(oid="2.5.6.6", names=["person", "individual"])

        if not (oc.has_name("person")):
            raise AssertionError(f"Expected True, got {oc.has_name('person')}")
        assert oc.has_name("PERSON") is True  # Case insensitive
        if not (oc.has_name("individual")):
            raise AssertionError(f"Expected True, got {oc.has_name('individual')}")
        if oc.has_name("unknown"):
            raise AssertionError(f"Expected False, got {oc.has_name('unknown')}")

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
        if "objectClass" not in must_attrs:  # From top
            raise AssertionError(f"Expected 'objectClass' in {must_attrs}")
        assert "sn" in must_attrs  # From person
        if "cn" not in must_attrs:  # From person
            raise AssertionError(f"Expected 'cn' in {must_attrs}")
        assert "description" in may_attrs  # From person
        if "telephoneNumber" not in may_attrs:  # From person
            raise AssertionError(f"Expected 'telephoneNumber' in {may_attrs}")
        assert "title" in may_attrs  # From organizationalPerson
        if "ou" not in may_attrs:  # From organizationalPerson
            raise AssertionError(f"Expected 'ou' in {may_attrs}")

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

        if oc_dict["oid"] != "2.5.6.6":
            raise AssertionError(f"Expected {'2.5.6.6'}, got {oc_dict['oid']}")
        assert oc_dict["names"] == ["person"]
        if oc_dict["description"] != "A person":
            raise AssertionError(f"Expected {'A person'}, got {oc_dict['description']}")
        assert oc_dict["object_class_type"] == "STRUCTURAL"
        if oc_dict["superior_classes"] != ["top"]:
            raise AssertionError(
                f"Expected {['top']}, got {oc_dict['superior_classes']}"
            )
        assert oc_dict["must_attributes"] == ["sn", "cn"]
        if oc_dict["may_attributes"] != ["description"]:
            raise AssertionError(
                f"Expected {['description']}, got {oc_dict['may_attributes']}"
            )


class TestSchemaDiscoveryResult:
    """Test suite for SchemaDiscoveryResult class."""

    def test_schema_discovery_result_initialization(self) -> None:
        """Test SchemaDiscoveryResult initialization with defaults."""
        result = SchemaDiscoveryResult()

        assert result.discovery_id is not None
        assert result.timestamp is not None
        if result.server_info != {}:
            raise AssertionError(f"Expected {{}}, got {result.server_info}")
        assert result.object_classes == {}
        if result.attributes != {}:
            raise AssertionError(f"Expected {{}}, got {result.attributes}")
        assert result.discovery_errors == []
        if result.cache_hit:
            raise AssertionError(f"Expected False, got {result.cache_hit}")

    def test_schema_discovery_result_successful(self) -> None:
        """Test is_successful property."""
        # Successful result
        result1 = SchemaDiscoveryResult()
        if not (result1.is_successful):
            raise AssertionError(f"Expected True, got {result1.is_successful}")

        # Failed result
        result2 = SchemaDiscoveryResult(discovery_errors=["Error 1", "Error 2"])
        if result2.is_successful:
            raise AssertionError(f"Expected False, got {result2.is_successful}")

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

        if result.total_elements != 4:
            raise AssertionError(f"Expected {4}, got {result.total_elements}")

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

        if result_dict["timestamp"] != timestamp.isoformat():
            raise AssertionError(
                f"Expected {timestamp.isoformat()}, got {result_dict['timestamp']}"
            )
        assert result_dict["server_info"] == {"vendor": "Test"}
        if "person" not in result_dict["object_classes"]:
            raise AssertionError(
                f"Expected {'person'} in {result_dict['object_classes']}"
            )
        assert "cn" in result_dict["attributes"]
        if result_dict["discovery_errors"] != ["error1"]:
            raise AssertionError(
                f"Expected {['error1']}, got {result_dict['discovery_errors']}"
            )
        if not (result_dict["cache_hit"]):
            raise AssertionError(f"Expected True, got {result_dict['cache_hit']}")
        if result_dict["discovery_duration_ms"] != 100:
            raise AssertionError(
                f"Expected {100}, got {result_dict['discovery_duration_ms']}"
            )
        assert result_dict["total_elements"] == EXPECTED_BULK_SIZE


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
        if not (result.data.is_successful):
            raise AssertionError(f"Expected True, got {result.data.is_successful}")
        assert result.data.total_elements > 0
        if "person" not in result.data.object_classes:
            raise AssertionError(f"Expected {'person'} in {result.data.object_classes}")
        assert "cn" in result.data.attributes
        if result.data.cache_hit:
            raise AssertionError(f"Expected False, got {result.data.cache_hit}")

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
        if result1.data.cache_hit:
            raise AssertionError(f"Expected False, got {result1.data.cache_hit}")

        # Second discovery - should be from cache
        result2 = await discovery_service.discover_schema(mock_connection)
        assert result2.is_success
        assert result2.data is not None
        if not (result2.data.cache_hit):
            raise AssertionError(f"Expected True, got {result2.data.cache_hit}")

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
        if result.data.cache_hit:
            raise AssertionError(f"Expected False, got {result.data.cache_hit}")

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
        if result1.data.cache_hit:
            raise AssertionError(f"Expected False, got {result1.data.cache_hit}")
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
        if not (result.data["is_valid"]):
            raise AssertionError(f"Expected True, got {result.data['is_valid']}")
        if len(result.data["errors"]) != 0:
            raise AssertionError(f"Expected {0}, got {len(result.data['errors'])}")
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
        if result.data["is_valid"]:
            raise AssertionError(f"Expected False, got {result.data['is_valid']}")
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
        if "unknownAttr" not in result.data["unknown_attributes"]:
            raise AssertionError(
                f"Expected {'unknownAttr'} in {result.data['unknown_attributes']}"
            )
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
        if result.data["is_valid"]:
            raise AssertionError(f"Expected False, got {result.data['is_valid']}")
        assert len(result.data["errors"]) > 0
        has_unknown_error = any(
            "Unknown object class" in error for error in result.data["errors"]
        )
        if not has_unknown_error:
            raise AssertionError(
                f"Expected 'Unknown object class' error in {result.data['errors']}"
            )

    def test_generate_cache_key(
        self,
        discovery_service: SchemaDiscoveryService,
        mock_connection: MagicMock,
    ) -> None:
        """Test cache key generation."""
        cache_key = discovery_service._generate_cache_key(mock_connection)
        if cache_key != "schema_ldap.example.com":
            raise AssertionError(
                f"Expected {'schema_ldap.example.com'}, got {cache_key}"
            )

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
        if len(service._schema_cache) != EXPECTED_BULK_SIZE:
            raise AssertionError(f"Expected {2}, got {len(service._schema_cache)}")

        # Adding third should remove oldest
        service._cache_schema("key3", result3)
        if len(service._schema_cache) != EXPECTED_BULK_SIZE:
            raise AssertionError(f"Expected {2}, got {len(service._schema_cache)}")
        if "key3" not in service._schema_cache:
            raise AssertionError(f"Expected {'key3'} in {service._schema_cache}")

    def test_cache_expiration(self, discovery_service: SchemaDiscoveryService) -> None:
        """Test cache expiration."""
        result = SchemaDiscoveryResult()

        # Cache with past timestamp to simulate expiration
        past_time = datetime.now(UTC) - timedelta(hours=2)
        discovery_service._schema_cache["test_key"] = (result, past_time)

        # Should return None for expired cache
        cached_result = discovery_service._get_cached_schema("test_key")
        assert cached_result is None
        if "test_key" not in discovery_service._schema_cache:
            raise AssertionError(
                f"Expected 'test_key' not to be in {discovery_service._schema_cache}"
            )

    def test_clear_cache(self, discovery_service: SchemaDiscoveryService) -> None:
        """Test cache clearing."""
        result = SchemaDiscoveryResult()
        discovery_service._cache_schema("test_key", result)

        if len(discovery_service._schema_cache) != 1:
            raise AssertionError(
                f"Expected {1}, got {len(discovery_service._schema_cache)}"
            )

        discovery_service.clear_cache()

        if len(discovery_service._schema_cache) != 0:
            raise AssertionError(
                f"Expected {0}, got {len(discovery_service._schema_cache)}"
            )

    def test_get_cache_stats(self, discovery_service: SchemaDiscoveryService) -> None:
        """Test cache statistics."""
        stats = discovery_service.get_cache_stats()

        if "cache_size" not in stats:
            raise AssertionError(f"Expected {'cache_size'} in {stats}")
        assert "max_cache_size" in stats
        if "cache_ttl_minutes" not in stats:
            raise AssertionError(f"Expected {'cache_ttl_minutes'} in {stats}")
        assert "discovery_history_size" in stats
        if stats["max_cache_size"] != 10:
            raise AssertionError(f"Expected {10}, got {stats['max_cache_size']}")
        assert stats["cache_ttl_minutes"] == 60

    def test_get_discovery_history(
        self,
        discovery_service: SchemaDiscoveryService,
    ) -> None:
        """Test discovery history tracking."""
        # Initially empty
        history = discovery_service.get_discovery_history()
        if len(history) != 0:
            raise AssertionError(f"Expected {0}, got {len(history)}")

        # Add some results to history
        result1 = SchemaDiscoveryResult()
        result2 = SchemaDiscoveryResult()
        discovery_service._discovery_history.extend([result1, result2])

        # Check history
        history = discovery_service.get_discovery_history()
        if len(history) != EXPECTED_BULK_SIZE:
            raise AssertionError(f"Expected {2}, got {len(history)}")

        # Test limit
        history_limited = discovery_service.get_discovery_history(limit=1)
        if len(history_limited) != 1:
            raise AssertionError(f"Expected {1}, got {len(history_limited)}")

    def test_enum_values(self) -> None:
        """Test enum value definitions."""
        # SchemaElementType
        if SchemaElementType.OBJECT_CLASS.value != "objectClass":
            raise AssertionError(
                f"Expected {'objectClass'}, got {SchemaElementType.OBJECT_CLASS.value}"
            )
        assert SchemaElementType.ATTRIBUTE_TYPE.value == "attributeType"

        # AttributeUsage
        if AttributeUsage.USER_APPLICATIONS.value != "userApplications":
            raise AssertionError(
                f"Expected {'userApplications'}, got {AttributeUsage.USER_APPLICATIONS.value}"
            )
        assert AttributeUsage.DIRECTORY_OPERATION.value == "directoryOperation"

        # ObjectClassType
        if ObjectClassType.STRUCTURAL.value != "STRUCTURAL":
            raise AssertionError(
                f"Expected {'STRUCTURAL'}, got {ObjectClassType.STRUCTURAL.value}"
            )
        assert ObjectClassType.ABSTRACT.value == "ABSTRACT"
        if ObjectClassType.AUXILIARY.value != "AUXILIARY":
            raise AssertionError(
                f"Expected {'AUXILIARY'}, got {ObjectClassType.AUXILIARY.value}"
            )
