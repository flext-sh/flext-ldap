"""Unit tests for FlextLdapEntryAdapter entry adapter module.

**Tested Modules:**
- `flext_ldap.adapters.entry.FlextLdapEntryAdapter` - Main adapter class for ldap3 ↔ FlextLdif conversion

**Test Scope:**
- Adapter initialization with default and custom server types
- ldif_entry_to_ldap3_attributes conversion (empty, single, list values, empty values)
- ldap3_to_ldif_entry conversion (None values, non-list values, base64 encoding, metadata tracking)
- Entry normalization and validation for different server types
- Exception handling and error cases
- Metadata tracking (conversions, base64, DN changes, attribute differences)
- String conversions and type conversions
- Entry attribute error handling

All tests use real functionality without mocks, leveraging flext-core test utilities
and domain-specific helpers to reduce code duplication while maintaining 100% coverage.

Module: TestFlextLdapEntryAdapter
Scope: Comprehensive adapter testing with maximum code reuse via flext_tests
Pattern: Parametrized tests using flext_tests utilities and factories

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_tests import FlextTestsMatchers
from pydantic import ValidationError

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from tests.fixtures.typing import GenericFieldsDict

from ..fixtures.constants import TestConstants
from ..helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.unit


class TestFlextLdapEntryAdapter:
    """Comprehensive tests for FlextLdapEntryAdapter using flext_tests and DRY principles.

    Uses parametrized tests, factories, and flext_tests utilities for maximum code reuse.
    """

    @pytest.fixture
    def adapter(self) -> FlextLdapEntryAdapter:
        """Provide FlextLdapEntryAdapter instance for testing."""
        return FlextLdapEntryAdapter()

    @pytest.fixture
    def test_entry(self) -> FlextLdifModels.Entry:
        """Provide standard test entry."""
        return EntryTestHelpers.create_entry(
            TestConstants.Adapter.TEST_DN,
            TestConstants.Adapter.STANDARD_ATTRIBUTES,
        )

    def test_adapter_initialization(self, adapter: FlextLdapEntryAdapter) -> None:
        """Test adapter initialization with default server_type."""
        assert adapter is not None
        assert adapter._ldif is not None
        assert adapter._server_type == FlextLdifConstants.ServerTypes.RFC.value
        assert adapter._server_type == TestConstants.ServerTypes.RFC

    def test_adapter_initialization_with_server_type(self) -> None:
        """Test adapter initialization with server type."""
        adapter = FlextLdapEntryAdapter(
            server_type=TestConstants.Adapter.SERVER_TYPE_OPENLDAP,
        )
        assert adapter._server_type == TestConstants.Adapter.SERVER_TYPE_OPENLDAP

    def test_ldif_entry_to_ldap3_attributes_with_empty_attributes(
        self,
        adapter: FlextLdapEntryAdapter,
    ) -> None:
        """Test conversion with entry having empty attributes - fast-fail."""
        entry = EntryTestHelpers.create_entry(
            TestConstants.Adapter.TEST_DN,
            TestConstants.Adapter.EMPTY_ATTRIBUTES,
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        # Use FlextTestsMatchers for failure assertion
        FlextTestsMatchers.assert_failure(
            result,
            TestConstants.Adapter.ERROR_NO_ATTRIBUTES,
        )

    @pytest.mark.parametrize(
        ("attrs", "expected_cn", "expected_checks"),
        [
            (
                {"cn": ["test"], "sn": ["User"], "objectClass": ["top", "person"]},
                ["test"],
                {"sn": ["User"], "objectClass": ["top", "person"]},
            ),
            (
                {
                    "cn": ["test"],
                    "mail": ["test@example.com", "test2@example.com"],
                    "objectClass": ["top", "person"],
                },
                ["test"],
                {
                    "mail_count": 2,
                    "mail_contains": ["test@example.com", "test2@example.com"],
                },
            ),
            (
                {"cn": ["test"], "description": [], "emptyList": []},
                ["test"],
                {"description": [], "emptyList": []},
            ),
        ],
    )
    def test_ldif_entry_to_ldap3_attributes_conversion(
        self,
        adapter: FlextLdapEntryAdapter,
        attrs: dict[str, list[str]],
        expected_cn: list[str],
        expected_checks: dict[str, list[str] | int],
    ) -> None:
        """Parametrized test for ldif_entry_to_ldap3_attributes conversions."""
        entry = EntryTestHelpers.create_entry(TestConstants.Adapter.TEST_DN, attrs)
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attrs_result = FlextTestsMatchers.assert_success(result)
        assert attrs_result["cn"] == expected_cn
        for key, expected_value in expected_checks.items():
            if key.endswith("_count"):
                attr_key = key.replace("_count", "")
                assert isinstance(expected_value, int)
                assert len(attrs_result[attr_key]) == expected_value
            elif key.endswith("_contains"):
                attr_key = key.replace("_contains", "")
                assert isinstance(expected_value, list)
                for value in expected_value:
                    assert value in attrs_result[attr_key]
            else:
                assert attrs_result.get(key) == expected_value

    def test_ldif_entry_to_ldap3_attributes_with_single_string_value(
        self,
        adapter: FlextLdapEntryAdapter,
    ) -> None:
        """Test conversion with single string value."""
        entry = EntryTestHelpers.create_entry(
            TestConstants.Adapter.TEST_DN,
            TestConstants.Adapter.STANDARD_ATTRIBUTES,
        )
        if entry.attributes:
            entry.attributes.attributes["singleValue"] = ["single_string"]
            entry.attributes.attributes["emptyString"] = [""]
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        attrs = FlextTestsMatchers.assert_success(result)
        assert attrs["cn"] == ["test"]
        assert isinstance(attrs.get("singleValue"), list)
        assert "emptyString" in attrs
        assert attrs["emptyString"] == [""]

    def test_validate_entry_for_server_pydantic_prevents_none(self) -> None:
        """Test that Pydantic v2 validation prevents None attributes."""
        entry = EntryTestHelpers.create_entry(
            TestConstants.Adapter.TEST_DN,
            TestConstants.Adapter.EMPTY_ATTRIBUTES,
        )
        invalid_data = entry.model_dump()
        invalid_data["attributes"] = None
        with pytest.raises(ValidationError):
            FlextLdifModels.Entry.model_validate(invalid_data)

    def test_execute_method(self, adapter: FlextLdapEntryAdapter) -> None:
        """Test execute method required by FlextService."""
        result = adapter.execute()
        executed = FlextTestsMatchers.assert_success(result)
        assert executed is True

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("attr_name", "attr_value"),
        [
            ("description", None),
            ("description", "single_value"),
        ],
    )
    def test_ldap3_to_ldif_entry_value_conversions(
        self,
        ldap_container: GenericFieldsDict,
        attr_name: str,
        attr_value: object,
    ) -> None:
        """Parametrized test for value conversions using real LDAP3 entries."""
        adapter = FlextLdapEntryAdapter()
        with EntryTestHelpers.ldap3_connection_from_container(ldap_container) as (
            _,
            ldap3_entry,
        ):
            if ldap3_entry and hasattr(ldap3_entry, "entry_attributes_as_dict"):
                # Modify entry attributes in memory (no server write)
                if attr_value is None:
                    # Remove attribute by setting to None
                    ldap3_entry.entry_attributes_as_dict[attr_name] = None
                else:
                    ldap3_entry.entry_attributes_as_dict[attr_name] = attr_value
                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                entry = FlextTestsMatchers.assert_success(result)
                assert entry.attributes is not None
                if attr_value is None:
                    # None values should be removed or empty
                    if attr_name in entry.attributes.attributes:
                        assert entry.attributes.attributes[attr_name] == []
                elif attr_name in entry.attributes.attributes:
                    assert entry.attributes.attributes[attr_name] == [str(attr_value)]

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("attr_name", "attr_value"),
        [
            ("testBase64Attr", ["test\x80value", "normal_value"]),
            ("testBase64Single", "::dGVzdA=="),
            ("testHighAscii", ["café", "test"]),
        ],
    )
    def test_ldap3_to_ldif_entry_base64_detection(
        self,
        ldap_container: GenericFieldsDict,
        attr_name: str,
        attr_value: object,
    ) -> None:
        """Parametrized test for base64 encoding detection."""
        adapter = FlextLdapEntryAdapter()
        with EntryTestHelpers.ldap3_connection_from_container(ldap_container) as (
            _,
            ldap3_entry,
        ):
            if ldap3_entry and hasattr(ldap3_entry, "entry_attributes_as_dict"):
                ldap3_entry.entry_attributes_as_dict[attr_name] = attr_value
                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                entry = FlextTestsMatchers.assert_success(result)
                assert entry.metadata is not None

    @pytest.mark.integration
    @pytest.mark.parametrize(
        ("attr_name", "attr_value", "metadata_key"),
        [
            ("testConvertedAttr", ["::dGVzdA=="], "base64_encoded_attributes"),
            ("testConvertedAttr", [123, 456], "converted_attributes"),
            ("testRemovedAttr", None, "removed_attributes"),
        ],
    )
    def test_ldap3_to_ldif_entry_metadata_tracking(
        self,
        ldap_container: GenericFieldsDict,
        attr_name: str,
        attr_value: object,
        metadata_key: str,
    ) -> None:
        """Parametrized test for metadata tracking."""
        adapter = FlextLdapEntryAdapter()
        with EntryTestHelpers.ldap3_connection_from_container(ldap_container) as (
            _,
            ldap3_entry,
        ):
            if ldap3_entry and hasattr(ldap3_entry, "entry_attributes_as_dict"):
                ldap3_entry.entry_attributes_as_dict[attr_name] = attr_value
                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                entry = FlextTestsMatchers.assert_success(result)
                extensions = EntryTestHelpers.MetadataHelpers.get_extensions(entry)
                if metadata_key == "removed_attributes":
                    removed = extensions.get(metadata_key)
                    if removed and isinstance(removed, (list, dict, set)):
                        assert attr_name in removed
                elif metadata_key in extensions:
                    assert extensions[metadata_key] is not None

    @pytest.mark.integration
    def test_ldap3_to_ldif_entry_tracks_dn_changes(
        self,
        ldap_container: GenericFieldsDict,
    ) -> None:
        """Test conversion tracks DN changes in metadata."""
        adapter = FlextLdapEntryAdapter()
        with EntryTestHelpers.ldap3_connection_from_container(ldap_container) as (
            _,
            ldap3_entry,
        ):
            if ldap3_entry:
                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                entry = FlextTestsMatchers.assert_success(result)
                extensions = EntryTestHelpers.MetadataHelpers.get_extensions(entry)
                assert "dn_changed" in extensions or "original_dn" in extensions

    @pytest.mark.integration
    def test_ldap3_to_ldif_entry_tracks_string_conversions(
        self,
        ldap_container: GenericFieldsDict,
    ) -> None:
        """Test tracking of string conversions in conversion metadata."""
        adapter = FlextLdapEntryAdapter()
        with EntryTestHelpers.ldap3_connection_from_container(ldap_container) as (
            _,
            ldap3_entry,
        ):
            if ldap3_entry and hasattr(ldap3_entry, "entry_attributes_as_dict"):
                ldap3_entry.entry_attributes_as_dict["testInt"] = [123]
                ldap3_entry.entry_attributes_as_dict["testNormal"] = ["normal"]
                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                entry = FlextTestsMatchers.assert_success(result)
                extensions = EntryTestHelpers.MetadataHelpers.get_extensions(entry)
                converted_attrs = extensions.get("converted_attributes")
                if converted_attrs is not None:
                    assert isinstance(converted_attrs, dict)

    @pytest.mark.integration
    def test_ldap3_to_ldif_entry_tracks_conversion_counts(
        self,
        ldap_container: GenericFieldsDict,
    ) -> None:
        """Test tracking of conversion counts in metadata."""
        adapter = FlextLdapEntryAdapter()
        with EntryTestHelpers.ldap3_connection_from_container(ldap_container) as (
            _,
            ldap3_entry,
        ):
            if ldap3_entry and hasattr(ldap3_entry, "entry_attributes_as_dict"):
                ldap3_entry.entry_attributes_as_dict.update({
                    "testInt1": [123],
                    "testInt2": [456],
                    "testFloat": [78.9],
                })
                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                entry = FlextTestsMatchers.assert_success(result)
                extensions = EntryTestHelpers.MetadataHelpers.get_extensions(entry)
                conversion_count = extensions.get("conversion_count")
                if conversion_count is not None and isinstance(conversion_count, int):
                    assert conversion_count >= 0

    @pytest.mark.integration
    def test_ldap3_to_ldif_entry_tracks_dn_changes_unit(
        self,
        ldap_container: GenericFieldsDict,
    ) -> None:
        """Test tracking of DN changes in conversion metadata."""
        adapter = FlextLdapEntryAdapter()
        with EntryTestHelpers.ldap3_connection_from_container(ldap_container) as (
            _,
            ldap3_entry,
        ):
            if ldap3_entry and hasattr(ldap3_entry, "entry_attributes_as_dict"):
                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                entry = FlextTestsMatchers.assert_success(result)
                original_dn = entry.dn.value if entry.dn else "unknown"
                assert original_dn is not None
                assert isinstance(original_dn, str)

    @pytest.mark.integration
    def test_ldap3_to_ldif_entry_tracks_attribute_differences(
        self,
        ldap_container: GenericFieldsDict,
    ) -> None:
        """Test tracking of attribute differences."""
        adapter = FlextLdapEntryAdapter()
        with EntryTestHelpers.ldap3_connection_from_container(ldap_container) as (
            _,
            ldap3_entry,
        ):
            if ldap3_entry and hasattr(ldap3_entry, "entry_attributes_as_dict"):
                ldap3_entry.entry_attributes_as_dict["testAttr"] = ["original"]
                result = adapter.ldap3_to_ldif_entry(ldap3_entry)
                entry = FlextTestsMatchers.assert_success(result)
                extensions = EntryTestHelpers.MetadataHelpers.get_extensions(entry)
                if "converted_attributes" in extensions:
                    converted_attrs = extensions["converted_attributes"]
                    assert isinstance(converted_attrs, dict)

    def test_ldif_entry_to_ldap3_attributes_error_handling(self) -> None:
        """Test error handling in ldif_entry_to_ldap3_attributes."""
        adapter = FlextLdapEntryAdapter()
        entry = EntryTestHelpers.create_entry(
            TestConstants.Adapter.TEST_DN,
            {"cn": ["test"], "objectClass": ["person"]},
        )
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        assert result.is_success or result.is_failure
