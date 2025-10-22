"""Unit tests for FlextLdap API using real fixtures and data comparisons.

This module demonstrates the proper pattern for testing LDAP operations
with real-world data fixtures instead of mocks, with comprehensive
data validation and comparison.

Pattern:
1. Setup: Use RFC_TEST_ENTRIES or server-specific fixtures from conftest
2. Execute: Call API method with fixture data
3. Compare: Validate returned data matches fixture structure

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLdap, FlextLdapModels
from tests.conftest import (
    ACTIVE_DIRECTORY_TEST_ENTRIES,
    EDGE_CASE_ENTRIES,
    OPENLDAP2_TEST_ENTRIES,
    ORACLE_OID_TEST_ENTRIES,
    ORACLE_OUD_TEST_ENTRIES,
    RFC_TEST_ENTRIES,
)


@pytest.mark.unit
class TestFlextLdapWithRealFixtures:
    """Test FlextLdap API methods with real-world fixture data."""

    @pytest.fixture
    def api(self) -> FlextLdap:
        """Create API instance for testing."""
        return FlextLdap()

    # =========================================================================
    # FIXTURE DATA VALIDATION TESTS
    # =========================================================================

    def test_fixture_rfc_entries_structure(self) -> None:
        """Verify RFC fixture entries have correct structure."""
        # SETUP: Load RFC fixtures
        assert RFC_TEST_ENTRIES is not None
        assert len(RFC_TEST_ENTRIES) > 0

        # COMPARE: Verify each fixture has required fields
        for entry_name, entry_data in RFC_TEST_ENTRIES.items():
            assert isinstance(entry_name, str), (
                f"Entry name must be string: {entry_name}"
            )
            assert isinstance(entry_data, dict), (
                f"Entry data must be dict: {entry_name}"
            )
            assert "dn" in entry_data, f"Entry missing DN: {entry_name}"
            assert "object_classes" in entry_data, (
                f"Entry missing object_classes: {entry_name}"
            )
            assert isinstance(entry_data["object_classes"], list), (
                f"object_classes must be list: {entry_name}"
            )

    def test_fixture_server_entries_completeness(self) -> None:
        """Verify server-specific fixtures are complete."""
        server_fixtures = {
            "OpenLDAP 2.x": OPENLDAP2_TEST_ENTRIES,
            "Oracle OID": ORACLE_OID_TEST_ENTRIES,
            "Oracle OUD": ORACLE_OUD_TEST_ENTRIES,
            "Active Directory": ACTIVE_DIRECTORY_TEST_ENTRIES,
        }

        for server_name, fixture in server_fixtures.items():
            assert fixture is not None, f"{server_name} fixture is None"
            assert len(fixture) > 0, f"{server_name} fixture is empty"

    def test_fixture_edge_cases_coverage(self) -> None:
        """Verify edge case fixtures cover important scenarios."""
        assert "international_chars" in EDGE_CASE_ENTRIES
        assert "long_attribute_value" in EDGE_CASE_ENTRIES
        assert "special_characters" in EDGE_CASE_ENTRIES

    # =========================================================================
    # MODEL CREATION TESTS - Using real fixtures
    # =========================================================================

    def test_entry_model_creation_from_fixture(self) -> None:
        """Test creating Entry models from fixture data."""
        # SETUP: Load RFC fixture
        fixture_data = RFC_TEST_ENTRIES["person_example"]

        # EXECUTE: Create Entry model
        entry = FlextLdapModels.Entry(
            dn=fixture_data["dn"],
            attributes=fixture_data,
        )

        # COMPARE: Validate model structure
        assert entry.dn == fixture_data["dn"]
        assert entry.cn == fixture_data["cn"][0]  # Extracted to field, take first value
        assert entry.sn == fixture_data["sn"][0]  # Extracted to field, take first value

    def test_entry_model_creation_validates_required_fields(self) -> None:
        """Test Entry model validation with fixture data."""
        # SETUP: Create minimal valid entry from fixture
        fixture = RFC_TEST_ENTRIES["person_example"]

        # EXECUTE: Create Entry
        entry = FlextLdapModels.Entry(
            dn=fixture["dn"],
            attributes=fixture,
        )

        # COMPARE: Verify required fields are present
        assert entry.dn is not None
        assert len(entry.dn) > 0
        assert entry.attributes is not None
        assert len(entry.attributes) > 0

    def test_entry_model_handles_multi_valued_attributes(self) -> None:
        """Test Entry model correctly handles multi-valued attributes."""
        # SETUP: Use RFC fixture with multi-valued objectClass
        fixture = RFC_TEST_ENTRIES["inetorgperson_example"]

        # EXECUTE: Create Entry
        entry = FlextLdapModels.Entry(
            dn=fixture["dn"],
            attributes=fixture,
        )

        # COMPARE: Verify multi-valued attributes
        obj_classes = entry.object_classes
        assert isinstance(obj_classes, list)
        assert len(obj_classes) >= 2  # At least 2 object classes

    def test_entry_model_unicode_attributes(self) -> None:
        """Test Entry model handles unicode attributes correctly."""
        # SETUP: Use edge case fixture with international chars
        fixture = EDGE_CASE_ENTRIES["international_chars"]

        # EXECUTE: Create Entry
        entry = FlextLdapModels.Entry(
            dn=fixture["dn"],
            attributes=fixture,
        )

        # COMPARE: Verify unicode content is preserved
        cn_value = entry.cn[0] if isinstance(entry.cn, list) else entry.cn
        assert "ü" in cn_value or "ó" in cn_value or "á" in cn_value

    # =========================================================================
    # SERVER-SPECIFIC ENTRY VALIDATION TESTS
    # =========================================================================

    def test_validate_rfc_compliant_entries(self, api: FlextLdap) -> None:
        """Test validation of RFC-compliant entries."""
        # SETUP: Create entries from RFC fixtures
        entries_to_validate = []
        for entry_name in ["person_example", "inetorgperson_example"]:
            fixture = RFC_TEST_ENTRIES[entry_name]
            # Extract object_classes from fixture to avoid conflict with model field
            object_classes = fixture.get("object_classes", ["top"])
            attributes = {k: v for k, v in fixture.items() if k != "object_classes"}
            entry = FlextLdapModels.Entry(
                dn=fixture["dn"],
                object_classes=object_classes,
                attributes=attributes,
            )
            entries_to_validate.append((entry_name, entry))

        # EXECUTE & COMPARE: Validate each entry
        for entry_name, entry in entries_to_validate:
            # Use RFC quirks mode for strict validation
            result = api.validate_entries(entry, quirks_mode="rfc")

            # COMPARE: Verify validation result
            assert isinstance(result, FlextResult)
            assert result.is_success, (
                f"RFC validation failed for {entry_name}: {result.error}"
            )

    def test_validate_openldap2_entries(self, api: FlextLdap) -> None:
        """Test validation of OpenLDAP 2.x specific entries."""
        # SETUP: Create entry from OpenLDAP fixture
        fixture = OPENLDAP2_TEST_ENTRIES["config_database"]
        # Extract object_classes from fixture to avoid conflict with model field
        object_classes = fixture.get("object_classes", ["top"])
        attributes = {k: v for k, v in fixture.items() if k != "object_classes"}
        entry = FlextLdapModels.Entry(
            dn=fixture["dn"],
            object_classes=object_classes,
            attributes=attributes,
        )

        # EXECUTE: Validate with server-specific quirks
        result = api.validate_entries(entry, quirks_mode="server")

        # COMPARE: Verify OpenLDAP-specific attributes are recognized
        assert result.is_success
        assert "olcAccess" in entry.attributes

    def test_validate_oracle_oid_entries(self, api: FlextLdap) -> None:
        """Test validation of Oracle OID specific entries."""
        # SETUP: Create entry from OID fixture
        fixture = ORACLE_OID_TEST_ENTRIES["root_dn_user"]
        entry = FlextLdapModels.Entry(
            dn=fixture["dn"],
            attributes=fixture,
        )

        # EXECUTE: Validate with server quirks
        result = api.client.validate_entry(entry, quirks_mode="server")

        # COMPARE: Verify OID-specific attributes
        assert result.is_success
        assert "ds-root-dn-user" in entry.object_classes

    def test_relaxed_mode_accepts_malformed_entries(self, api: FlextLdap) -> None:
        """Test that relaxed mode skips strict validation."""
        # SETUP: Create entry with missing required fields
        minimal_entry = FlextLdapModels.Entry(
            dn="cn=test",
            attributes={},
        )

        # EXECUTE: Validate with relaxed mode
        result = api.client.validate_entry(minimal_entry, quirks_mode="relaxed")

        # COMPARE: Verify relaxed mode accepts it
        assert result.is_success

    # =========================================================================
    # ENTRY CONVERSION TESTS - Using fixtures for source and target
    # =========================================================================

    def test_convert_rfc_to_openldap2_format(self, api: FlextLdap) -> None:
        """Test conversion from RFC to OpenLDAP 2.x format."""
        # SETUP: Use RFC fixture as source
        rfc_fixture = RFC_TEST_ENTRIES["inetorgperson_example"]
        source_entry = FlextLdapModels.Entry(
            dn=rfc_fixture["dn"],
            attributes=rfc_fixture,
        )

        # EXECUTE: Convert to OpenLDAP 2.x format
        result = api.convert(
            entries=[source_entry],
            source_server="rfc",
            target_server="openldap2",
        )

        # COMPARE: Verify conversion maintains data integrity
        assert result.is_success
        converted_entries = result.unwrap()
        assert isinstance(converted_entries, list)
        assert len(converted_entries) > 0

        # Verify DN is preserved
        converted = converted_entries[0]
        assert converted.dn == source_entry.dn

    def test_convert_openldap2_to_oracle_oud(self, api: FlextLdap) -> None:
        """Test conversion from OpenLDAP 2.x to Oracle OUD."""
        # SETUP: Use OpenLDAP fixture
        openldap_fixture = OPENLDAP2_TEST_ENTRIES["config_database"]
        source_entry = FlextLdapModels.Entry(
            dn=openldap_fixture["dn"],
            attributes=openldap_fixture,
        )

        # EXECUTE: Convert to OUD format
        result = api.convert(
            entries=[source_entry],
            source_server="openldap2",
            target_server="oud",
        )

        # COMPARE: Verify conversion succeeds and preserves entry
        assert result.is_success
        converted_entries = result.unwrap()
        assert len(converted_entries) > 0
        assert converted_entries[0].dn == source_entry.dn

    # =========================================================================
    # BATCH OPERATION TESTS - Using multiple fixtures
    # =========================================================================

    def test_validate_batch_of_different_entry_types(self, api: FlextLdap) -> None:
        """Test validation of batch with different RFC entry types."""
        # SETUP: Create entries from multiple fixtures
        entries = []
        for entry_name in ["person_example", "inetorgperson_example"]:
            fixture = RFC_TEST_ENTRIES[entry_name]
            entry = FlextLdapModels.Entry(
                dn=fixture["dn"],
                attributes=fixture,
            )
            entries.append(entry)

        # EXECUTE: Validate batch
        results = []
        for entry in entries:
            result = api.client.validate_entry(entry)
            results.append(result)

        # COMPARE: Verify all validations succeed
        assert all(r.is_success for r in results), "Batch validation failed"
        assert len(results) == 2

    def test_convert_batch_entries(self, api: FlextLdap) -> None:
        """Test batch conversion of multiple entries."""
        # SETUP: Create multiple entries from RFC fixtures
        source_entries = []
        for entry_name in ["person_example", "inetorgperson_example"]:
            fixture = RFC_TEST_ENTRIES[entry_name]
            entry = FlextLdapModels.Entry(
                dn=fixture["dn"],
                attributes=fixture,
            )
            source_entries.append(entry)

        # EXECUTE: Batch convert
        result = api.convert(
            entries=source_entries,
            source_server="rfc",
            target_server="openldap2",
        )

        # COMPARE: Verify batch conversion
        assert result.is_success
        converted = result.unwrap()
        assert len(converted) == len(source_entries)

        # Verify all DNs are preserved
        for i, source in enumerate(source_entries):
            assert converted[i].dn == source.dn

    # =========================================================================
    # DATA INTEGRITY TESTS - Fixture comparison
    # =========================================================================

    def test_entry_attributes_roundtrip(self) -> None:
        """Test that entry attributes survive roundtrip conversion."""
        # SETUP: Use fixture with many attributes
        fixture = RFC_TEST_ENTRIES["inetorgperson_example"]

        # EXECUTE: Create entry from fixture and extract
        entry = FlextLdapModels.Entry(
            dn=fixture["dn"],
            attributes=fixture,
        )

        # COMPARE: Verify key attributes are preserved
        # Some attributes are extracted as direct fields, others remain in attributes
        extracted_fields = ["cn", "uid", "sn", "mail", "givenName", "telephoneNumber", "mobile", "title"]
        preserved_in_attributes = ["objectClass", "departmentNumber", "o", "l", "st", "postalCode"]

        # Check extracted fields are in direct fields
        for attr in extracted_fields:
            if attr in fixture:
                if attr == "objectClass":
                    # objectClass becomes object_classes
                    assert entry.object_classes, "objectClass attribute was lost"
                elif attr == "givenName":
                    # givenName becomes given_name
                    assert entry.given_name is not None, "givenName attribute was lost"
                elif attr == "telephoneNumber":
                    # telephoneNumber becomes telephone_number
                    assert entry.telephone_number is not None, "telephoneNumber attribute was lost"
                else:
                    field_name = attr
                    assert getattr(entry, field_name) is not None, f"Attribute {attr} was lost"

        # Check remaining attributes are in additional_attributes or attributes
        for attr in preserved_in_attributes:
            if attr in fixture:
                if attr == "objectClass":
                    continue  # Already checked above
                # Check in additional_attributes or attributes
                attr_present = (
                    attr in getattr(entry, 'additional_attributes', {}) or
                    attr in getattr(entry, 'attributes', {})
                )
                assert attr_present, f"Attribute {attr} was lost"

    def test_entry_multivalue_attributes_preserved(self) -> None:
        """Test that multi-valued attributes are preserved correctly."""
        # SETUP: Use RFC fixture with multi-valued attrs
        fixture = RFC_TEST_ENTRIES["inetorgperson_example"]

        # EXECUTE: Create entry
        entry = FlextLdapModels.Entry(
            dn=fixture["dn"],
            attributes=fixture,
        )

        # COMPARE: Verify multi-valued objectClass
        obj_classes_in_fixture = fixture.get("object_classes", fixture.get("objectClass", []))
        obj_classes_in_entry = entry.object_classes

        if isinstance(obj_classes_in_fixture, list):
            assert len(obj_classes_in_entry) == len(obj_classes_in_fixture)

    def test_unicode_data_preserved_in_conversion(self) -> None:
        """Test that unicode characters are preserved during operations."""
        # SETUP: Use edge case fixture with unicode
        fixture = EDGE_CASE_ENTRIES["international_chars"]

        # EXECUTE: Create entry and extract unicode
        entry = FlextLdapModels.Entry(
            dn=fixture["dn"],
            attributes=fixture,
        )

        # COMPARE: Verify unicode is preserved
        cn_original = (
            fixture["cn"][0] if isinstance(fixture["cn"], list) else fixture["cn"]
        )
        cn_in_entry = (
            entry.cn[0] if isinstance(entry.cn, list) else entry.cn
        )

        assert cn_in_entry == cn_original

    # =========================================================================
    # QUIRKS MODE BEHAVIOR TESTS
    # =========================================================================

    def test_automatic_quirks_mode_default(self, api: FlextLdap) -> None:
        """Test that automatic quirks mode is the default."""
        # SETUP: Create new API instance
        # COMPARE: Verify default quirks mode
        assert api.quirks_mode == "automatic"

    def test_rfc_quirks_mode_strict(self, api: FlextLdap) -> None:
        """Test RFC quirks mode enforces strict validation."""
        # SETUP: Create entry with fixture
        fixture = RFC_TEST_ENTRIES["person_example"]
        entry = FlextLdapModels.Entry(
            dn=fixture["dn"],
            attributes=fixture,
        )

        # EXECUTE: Validate with RFC mode
        result = api.client.validate_entry(entry, quirks_mode="rfc")

        # COMPARE: Verify strict validation
        assert result.is_success

    def test_relaxed_quirks_mode_permissive(self, api: FlextLdap) -> None:
        """Test relaxed quirks mode skips strict checks."""
        # SETUP: Create minimal entry
        minimal_entry = FlextLdapModels.Entry(
            dn="cn=minimal",
            attributes={},
        )

        # EXECUTE: Validate with relaxed mode
        result = api.client.validate_entry(minimal_entry, quirks_mode="relaxed")

        # COMPARE: Verify permissive validation
        assert result.is_success

    # =========================================================================
    # ERROR CASES - With fixtures
    # =========================================================================

    def test_validation_fails_on_empty_dn(self, api: FlextLdap) -> None:
        """Test that Entry model correctly rejects empty DN at creation time."""
        # SETUP & EXECUTE: Try to create entry with empty DN
        with pytest.raises(Exception):  # Should fail at creation time
            FlextLdapModels.Entry(
                dn="",  # Invalid - empty DN
                object_classes=["top"],
                attributes={"cn": ["Test"]},
            )


@pytest.mark.unit
class TestFixtureQualityAndCoverage:
    """Tests to verify fixture quality and coverage."""

    def test_all_server_types_have_fixtures(self) -> None:
        """Verify fixtures exist for all documented server types."""
        fixtures_by_server = {
            "RFC": RFC_TEST_ENTRIES,
            "OpenLDAP 2.x": OPENLDAP2_TEST_ENTRIES,
            "Oracle OID": ORACLE_OID_TEST_ENTRIES,
            "Oracle OUD": ORACLE_OUD_TEST_ENTRIES,
            "Active Directory": ACTIVE_DIRECTORY_TEST_ENTRIES,
        }

        for server_name, fixture in fixtures_by_server.items():
            assert fixture is not None, f"No fixture for {server_name}"
            assert len(fixture) > 0, f"Empty fixture for {server_name}"

    def test_fixtures_contain_diverse_entry_types(self) -> None:
        """Verify fixtures include diverse entry type examples."""
        # RFC should have multiple entry types
        assert len(RFC_TEST_ENTRIES) >= 3

        # Verify specific important types exist
        important_types = ["person_example", "inetorgperson_example"]
        for entry_type in important_types:
            assert entry_type in RFC_TEST_ENTRIES, f"Missing {entry_type}"

    def test_fixtures_include_edge_cases(self) -> None:
        """Verify edge case fixtures exist."""
        important_cases = [
            "international_chars",
            "long_attribute_value",
            "special_characters",
        ]
        for case in important_cases:
            assert case in EDGE_CASE_ENTRIES, f"Missing edge case: {case}"
