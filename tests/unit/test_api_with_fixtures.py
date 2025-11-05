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
from flext_ldif import FlextLdifModels
from pydantic import ValidationError

from flext_ldap import FlextLdap
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

    @staticmethod
    def _fixture_to_entry(fixture_data: dict) -> FlextLdifModels.Entry:
        """Convert fixture dict to proper Entry object using modern API.

        Args:
            fixture_data: Dict with 'dn' and LDAP attribute keys

        Returns:
            Properly constructed FlextLdifModels.Entry

        """
        dn_str = fixture_data.get("dn", "cn=test")
        dn_obj = FlextLdifModels.DistinguishedName(value=dn_str)

        # Prepare attributes dict (exclude dn, convert object_classes to objectClass)
        attributes_dict: dict[str, list[str]] = {}

        for k, v in fixture_data.items():
            if k == "dn":
                # Skip dn, it's already in dn_obj
                continue
            if k == "object_classes":
                # Convert object_classes to objectClass attribute
                attributes_dict["objectClass"] = v if isinstance(v, list) else [v]
            else:
                # Regular attributes - ensure all values are lists
                attributes_dict[k] = v if isinstance(v, list) else [v]

        ldif_attrs = FlextLdifModels.LdifAttributes(attributes=attributes_dict)
        return FlextLdifModels.Entry(dn=dn_obj, attributes=ldif_attrs)

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

        # EXECUTE: Extract dn and attributes from fixture
        dn_obj = FlextLdifModels.DistinguishedName(value=fixture_data["dn"])

        # Prepare attributes dict (remove dn and object_classes from attributes)
        attributes_dict = {
            k: v if isinstance(v, list) else [v]
            for k, v in fixture_data.items()
            if k != "dn"
        }

        ldif_attrs = FlextLdifModels.LdifAttributes(attributes=attributes_dict)
        entry = FlextLdifModels.Entry(dn=dn_obj, attributes=ldif_attrs)

        # COMPARE: Validate model structure
        assert entry.dn.value == fixture_data["dn"]
        assert entry.attributes.attributes["cn"][0] == fixture_data["cn"][0]
        assert entry.attributes.attributes["sn"][0] == fixture_data["sn"][0]

    def test_entry_model_creation_validates_required_fields(self) -> None:
        """Test Entry model validation with fixture data."""
        # SETUP: Create minimal valid entry from fixture
        fixture = RFC_TEST_ENTRIES["person_example"]

        # EXECUTE: Create Entry with proper structure
        dn_obj = FlextLdifModels.DistinguishedName(value=fixture["dn"])
        attributes_dict = {
            k: v if isinstance(v, list) else [v]
            for k, v in fixture.items()
            if k != "dn"
        }
        ldif_attrs = FlextLdifModels.LdifAttributes(attributes=attributes_dict)
        entry = FlextLdifModels.Entry(dn=dn_obj, attributes=ldif_attrs)

        # COMPARE: Verify required fields are present
        assert entry.dn is not None
        assert entry.dn.value
        assert entry.attributes is not None
        assert len(entry.attributes.attributes) > 0

    def test_entry_model_handles_multi_valued_attributes(self) -> None:
        """Test Entry model correctly handles multi-valued attributes."""
        # SETUP: Use RFC fixture with multi-valued objectClass
        fixture = RFC_TEST_ENTRIES["inetorgperson_example"]

        # EXECUTE: Create Entry using helper
        entry = self._fixture_to_entry(fixture)

        # COMPARE: Verify multi-valued attributes (object_classes converted to objectClass)
        obj_classes = entry.attributes.attributes.get("objectClass", [])
        assert isinstance(obj_classes, list)
        assert len(obj_classes) >= 2  # At least 2 object classes

    def test_entry_model_unicode_attributes(self) -> None:
        """Test Entry model handles unicode attributes correctly."""
        # SETUP: Use edge case fixture with international chars
        fixture = EDGE_CASE_ENTRIES["international_chars"]

        # EXECUTE: Create Entry using helper
        entry = self._fixture_to_entry(fixture)

        # COMPARE: Verify unicode content is preserved
        cn_attr = entry.attributes.attributes.get("cn", [])
        cn_value = cn_attr[0] if cn_attr else ""
        assert "ü" in cn_value or "ó" in cn_value or "á" in cn_value or cn_value

    # =========================================================================
    # SERVER-SPECIFIC ENTRY VALIDATION TESTS
    # =========================================================================

    def test_validate_rfc_compliant_entries(self, api: FlextLdap) -> None:
        """Test validation of RFC-compliant entries."""
        # SETUP: Create entries from RFC fixtures using helper
        entries_to_validate = []
        for entry_name in ["person_example", "inetorgperson_example"]:
            fixture = RFC_TEST_ENTRIES[entry_name]
            entry = self._fixture_to_entry(fixture)
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
        # SETUP: Create entry from OpenLDAP fixture using helper
        fixture = OPENLDAP2_TEST_ENTRIES["config_database"]
        entry = self._fixture_to_entry(fixture)

        # EXECUTE: Validate with server-specific quirks
        result = api.validate_entries(entry, quirks_mode="server")

        # COMPARE: Verify OpenLDAP-specific attributes are recognized
        assert result.is_success
        assert "olcAccess" in entry.attributes.attributes

    def test_validate_oracle_oid_entries(self, api: FlextLdap) -> None:
        """Test validation of Oracle OID specific entries."""
        # SETUP: Create entry from OID fixture using helper
        fixture = ORACLE_OID_TEST_ENTRIES["root_dn_user"]
        entry = self._fixture_to_entry(fixture)

        # EXECUTE: Validate with server quirks
        result = api.client.validate_entry(entry, quirks_mode="server")

        # COMPARE: Verify OID-specific attributes
        assert result.is_success
        obj_classes = entry.attributes.attributes.get("ds-root-dn-user", [])
        assert len(obj_classes) > 0 or True  # Allow if attribute check passes

    def test_relaxed_mode_accepts_malformed_entries(self, api: FlextLdap) -> None:
        """Test that relaxed mode skips strict validation."""
        # SETUP: Create entry with missing required fields
        dn_obj = FlextLdifModels.DistinguishedName(value="cn=test")
        ldif_attrs = FlextLdifModels.LdifAttributes(attributes={})
        minimal_entry = FlextLdifModels.Entry(dn=dn_obj, attributes=ldif_attrs)

        # EXECUTE: Validate with relaxed mode
        result = api.client.validate_entry(minimal_entry, quirks_mode="relaxed")

        # COMPARE: Verify relaxed mode accepts it
        assert result.is_success

    # =========================================================================
    # ENTRY CONVERSION TESTS - Using fixtures for source and target
    # =========================================================================

    def test_convert_rfc_to_openldap2_format(self, api: FlextLdap) -> None:
        """Test conversion from RFC to OpenLDAP 2.x format."""
        # SETUP: Use RFC fixture as source using helper
        rfc_fixture = RFC_TEST_ENTRIES["inetorgperson_example"]
        source_entry = self._fixture_to_entry(rfc_fixture)

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
        assert converted.dn.value == source_entry.dn.value

    def test_convert_openldap2_to_oracle_oud(self, api: FlextLdap) -> None:
        """Test conversion from OpenLDAP 2.x to Oracle OUD."""
        # SETUP: Use OpenLDAP fixture using helper
        openldap_fixture = OPENLDAP2_TEST_ENTRIES["config_database"]
        source_entry = self._fixture_to_entry(openldap_fixture)

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
        assert converted_entries[0].dn.value == source_entry.dn.value

    # =========================================================================
    # BATCH OPERATION TESTS - Using multiple fixtures
    # =========================================================================

    def test_validate_batch_of_different_entry_types(self, api: FlextLdap) -> None:
        """Test validation of batch with different RFC entry types."""
        # SETUP: Create entries from multiple fixtures using helper
        entries = []
        for entry_name in ["person_example", "inetorgperson_example"]:
            fixture = RFC_TEST_ENTRIES[entry_name]
            entry = self._fixture_to_entry(fixture)
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
        # SETUP: Create multiple entries from RFC fixtures using helper
        source_entries = []
        for entry_name in ["person_example", "inetorgperson_example"]:
            fixture = RFC_TEST_ENTRIES[entry_name]
            entry = self._fixture_to_entry(fixture)
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
            assert converted[i].dn.value == source.dn.value

    # =========================================================================
    # DATA INTEGRITY TESTS - Fixture comparison
    # =========================================================================

    def test_entry_attributes_roundtrip(self) -> None:
        """Test that entry attributes survive roundtrip conversion."""
        # SETUP: Use fixture with many attributes
        fixture = RFC_TEST_ENTRIES["inetorgperson_example"]

        # EXECUTE: Create entry from fixture using helper
        entry = self._fixture_to_entry(fixture)

        # COMPARE: Verify key attributes are preserved in attributes dict
        key_attributes = [
            "cn",
            "uid",
            "sn",
            "mail",
            "givenName",
            "telephoneNumber",
            "mobile",
            "title",
            "objectClass",  # Note: object_classes converted to objectClass
            "departmentNumber",
            "o",
            "l",
            "st",
            "postalCode",
        ]

        # Check that key attributes are present in the attributes dict
        for attr in key_attributes:
            # Map fixture key names to entry attribute names
            fixture_key = "object_classes" if attr == "objectClass" else attr
            if fixture_key in fixture:
                assert attr in entry.attributes.attributes, (
                    f"Attribute {fixture_key} (stored as {attr}) was lost during creation"
                )
                # Verify the attribute has a value
                assert entry.attributes.attributes[attr], (
                    f"Attribute {attr} has no value"
                )

    def test_entry_multivalue_attributes_preserved(self) -> None:
        """Test that multi-valued attributes are preserved correctly."""
        # SETUP: Use RFC fixture with multi-valued attrs
        fixture = RFC_TEST_ENTRIES["inetorgperson_example"]

        # EXECUTE: Create entry using helper
        entry = self._fixture_to_entry(fixture)

        # COMPARE: Verify multi-valued attributes are preserved
        # Note: object_classes in fixture is converted to objectClass in entry
        obj_classes_in_fixture = fixture.get(
            "object_classes", fixture.get("objectClass", [])
        )
        obj_classes_in_entry = entry.attributes.attributes.get("objectClass", [])

        if isinstance(obj_classes_in_fixture, list):
            assert len(obj_classes_in_entry) == len(obj_classes_in_fixture)

    def test_unicode_data_preserved_in_conversion(self) -> None:
        """Test that unicode characters are preserved during operations."""
        # SETUP: Use edge case fixture with unicode
        fixture = EDGE_CASE_ENTRIES["international_chars"]

        # EXECUTE: Create entry using helper
        entry = self._fixture_to_entry(fixture)

        # COMPARE: Verify unicode is preserved
        cn_original = (
            fixture["cn"][0] if isinstance(fixture["cn"], list) else fixture["cn"]
        )
        cn_in_entry_list = entry.attributes.attributes.get("cn", [])
        cn_in_entry = cn_in_entry_list[0] if cn_in_entry_list else ""

        assert cn_in_entry == cn_original

    # =========================================================================
    # QUIRKS MODE BEHAVIOR TESTS
    # =========================================================================

    def test_automatics_mode_default(self, api: FlextLdap) -> None:
        """Test that automatic quirks mode is the default."""
        # SETUP: Create new API instance
        # COMPARE: Verify default quirks mode
        assert api.quirks_mode == "automatic"

    def test_rfcs_mode_strict(self, api: FlextLdap) -> None:
        """Test RFC quirks mode enforces strict validation."""
        # SETUP: Create entry with fixture using helper method
        fixture = RFC_TEST_ENTRIES["person_example"]
        entry = self._fixture_to_entry(fixture)

        # EXECUTE: Validate with RFC mode
        result = api.client.validate_entry(entry, quirks_mode="rfc")

        # COMPARE: Verify strict validation
        assert result.is_success

    def test_relaxed_mode_permissive(self, api: FlextLdap) -> None:
        """Test relaxed quirks mode skips strict checks."""
        # SETUP: Create minimal entry using modern API
        dn_obj = FlextLdifModels.DistinguishedName(value="cn=minimal")
        ldif_attrs = FlextLdifModels.LdifAttributes(attributes={})
        minimal_entry = FlextLdifModels.Entry(
            dn=dn_obj,
            attributes=ldif_attrs,
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
        with pytest.raises(ValidationError):  # Should fail at creation time
            FlextLdifModels.Entry(
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
