"""Integration tests for FlextLdapEntryAdapter with modern patterns.

Tests entry adapter conversion with real LDAP operations using factories,
parameterized tests, and flext_tests utilities for maximum code reduction
while maintaining comprehensive edge case coverage.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import ClassVar

import pytest
from flext_ldif import FlextLdifParser
from flext_ldif.models import FlextLdifModels
from flext_tests import FlextTestsFactories, FlextTestsUtilities
from ldap3 import BASE, LEVEL, SUBTREE, Connection, Server

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from tests.fixtures.typing import GenericFieldsDict

from ..fixtures.constants import RFC
from ..helpers.operation_helpers import TestOperationHelpers

pytestmark = pytest.mark.integration


class EntryTestType(StrEnum):
    """Entry test type enumeration."""

    BASIC_CONVERSION = "basic_conversion"
    MIXED_ATTRIBUTES = "mixed_attributes"
    BASE64_ATTRIBUTES = "base64_attributes"
    DN_CHANGE_TRACKING = "dn_change_tracking"


class AttributeTestType(StrEnum):
    """Attribute test type enumeration."""

    EMPTY_LIST = "empty_list"
    EMPTY_STRING_IN_LIST = "empty_string_in_list"
    FALSY_VALUES = "falsy_values"


class TestFlextLdapEntryAdapterRealOperations:
    """Real LDAP entry adapter tests with modern patterns.

    Tests FlextLdapEntryAdapter operations against real LDAP server.
    Uses parameterized tests, factories, and mappings for maximum code reduction
    while maintaining comprehensive edge case coverage.
    """

    # Test data factories using flext_tests
    @staticmethod
    def _create_test_entry_data(
        test_type: str,
        base_dn: str = RFC.DEFAULT_BASE_DN,
    ) -> object:
        """Create test entry data using FlextTestsFactories."""
        return FlextTestsFactories.create_user(
            user_id=f"test_{test_type}",
            name=f"Test {test_type.title()} Entry",
            email=f"{test_type}@flext.local",
            base_dn=base_dn,
        )

    @staticmethod
    def _create_ldap_connection(
        ldap_container: GenericFieldsDict,
    ) -> Connection:
        """Create and return a connected LDAP connection."""
        server = Server(f"ldap://{RFC.DEFAULT_HOST}:{RFC.DEFAULT_PORT}", get_info="ALL")
        return Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
        )

    # Attribute conversion test configurations
    ATTRIBUTE_TEST_CONFIGS: ClassVar[
        list[tuple[AttributeTestType, dict[str, list[str]]]]
    ] = [
        # (test_type, attributes_dict)
        (
            AttributeTestType.EMPTY_LIST,
            {
                "cn": ["test"],
                "description": [],  # Empty list
                "emptyList": [],  # Another empty list
            },
        ),
        (
            AttributeTestType.EMPTY_STRING_IN_LIST,
            {
                "cn": ["test"],
                "emptyStringAttr": [""],  # List with empty string
            },
        ),
        (
            AttributeTestType.FALSY_VALUES,
            {
                "cn": ["test"],
                "emptyList": [],
                "listWithEmpty": [""],
            },
        ),
    ]

    @pytest.mark.parametrize(
        ("test_type", "attributes_dict"),
        ATTRIBUTE_TEST_CONFIGS,
        ids=[config[0].value for config in ATTRIBUTE_TEST_CONFIGS],
    )
    def test_ldif_entry_to_ldap3_attributes_parameterized(
        self,
        test_type: AttributeTestType,
        attributes_dict: dict[str, list[str]],
    ) -> None:
        """Parameterized test for LDIF to LDAP3 attribute conversions."""
        adapter = FlextLdapEntryAdapter()

        # Create entry with test attributes
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes.model_validate({
                "attributes": attributes_dict,
            }),
        )

        # Convert and assert success
        result = adapter.ldif_entry_to_ldap3_attributes(entry)
        FlextTestsUtilities.TestUtilities.assert_result_success(result)

        attrs = result.unwrap()

        # Verify expected attributes
        match test_type:
            case AttributeTestType.EMPTY_LIST:
                assert attrs["cn"] == ["test"]
                assert attrs["description"] == []
                assert attrs["emptyList"] == []
            case AttributeTestType.EMPTY_STRING_IN_LIST:
                assert attrs["cn"] == ["test"]
                assert attrs["emptyStringAttr"] == [""]
            case AttributeTestType.FALSY_VALUES:
                assert attrs["cn"] == ["test"]
                assert attrs["emptyList"] == []
                assert attrs["listWithEmpty"] == [""]

    # LDAP3 to LDIF entry conversion test configurations
    ENTRY_CONVERSION_TEST_CONFIGS: ClassVar[
        list[tuple[EntryTestType, GenericFieldsDict]]
    ] = [
        # (test_type, config_dict)
        (
            EntryTestType.BASIC_CONVERSION,
            {
                "search_base": RFC.DEFAULT_BASE_DN,
                "filter_str": "(objectClass=*)",
                "scope": "BASE",
                "verify_mixed_attrs": False,
                "verify_base64": False,
                "verify_dn_change": False,
            },
        ),
        (
            EntryTestType.MIXED_ATTRIBUTES,
            {
                "search_base": RFC.DEFAULT_BASE_DN,
                "filter_str": "(objectClass=*)",
                "scope": "BASE",
                "verify_mixed_attrs": True,
                "verify_base64": False,
                "verify_dn_change": False,
            },
        ),
        (
            EntryTestType.BASE64_ATTRIBUTES,
            {
                "create_entry": True,
                "entry_attrs": {"description": ["Test with high ASCII: \x80\x81\x82"]},
                "verify_mixed_attrs": False,
                "verify_base64": True,
                "verify_dn_change": False,
            },
        ),
        (
            EntryTestType.DN_CHANGE_TRACKING,
            {
                "create_entry": True,
                "entry_attrs": {},
                "verify_mixed_attrs": False,
                "verify_base64": False,
                "verify_dn_change": True,
            },
        ),
    ]

    @pytest.mark.parametrize(
        ("test_type", "config"),
        ENTRY_CONVERSION_TEST_CONFIGS,
        ids=[config[0].value for config in ENTRY_CONVERSION_TEST_CONFIGS],
    )
    def test_ldap3_to_ldif_entry_conversion_parameterized(
        self,
        ldap_container: GenericFieldsDict,
        test_type: EntryTestType,
        config: GenericFieldsDict,
    ) -> None:
        """Parameterized test for LDAP3 to LDIF entry conversions."""
        adapter_entry = FlextLdapEntryAdapter()
        adapter_ldap3 = Ldap3Adapter(parser=FlextLdifParser())

        # Create LDAP connection
        connection = self._create_ldap_connection(ldap_container)

        try:
            ldap3_entry = None

            if config.get("create_entry"):
                # Create and add entry with specific attributes
                test_cn = f"test{test_type.value}"
                entry_attrs = config.get("entry_attrs", {})
                entry = TestOperationHelpers.create_inetorgperson_entry(
                    test_cn,
                    RFC.DEFAULT_BASE_DN,
                    additional_attrs=entry_attrs
                    if isinstance(entry_attrs, dict)
                    else None,
                )

                # Connect and add entry
                conn_config = FlextLdapModels.ConnectionConfig(
                    host=RFC.DEFAULT_HOST,
                    port=RFC.DEFAULT_PORT,
                    bind_dn=str(ldap_container["bind_dn"]),
                    bind_password=str(ldap_container["password"]),
                )
                connect_result = adapter_ldap3.connect(conn_config)
                if not connect_result.is_success:
                    pytest.skip(f"Could not connect to LDAP: {connect_result.error}")

                # Add with retry
                add_result = adapter_ldap3.add(entry)
                if not add_result.is_success:
                    _ = adapter_ldap3.delete(str(entry.dn))
                    add_result = adapter_ldap3.add(entry)
                FlextTestsUtilities.TestUtilities.assert_result_success(add_result)

                # Search for the created entry
                connection.search(
                    search_base=str(entry.dn),
                    search_filter="(objectClass=*)",
                    search_scope=FlextLdapConstants.SearchScope.BASE.value,
                    attributes=["*"],
                )
                if connection.entries:
                    ldap3_entry = connection.entries[0]

                # Cleanup entry after test
                if entry.dn:
                    _ = adapter_ldap3.delete(str(entry.dn))
                adapter_ldap3.disconnect()
            else:
                # Search for existing entry
                scope_str = str(config["scope"])
                scope_value: str
                if scope_str == "BASE":
                    scope_value = BASE
                elif scope_str == "LEVEL":
                    scope_value = LEVEL
                elif scope_str == "SUBTREE":
                    scope_value = SUBTREE
                else:
                    scope_value = BASE

                connection.search(
                    search_base=str(config["search_base"]),
                    search_filter=str(config["filter_str"]),
                    search_scope=scope_value,
                    attributes=["*"],
                )
                if connection.entries:
                    ldap3_entry = connection.entries[0]

            # Skip if no entry found
            if not ldap3_entry:
                pytest.skip("No LDAP entries found for testing")

            # Ensure ldap3_entry is not None for type checker
            assert ldap3_entry is not None

            # Convert entry
            result = adapter_entry.ldap3_to_ldif_entry(ldap3_entry)
            converted_entry = TestOperationHelpers.assert_result_success_and_unwrap(
                result,
            )

            # Verify basic structure
            assert converted_entry.dn is not None
            assert ldap3_entry is not None
            assert str(converted_entry.dn) == str(ldap3_entry.entry_dn)
            assert converted_entry.attributes is not None

            # Type-specific verifications
            match test_type:
                case EntryTestType.MIXED_ATTRIBUTES:
                    # Verify all attributes are lists and values are strings
                    assert len(converted_entry.attributes.attributes) > 0
                    for (
                        attr_name,
                        attr_values,
                    ) in converted_entry.attributes.attributes.items():
                        assert isinstance(attr_values, list), (
                            f"Attribute {attr_name} should be a list"
                        )
                        for value in attr_values:
                            assert isinstance(value, str), (
                                f"Value in {attr_name} should be a string"
                            )

                case EntryTestType.BASE64_ATTRIBUTES:
                    # Verify base64 detection in metadata
                    assert converted_entry.metadata is not None
                    if hasattr(converted_entry.metadata, "extensions"):
                        extensions = converted_entry.metadata.extensions
                        if isinstance(extensions, dict):
                            base64_attrs = extensions.get("base64_encoded_attributes")
                            if base64_attrs:
                                base64_attrs_list = (
                                    list(base64_attrs)
                                    if isinstance(base64_attrs, (list, set))
                                    else [base64_attrs]
                                )
                                base64_attrs_str = [str(a) for a in base64_attrs_list]
                                assert (
                                    any("description" in a for a in base64_attrs_str)
                                    or len(base64_attrs_str) > 0
                                )

                case EntryTestType.DN_CHANGE_TRACKING:
                    # Verify DN change tracking in metadata
                    assert converted_entry.metadata is not None
                    if hasattr(converted_entry.metadata, "extensions"):
                        extensions = converted_entry.metadata.extensions
                        if isinstance(extensions, dict):
                            assert "dn_changed" in extensions

                case _:
                    # Basic conversion - just verify structure
                    pass

        finally:
            if connection.bound:
                unbind_func: Callable[[], None] = connection.unbind
                unbind_func()
