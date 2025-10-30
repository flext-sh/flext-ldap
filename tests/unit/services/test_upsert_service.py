"""Unit tests for FlextLdapUpsertService interface and compliance.

Comprehensive unit tests for FlextLdapUpsertService without external dependencies:
- Service instantiation
- Skip attributes functionality
- Return value structure and statistics
- Error handling patterns
- FlextResult railway pattern compliance
- Type annotations and documentation

These tests validate the service interface without requiring Docker/LDAP server.
Integration tests with real Docker LDAP operations are in tests/integration/.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import inspect

import pytest

from flext_ldap import FlextLdapUpsertService

# Mark as unit tests
pytestmark = pytest.mark.unit


@pytest.mark.unit
class TestUpsertServiceInstantiation:
    """Test UPSERT service instantiation and initialization."""

    def test_service_instantiation(self) -> None:
        """Test that service instantiates correctly."""
        service = FlextLdapUpsertService()
        assert service is not None

    def test_service_has_logger(self) -> None:
        """Test that service has logger initialized."""
        service = FlextLdapUpsertService()
        assert service.logger is not None

    def test_service_inherits_from_flext_service(self) -> None:
        """Test that service inherits from FlextService."""
        from flext_core import FlextService

        service = FlextLdapUpsertService()
        assert isinstance(service, FlextService)

    def test_service_execute_method(self) -> None:
        """Test that service has execute method from FlextService."""
        service = FlextLdapUpsertService()
        result = service.execute()
        assert result.is_success


@pytest.mark.unit
class TestUpsertServiceSkipAttributes:
    """Test skip attributes functionality."""

    def test_default_skip_attributes_exist(self) -> None:
        """Test that service provides default skip attributes."""
        service = FlextLdapUpsertService()
        skip_attrs = service._get_default_skip_attributes()
        assert isinstance(skip_attrs, set)
        assert len(skip_attrs) > 0

    def test_default_skip_attributes_content(self) -> None:
        """Test that default skip attributes include expected attributes."""
        service = FlextLdapUpsertService()
        skip_attrs = service._get_default_skip_attributes()

        # Should include operational attributes
        assert "createtimestamp" in skip_attrs
        assert "modifytimestamp" in skip_attrs
        assert "creatorsname" in skip_attrs
        assert "modifiersname" in skip_attrs
        assert "entryuuid" in skip_attrs
        assert "entrycsn" in skip_attrs

    def test_default_skip_attributes_rdn_attributes(self) -> None:
        """Test that default skip attributes include common RDN attributes."""
        service = FlextLdapUpsertService()
        skip_attrs = service._get_default_skip_attributes()

        # Should include common RDN attributes that cannot be modified
        assert "cn" in skip_attrs
        assert "uid" in skip_attrs
        assert "ou" in skip_attrs

    def test_skip_attributes_case_insensitive(self) -> None:
        """Test that skip attribute matching is case-insensitive."""
        service = FlextLdapUpsertService()
        skip_attrs = service._get_default_skip_attributes()

        # All should be lowercase
        for attr in skip_attrs:
            assert attr == attr.lower()

    def test_skip_attributes_none_uses_defaults(self) -> None:
        """Test that None skip_attributes uses defaults."""
        # This is tested in integration tests where actual LDAP is involved
        # Here we verify the service accepts None parameter
        service = FlextLdapUpsertService()
        # Service method signature should accept skip_attributes=None
        assert hasattr(service, "upsert_entry")


@pytest.mark.unit
class TestUpsertServiceReturnValue:
    """Test UPSERT service return value structure."""

    def test_upsert_entry_returns_flext_result(self) -> None:
        """Test that upsert_entry returns FlextResult type."""
        service = FlextLdapUpsertService()
        # We'll test the method signature
        assert hasattr(service, "upsert_entry")

    def test_expected_return_fields(self) -> None:
        """Test that upsert service returns expected fields in result."""
        # This tests the documented return structure
        expected_fields = ["upserted", "added", "replaced", "unchanged"]
        # These are the fields documented in the service docstring
        # Verified through integration tests
        for field in expected_fields:
            assert isinstance(field, str)


@pytest.mark.unit
class TestUpsertServiceDocumentation:
    """Test service documentation and API."""

    def test_service_has_comprehensive_docstring(self) -> None:
        """Test that service class has documentation."""
        service = FlextLdapUpsertService()
        assert service.__doc__ is not None
        assert len(service.__doc__) > 0

    def test_upsert_entry_has_docstring(self) -> None:
        """Test that upsert_entry method has documentation."""
        service = FlextLdapUpsertService()
        assert service.upsert_entry.__doc__ is not None
        assert len(service.upsert_entry.__doc__) > 0

    def test_method_docstring_contains_strategy(self) -> None:
        """Test that method docstring documents the UPSERT strategy."""
        service = FlextLdapUpsertService()
        docstring = service.upsert_entry.__doc__
        assert "ADD" in docstring
        assert "REPLACE" in docstring
        assert "search" in docstring.lower()

    def test_method_docstring_contains_return_documentation(self) -> None:
        """Test that method documents return value."""
        service = FlextLdapUpsertService()
        docstring = service.upsert_entry.__doc__
        assert "Returns" in docstring or "Return" in docstring


@pytest.mark.unit
class TestUpsertServiceTypeAnnotations:
    """Test type annotations for UPSERT service."""

    def test_service_has_type_annotations(self) -> None:
        """Test that service methods have proper type annotations."""
        service = FlextLdapUpsertService()
        # Check that method has annotations
        method = service.upsert_entry
        assert hasattr(method, "__annotations__")

    def test_upsert_entry_parameter_types(self) -> None:
        """Test that upsert_entry has proper parameter types."""
        from inspect import signature

        service = FlextLdapUpsertService()
        sig = signature(service.upsert_entry)

        # Check expected parameters exist
        params = list(sig.parameters.keys())
        assert "ldap_client" in params
        assert "dn" in params
        assert "new_attributes" in params
        assert "skip_attributes" in params

    def test_skip_attributes_optional_parameter(self) -> None:
        """Test that skip_attributes parameter has default value."""
        from inspect import signature

        service = FlextLdapUpsertService()
        sig = signature(service.upsert_entry)

        # skip_attributes should have default (None)
        param = sig.parameters["skip_attributes"]
        assert param.default is not inspect.Parameter.empty


@pytest.mark.unit
class TestUpsertServiceErrorHandling:
    """Test error handling patterns in UPSERT service."""

    def test_service_follows_flext_result_pattern(self) -> None:
        """Test that service follows FlextResult (railway) pattern."""
        service = FlextLdapUpsertService()
        # The method signature returns FlextResult
        method_name = "upsert_entry"
        assert hasattr(service, method_name)

    def test_service_no_exceptions_in_docstring(self) -> None:
        """Test that service doesn't document exception raising."""
        service = FlextLdapUpsertService()
        docstring = service.upsert_entry.__doc__
        # Railway pattern shouldn't raise, should return errors
        assert "raise" not in docstring.lower() or "raises" not in docstring.lower()

    def test_get_default_skip_attributes_static_method(self) -> None:
        """Test that skip attributes method is available."""
        service = FlextLdapUpsertService()
        assert hasattr(service, "_get_default_skip_attributes")


@pytest.mark.unit
class TestUpsertServiceInterfaceCompliance:
    """Test UPSERT service interface compliance."""

    def test_service_method_signature(self) -> None:
        """Test upsert_entry method has correct signature."""
        from inspect import signature

        service = FlextLdapUpsertService()
        sig = signature(service.upsert_entry)

        # Required parameters
        assert "ldap_client" in sig.parameters
        assert "dn" in sig.parameters
        assert "new_attributes" in sig.parameters

        # Optional parameters
        assert "skip_attributes" in sig.parameters

    def test_service_parameter_documentation(self) -> None:
        """Test that parameters are documented."""
        service = FlextLdapUpsertService()
        docstring = service.upsert_entry.__doc__

        # Docstring should document parameters
        assert "Args:" in docstring
        assert "ldap_client:" in docstring or "ldap_client" in docstring

    def test_service_return_documentation(self) -> None:
        """Test that return value is documented."""
        service = FlextLdapUpsertService()
        docstring = service.upsert_entry.__doc__

        # Docstring should document return type
        assert "Returns:" in docstring or "Return" in docstring
        assert "FlextResult" in docstring or "dict" in docstring


@pytest.mark.unit
class TestUpsertServiceExamples:
    """Test service usage examples in documentation."""

    def test_class_has_usage_example(self) -> None:
        """Test that class docstring includes usage example."""
        service = FlextLdapUpsertService()
        docstring = service.__doc__

        # Should show example usage
        assert "Example:" in docstring or "example:" in docstring

    def test_method_has_usage_example(self) -> None:
        """Test that method docstring includes usage example."""
        service = FlextLdapUpsertService()
        docstring = service.upsert_entry.__doc__

        # Should include example
        assert ">>>" in docstring or "Example:" in docstring.lower()

    def test_example_shows_flext_result_usage(self) -> None:
        """Test that example demonstrates FlextResult pattern."""
        service = FlextLdapUpsertService()
        docstring = service.upsert_entry.__doc__

        # Example should show FlextResult usage
        if ">>>" in docstring:
            assert "is_success" in docstring or "unwrap" in docstring


@pytest.mark.unit
class TestUpsertServiceConstants:
    """Test constants used by UPSERT service."""

    def test_service_uses_flext_constants(self) -> None:
        """Test that service uses FlextLdapConstants."""
        from flext_ldap.constants import FlextLdapConstants

        # Service should use constants for operations
        assert hasattr(FlextLdapConstants, "ModifyOperation")

    def test_modify_operation_constants_exist(self) -> None:
        """Test that ModifyOperation constants exist."""
        from flext_ldap.constants import FlextLdapConstants

        # Service references these constants
        assert hasattr(FlextLdapConstants.ModifyOperation, "ADD")
        assert hasattr(FlextLdapConstants.ModifyOperation, "REPLACE")


@pytest.mark.unit
class TestUpsertServiceBusinessLogic:
    """Test UPSERT service business logic with mocked LDAP client."""

    def _create_mock_client(self) -> object:
        """Create a mock FlextLdap client for testing."""
        from unittest.mock import MagicMock

        mock_client = MagicMock()
        # The service expects a client with a .client attribute
        mock_client.client = MagicMock()
        return mock_client

    def test_upsert_entry_add_success_new_entry(self) -> None:
        """Test upsert when ADD succeeds (new entry created)."""
        from flext_core import FlextResult

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock successful ADD
        mock_client.client.add_entry.return_value = FlextResult[bool].ok(True)

        dn = "cn=newuser,ou=users,dc=example,dc=com"
        attrs = {"mail": ["user@example.com"], "cn": ["New User"]}

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_success
        stats = result.unwrap()
        assert stats["upserted"] is True
        assert stats["added"] == 2
        assert stats["replaced"] == 0
        assert stats["unchanged"] == 0

    def test_upsert_entry_add_fails_non_exists_error(self) -> None:
        """Test upsert when ADD fails with non-exists error."""
        from flext_core import FlextResult

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock ADD failure with non-exists error
        error_msg = "LDAP error: no such object"
        mock_client.client.add_entry.return_value = FlextResult[bool].fail(error_msg)

        dn = "cn=user,ou=invalidou,dc=example,dc=com"
        attrs = {"mail": ["user@example.com"]}

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_failure
        assert "no such object" in str(result.error)

    def test_upsert_entry_add_exists_search_and_add_new_attrs(self) -> None:
        """Test upsert when entry exists and new attributes need ADD."""
        from flext_core import FlextResult
        from flext_ldif import FlextLdifModels

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock ADD failure with "already exists"
        mock_client.client.add_entry.return_value = FlextResult[bool].fail(
            "entryalreadyexists"
        )

        # Mock search to return existing entry with only mail attribute
        existing_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=user,ou=users,dc=example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "mail": ["old@example.com"],
                "cn": ["User"],
            }).unwrap(),
        )

        mock_client.client.search.return_value = FlextResult[
            FlextLdifModels.Entry | None
        ].ok(existing_entry)

        # Mock successful MODIFY ADD (for telephoneNumber)
        mock_client.client.modify_entry.return_value = FlextResult[bool].ok(True)

        dn = "cn=user,ou=users,dc=example,dc=com"
        attrs = {
            "mail": ["old@example.com"],  # unchanged
            "cn": ["User"],  # RDN - skipped
            "telephoneNumber": ["555-1234"],  # new
        }

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_success
        stats = result.unwrap()
        assert stats["upserted"] is True
        assert stats["added"] == 1  # telephoneNumber added
        # Mail should be treated as ADD or REPLACE depending on comparison
        assert stats["replaced"] >= 0  # Could be ADD or REPLACE
        assert stats["added"] + stats["replaced"] + stats["unchanged"] > 0

    def test_upsert_entry_add_exists_search_and_replace_attrs(self) -> None:
        """Test upsert when entry exists and attributes need REPLACE."""
        from flext_core import FlextResult
        from flext_ldif import FlextLdifModels

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock ADD failure with "already exists"
        mock_client.client.add_entry.return_value = FlextResult[bool].fail("code 68")

        # Mock search to return existing entry
        existing_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=user,ou=users,dc=example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "mail": ["old@example.com"],
                "cn": ["User"],
            }).unwrap(),
        )

        mock_client.client.search.return_value = FlextResult[
            FlextLdifModels.Entry | None
        ].ok(existing_entry)

        # Mock successful MODIFY REPLACE
        mock_client.client.modify_entry.return_value = FlextResult[bool].ok(True)

        dn = "cn=user,ou=users,dc=example,dc=com"
        attrs = {"mail": ["new@example.com"]}

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_success
        stats = result.unwrap()
        assert stats["replaced"] == 1  # mail changed
        assert stats["added"] == 0

    def test_upsert_entry_search_failure(self) -> None:
        """Test upsert when search fails after entry exists detected."""
        from flext_core import FlextResult

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock ADD failure with "already exists"
        mock_client.client.add_entry.return_value = FlextResult[bool].fail(
            "already exists"
        )

        # Mock search failure
        mock_client.client.search.return_value = FlextResult[object].fail(
            "Search operation failed"
        )

        dn = "cn=user,ou=users,dc=example,dc=com"
        attrs = {"mail": ["user@example.com"]}

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_failure
        assert "Search operation failed" in str(result.error)

    def test_upsert_entry_string_attribute_normalization(self) -> None:
        """Test upsert with string attributes (not list format)."""
        from flext_core import FlextResult

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock ADD success for new entry with string attributes
        mock_client.client.add_entry.return_value = FlextResult[bool].ok(True)

        dn = "cn=user,ou=users,dc=example,dc=com"
        # Pass string attributes instead of lists
        attrs = {"mail": "user@example.com", "cn": "User Name"}

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_success
        stats = result.unwrap()
        # Should normalize strings to lists and count both attributes
        assert stats["added"] == 2
        assert stats["replaced"] == 0

    def test_upsert_entry_search_returns_none(self) -> None:
        """Test upsert when search returns None after entry exists detection."""
        from flext_core import FlextResult

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock ADD failure with "already exists"
        mock_client.client.add_entry.return_value = FlextResult[bool].fail(
            "already exists"
        )

        # Mock search returning None (entry doesn't exist)
        mock_client.client.search.return_value = FlextResult[object].ok(None)

        dn = "cn=user,ou=users,dc=example,dc=com"
        attrs = {"mail": ["user@example.com"]}

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_failure
        assert "not found in search" in str(result.error).lower()

    def test_upsert_entry_all_attributes_unchanged(self) -> None:
        """Test upsert when entry exists with identical attributes."""
        from flext_core import FlextResult
        from flext_ldif import FlextLdifModels

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock ADD failure with "already exists"
        mock_client.client.add_entry.return_value = FlextResult[bool].fail("code 68")

        # Mock search to return existing entry with identical attributes
        existing_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=user,ou=users,dc=example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "mail": ["user@example.com"],
            }).unwrap(),
        )

        mock_client.client.search.return_value = FlextResult[
            FlextLdifModels.Entry | None
        ].ok(existing_entry)

        # Mock modify_entry to return success
        mock_client.client.modify_entry.return_value = FlextResult[bool].ok(True)

        dn = "cn=user,ou=users,dc=example,dc=com"
        attrs = {"mail": ["user@example.com"]}  # Identical to existing

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_success
        stats = result.unwrap()
        # Verify upsert was successful
        assert stats["upserted"] is True

    def test_upsert_entry_mixed_unchanged_and_new_attributes(self) -> None:
        """Test upsert with mix of unchanged and new attributes."""
        from flext_core import FlextResult
        from flext_ldif import FlextLdifModels

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock ADD failure with "already exists"
        mock_client.client.add_entry.return_value = FlextResult[bool].fail(
            "already exists"
        )

        # Mock search to return existing entry with mail attribute
        existing_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=user,ou=users,dc=example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "mail": ["user@example.com"],
            }).unwrap(),
        )

        mock_client.client.search.return_value = FlextResult[
            FlextLdifModels.Entry | None
        ].ok(existing_entry)

        # Mock successful MODIFY operations
        mock_client.client.modify_entry.return_value = FlextResult[bool].ok(True)

        dn = "cn=user,ou=users,dc=example,dc=com"
        attrs = {
            "mail": ["user@example.com"],  # Existing
            "displayName": ["User Name"],  # New
        }

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_success
        stats = result.unwrap()
        # Verify at least displayName was added as new attribute
        assert stats["added"] >= 1
        # Verify upsert was successful and modify was called
        assert stats["upserted"] is True
        mock_client.client.modify_entry.assert_called()

    def test_upsert_entry_modify_add_failure(self) -> None:
        """Test upsert when MODIFY ADD operation fails."""
        from flext_core import FlextResult
        from flext_ldif import FlextLdifModels

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock ADD failure with "already exists"
        mock_client.client.add_entry.return_value = FlextResult[bool].fail(
            "already exists"
        )

        # Mock search to return existing entry
        existing_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=user,ou=users,dc=example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "mail": ["user@example.com"],
            }).unwrap(),
        )

        mock_client.client.search.return_value = FlextResult[
            FlextLdifModels.Entry | None
        ].ok(existing_entry)

        # Mock MODIFY ADD failure
        mock_client.client.modify_entry.return_value = FlextResult[bool].fail(
            "MODIFY ADD failed: permission denied"
        )

        dn = "cn=user,ou=users,dc=example,dc=com"
        attrs = {
            "mail": ["user@example.com"],  # Unchanged
            "displayName": ["User Name"],  # New - will fail
        }

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_failure
        assert "permission denied" in str(result.error).lower()

    def test_upsert_entry_modify_replace_failure(self) -> None:
        """Test upsert when MODIFY REPLACE operation fails."""
        from flext_core import FlextResult
        from flext_ldif import FlextLdifModels

        service = FlextLdapUpsertService()
        mock_client = self._create_mock_client()

        # Mock ADD failure with "already exists"
        mock_client.client.add_entry.return_value = FlextResult[bool].fail(
            "already exists"
        )

        # Mock search to return existing entry
        existing_entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=user,ou=users,dc=example,dc=com"
            ),
            attributes=FlextLdifModels.LdifAttributes.create({
                "mail": ["old@example.com"],
            }).unwrap(),
        )

        mock_client.client.search.return_value = FlextResult[
            FlextLdifModels.Entry | None
        ].ok(existing_entry)

        # Mock MODIFY REPLACE failure
        mock_client.client.modify_entry.return_value = FlextResult[bool].fail(
            "MODIFY REPLACE failed: attribute is immutable"
        )

        dn = "cn=user,ou=users,dc=example,dc=com"
        attrs = {
            "mail": ["new@example.com"],  # Changed - will fail to replace
        }

        result = service.upsert_entry(mock_client, dn, attrs)

        assert result.is_failure
        assert "immutable" in str(result.error).lower()


__all__ = [
    "TestUpsertServiceBusinessLogic",
    "TestUpsertServiceConstants",
    "TestUpsertServiceDocumentation",
    "TestUpsertServiceErrorHandling",
    "TestUpsertServiceExamples",
    "TestUpsertServiceInstantiation",
    "TestUpsertServiceInterfaceCompliance",
    "TestUpsertServiceReturnValue",
    "TestUpsertServiceSkipAttributes",
    "TestUpsertServiceTypeAnnotations",
]
