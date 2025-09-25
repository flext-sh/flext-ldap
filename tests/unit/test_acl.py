"""Comprehensive tests for FlextLdap ACL modules.

This module provides complete test coverage for all ACL-related classes
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import patch

from flext_core import FlextResult
from flext_ldap.acl import (
    FlextLdapAclConstants,
    FlextLdapAclConverters,
    FlextLdapAclManager,
    FlextLdapAclModels,
    FlextLdapAclParsers,
)


class TestFlextLdapAclConstants:
    """Comprehensive test suite for FlextLdapAclConstants."""

    def test_acl_constants_initialization(
        self, acl_constants: FlextLdapAclConstants
    ) -> None:
        """Test ACL constants initialization."""
        assert acl_constants is not None
        assert hasattr(acl_constants, "_container")
        assert hasattr(acl_constants, "_logger")

    def test_get_permission_types(self, acl_constants: FlextLdapAclConstants) -> None:
        """Test getting permission types."""
        permissions = acl_constants.get_permission_types()

        assert isinstance(permissions, list)
        assert "read" in permissions
        assert "write" in permissions
        assert "delete" in permissions
        assert "search" in permissions

    def test_get_subject_types(self, acl_constants: FlextLdapAclConstants) -> None:
        """Test getting subject types."""
        subject_types = acl_constants.get_subject_types()

        assert isinstance(subject_types, list)
        assert "user" in subject_types
        assert "group" in subject_types
        assert "anonymous" in subject_types

    def test_get_scope_types(self, acl_constants: FlextLdapAclConstants) -> None:
        """Test getting scope types."""
        scope_types = acl_constants.get_scope_types()

        assert isinstance(scope_types, list)
        assert "base" in scope_types
        assert "one" in scope_types
        assert "subtree" in scope_types

    def test_get_ldap_server_types(self, acl_constants: FlextLdapAclConstants) -> None:
        """Test getting LDAP server types."""
        server_types = acl_constants.get_ldap_server_types()

        assert isinstance(server_types, list)
        assert "openldap" in server_types
        assert "oracle" in server_types
        assert "active_directory" in server_types

    def test_get_acl_formats(self, acl_constants: FlextLdapAclConstants) -> None:
        """Test getting ACL formats."""
        formats = acl_constants.get_acl_formats()

        assert isinstance(formats, list)
        assert "unified" in formats
        assert "openldap" in formats
        assert "oracle" in formats

    def test_validate_permission_type_valid(
        self, acl_constants: FlextLdapAclConstants
    ) -> None:
        """Test validating valid permission type."""
        result = acl_constants.validate_permission_type("read")

        assert result.is_success
        assert result.data is True

    def test_validate_permission_type_invalid(
        self, acl_constants: FlextLdapAclConstants
    ) -> None:
        """Test validating invalid permission type."""
        result = acl_constants.validate_permission_type("invalid_permission")

        assert result.is_failure
        assert "Invalid permission type" in result.error

    def test_validate_subject_type_valid(
        self, acl_constants: FlextLdapAclConstants
    ) -> None:
        """Test validating valid subject type."""
        result = acl_constants.validate_subject_type("user")

        assert result.is_success
        assert result.data is True

    def test_validate_subject_type_invalid(
        self, acl_constants: FlextLdapAclConstants
    ) -> None:
        """Test validating invalid subject type."""
        result = acl_constants.validate_subject_type("invalid_subject")

        assert result.is_failure
        assert "Invalid subject type" in result.error

    def test_validate_scope_type_valid(
        self, acl_constants: FlextLdapAclConstants
    ) -> None:
        """Test validating valid scope type."""
        result = acl_constants.validate_scope_type("subtree")

        assert result.is_success
        assert result.data is True

    def test_validate_scope_type_invalid(
        self, acl_constants: FlextLdapAclConstants
    ) -> None:
        """Test validating invalid scope type."""
        result = acl_constants.validate_scope_type("invalid_scope")

        assert result.is_failure
        assert "Invalid scope type" in result.error


class TestFlextLdapAclConverters:
    """Comprehensive test suite for FlextLdapAclConverters."""

    def test_acl_converters_initialization(
        self, acl_converters: FlextLdapAclConverters
    ) -> None:
        """Test ACL converters initialization."""
        assert acl_converters is not None
        assert hasattr(acl_converters, "_container")
        assert hasattr(acl_converters, "_logger")

    def test_convert_unified_to_openldap_success(
        self,
        acl_converters: FlextLdapAclConverters,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful unified to OpenLDAP conversion."""
        with patch.object(
            acl_converters, "_convert_to_openldap_format"
        ) as mock_convert:
            mock_convert.return_value = FlextResult[str].ok(
                'target="ldap:///dc=example,dc=com" version 3.0; acl "REDACTED_LDAP_BIND_PASSWORD access"; allow (read,write,delete) userdn="ldap:///uid=REDACTED_LDAP_BIND_PASSWORD,ou=people,dc=example,dc=com";'
            )

            result = acl_converters.convert_unified_to_openldap(
                sample_acl_data["unified_acl"]
            )

            assert result.is_success
            assert "target=" in result.data
            assert "version 3.0" in result.data
            mock_convert.assert_called_once()

    def test_convert_unified_to_openldap_failure(
        self,
        acl_converters: FlextLdapAclConverters,
    ) -> None:
        """Test unified to OpenLDAP conversion failure."""
        with patch.object(
            acl_converters, "_convert_to_openldap_format"
        ) as mock_convert:
            mock_convert.return_value = FlextResult[str].fail("Conversion failed")

            invalid_acl = {"invalid": "data"}
            result = acl_converters.convert_unified_to_openldap(invalid_acl)

            assert result.is_failure
            assert "Conversion failed" in result.error

    def test_convert_unified_to_oracle_success(
        self,
        acl_converters: FlextLdapAclConverters,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful unified to Oracle conversion."""
        with patch.object(acl_converters, "_convert_to_oracle_format") as mock_convert:
            mock_convert.return_value = FlextResult[str].ok(
                'target="dc=example,dc=com" version 3.0; acl "REDACTED_LDAP_BIND_PASSWORD access"; allow (read,write,delete) userdn="uid=REDACTED_LDAP_BIND_PASSWORD,ou=people,dc=example,dc=com";'
            )

            result = acl_converters.convert_unified_to_oracle(
                sample_acl_data["unified_acl"]
            )

            assert result.is_success
            assert "target=" in result.data
            assert "version 3.0" in result.data
            mock_convert.assert_called_once()

    def test_convert_unified_to_oracle_failure(
        self,
        acl_converters: FlextLdapAclConverters,
    ) -> None:
        """Test unified to Oracle conversion failure."""
        with patch.object(acl_converters, "_convert_to_oracle_format") as mock_convert:
            mock_convert.return_value = FlextResult[str].fail("Conversion failed")

            invalid_acl = {"invalid": "data"}
            result = acl_converters.convert_unified_to_oracle(invalid_acl)

            assert result.is_failure
            assert "Conversion failed" in result.error

    def test_convert_openldap_to_unified_success(
        self,
        acl_converters: FlextLdapAclConverters,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful OpenLDAP to unified conversion."""
        with patch.object(acl_converters, "_parse_openldap_format") as mock_parse:
            mock_parse.return_value = FlextResult[dict[str, object]].ok(
                sample_acl_data["unified_acl"]
            )

            result = acl_converters.convert_openldap_to_unified(
                sample_acl_data["openldap_aci"]
            )

            assert result.is_success
            assert "target" in result.data
            assert "permissions" in result.data
            mock_parse.assert_called_once()

    def test_convert_openldap_to_unified_failure(
        self,
        acl_converters: FlextLdapAclConverters,
    ) -> None:
        """Test OpenLDAP to unified conversion failure."""
        with patch.object(acl_converters, "_parse_openldap_format") as mock_parse:
            mock_parse.return_value = FlextResult[dict[str, object]].fail(
                "Parsing failed"
            )

            result = acl_converters.convert_openldap_to_unified("invalid acl format")

            assert result.is_failure
            assert "Parsing failed" in result.error

    def test_convert_oracle_to_unified_success(
        self,
        acl_converters: FlextLdapAclConverters,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful Oracle to unified conversion."""
        with patch.object(acl_converters, "_parse_oracle_format") as mock_parse:
            mock_parse.return_value = FlextResult[dict[str, object]].ok(
                sample_acl_data["unified_acl"]
            )

            result = acl_converters.convert_oracle_to_unified(
                sample_acl_data["oracle_aci"]
            )

            assert result.is_success
            assert "target" in result.data
            assert "permissions" in result.data
            mock_parse.assert_called_once()

    def test_convert_oracle_to_unified_failure(
        self,
        acl_converters: FlextLdapAclConverters,
    ) -> None:
        """Test Oracle to unified conversion failure."""
        with patch.object(acl_converters, "_parse_oracle_format") as mock_parse:
            mock_parse.return_value = FlextResult[dict[str, object]].fail(
                "Parsing failed"
            )

            result = acl_converters.convert_oracle_to_unified("invalid acl format")

            assert result.is_failure
            assert "Parsing failed" in result.error

    def test_convert_between_formats_success(
        self,
        acl_converters: FlextLdapAclConverters,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful conversion between formats."""
        with patch.object(
            acl_converters, "_convert_to_openldap_format"
        ) as mock_convert:
            mock_convert.return_value = FlextResult[str].ok("converted acl")

            result = acl_converters.convert_between_formats(
                source_format="unified",
                target_format="openldap",
                acl_data=sample_acl_data["unified_acl"],
            )

            assert result.is_success
            assert result.data == "converted acl"
            mock_convert.assert_called_once()

    def test_convert_between_formats_unsupported(
        self,
        acl_converters: FlextLdapAclConverters,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test conversion between unsupported formats."""
        result = acl_converters.convert_between_formats(
            source_format="unsupported",
            target_format="openldap",
            acl_data=sample_acl_data["unified_acl"],
        )

        assert result.is_failure
        assert "Unsupported source format" in result.error

    def test_validate_acl_format_valid(
        self, acl_converters: FlextLdapAclConverters
    ) -> None:
        """Test validating valid ACL format."""
        result = acl_converters.validate_acl_format(
            "unified", {"target": "dc=example,dc=com"}
        )

        assert result.is_success
        assert result.data is True

    def test_validate_acl_format_invalid(
        self, acl_converters: FlextLdapAclConverters
    ) -> None:
        """Test validating invalid ACL format."""
        result = acl_converters.validate_acl_format("unified", {"invalid": "data"})

        assert result.is_failure
        assert "Invalid ACL format" in result.error


class TestFlextLdapAclManager:
    """Comprehensive test suite for FlextLdapAclManager."""

    def test_acl_manager_initialization(self, acl_manager: FlextLdapAclManager) -> None:
        """Test ACL manager initialization."""
        assert acl_manager is not None
        assert hasattr(acl_manager, "_container")
        assert hasattr(acl_manager, "_logger")

    def test_create_acl_success(
        self,
        acl_manager: FlextLdapAclManager,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful ACL creation."""
        with (
            patch.object(acl_manager, "_validate_acl_data") as mock_validate,
            patch.object(acl_manager, "_store_acl") as mock_store,
        ):
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })
            mock_store.return_value = FlextResult[str].ok("acl_id_123")

            result = acl_manager.create_acl(sample_acl_data["unified_acl"])

            assert result.is_success
            assert result.data == "acl_id_123"
            mock_validate.assert_called_once()
            mock_store.assert_called_once()

    def test_create_acl_validation_failure(
        self,
        acl_manager: FlextLdapAclManager,
    ) -> None:
        """Test ACL creation with validation failure."""
        with patch.object(acl_manager, "_validate_acl_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].fail(
                "Validation failed"
            )

            invalid_acl = {"invalid": "data"}
            result = acl_manager.create_acl(invalid_acl)

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_create_acl_storage_failure(
        self,
        acl_manager: FlextLdapAclManager,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test ACL creation with storage failure."""
        with (
            patch.object(acl_manager, "_validate_acl_data") as mock_validate,
            patch.object(acl_manager, "_store_acl") as mock_store,
        ):
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })
            mock_store.return_value = FlextResult[str].fail("Storage failed")

            result = acl_manager.create_acl(sample_acl_data["unified_acl"])

            assert result.is_failure
            assert "Storage failed" in result.error

    def test_update_acl_success(
        self,
        acl_manager: FlextLdapAclManager,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful ACL update."""
        with (
            patch.object(acl_manager, "_validate_acl_data") as mock_validate,
            patch.object(acl_manager, "_update_acl_storage") as mock_update,
        ):
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })
            mock_update.return_value = FlextResult[bool].ok(True)

            result = acl_manager.update_acl(
                "acl_id_123", sample_acl_data["unified_acl"]
            )

            assert result.is_success
            assert result.data is True
            mock_validate.assert_called_once()
            mock_update.assert_called_once()

    def test_update_acl_not_found(
        self,
        acl_manager: FlextLdapAclManager,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test ACL update when ACL not found."""
        with (
            patch.object(acl_manager, "_validate_acl_data") as mock_validate,
            patch.object(acl_manager, "_update_acl_storage") as mock_update,
        ):
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })
            mock_update.return_value = FlextResult[bool].fail("ACL not found")

            result = acl_manager.update_acl(
                "nonexistent_id", sample_acl_data["unified_acl"]
            )

            assert result.is_failure
            assert "ACL not found" in result.error

    def test_delete_acl_success(self, acl_manager: FlextLdapAclManager) -> None:
        """Test successful ACL deletion."""
        with patch.object(acl_manager, "_remove_acl_storage") as mock_remove:
            mock_remove.return_value = FlextResult[bool].ok(True)

            result = acl_manager.delete_acl("acl_id_123")

            assert result.is_success
            assert result.data is True
            mock_remove.assert_called_once()

    def test_delete_acl_not_found(self, acl_manager: FlextLdapAclManager) -> None:
        """Test ACL deletion when ACL not found."""
        with patch.object(acl_manager, "_remove_acl_storage") as mock_remove:
            mock_remove.return_value = FlextResult[bool].fail("ACL not found")

            result = acl_manager.delete_acl("nonexistent_id")

            assert result.is_failure
            assert "ACL not found" in result.error

    def test_get_acl_success(self, acl_manager: FlextLdapAclManager) -> None:
        """Test successful ACL retrieval."""
        with patch.object(acl_manager, "_retrieve_acl_storage") as mock_retrieve:
            mock_acl_data = {"target": "dc=example,dc=com", "permissions": []}
            mock_retrieve.return_value = FlextResult[dict[str, object]].ok(
                mock_acl_data
            )

            result = acl_manager.get_acl("acl_id_123")

            assert result.is_success
            assert result.data == mock_acl_data
            mock_retrieve.assert_called_once()

    def test_get_acl_not_found(self, acl_manager: FlextLdapAclManager) -> None:
        """Test ACL retrieval when ACL not found."""
        with patch.object(acl_manager, "_retrieve_acl_storage") as mock_retrieve:
            mock_retrieve.return_value = FlextResult[dict[str, object]].fail(
                "ACL not found"
            )

            result = acl_manager.get_acl("nonexistent_id")

            assert result.is_failure
            assert "ACL not found" in result.error

    def test_list_acls_success(self, acl_manager: FlextLdapAclManager) -> None:
        """Test successful ACL listing."""
        with patch.object(acl_manager, "_list_acl_storage") as mock_list:
            mock_list.return_value = FlextResult[list[dict[str, object]]].ok([
                {"id": "acl_1", "name": "ACL 1"},
                {"id": "acl_2", "name": "ACL 2"},
            ])

            result = acl_manager.list_acls()

            assert result.is_success
            assert len(result.data) == 2
            assert result.data[0]["id"] == "acl_1"
            mock_list.assert_called_once()

    def test_list_acls_empty(self, acl_manager: FlextLdapAclManager) -> None:
        """Test ACL listing with empty results."""
        with patch.object(acl_manager, "_list_acl_storage") as mock_list:
            mock_list.return_value = FlextResult[list[dict[str, object]]].ok([])

            result = acl_manager.list_acls()

            assert result.is_success
            assert len(result.data) == 0
            mock_list.assert_called_once()

    def test_apply_acl_success(self, acl_manager: FlextLdapAclManager) -> None:
        """Test successful ACL application."""
        with patch.object(acl_manager, "_apply_acl_to_target") as mock_apply:
            mock_apply.return_value = FlextResult[bool].ok(True)

            result = acl_manager.apply_acl("acl_id_123", "dc=example,dc=com")

            assert result.is_success
            assert result.data is True
            mock_apply.assert_called_once()

    def test_apply_acl_failure(self, acl_manager: FlextLdapAclManager) -> None:
        """Test ACL application failure."""
        with patch.object(acl_manager, "_apply_acl_to_target") as mock_apply:
            mock_apply.return_value = FlextResult[bool].fail("Application failed")

            result = acl_manager.apply_acl("acl_id_123", "dc=example,dc=com")

            assert result.is_failure
            assert "Application failed" in result.error

    def test_validate_acl_data_success(
        self,
        acl_manager: FlextLdapAclManager,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful ACL data validation."""
        result = acl_manager._validate_acl_data(sample_acl_data["unified_acl"])

        assert result.is_success
        assert "valid" in result.data

    def test_validate_acl_data_failure(self, acl_manager: FlextLdapAclManager) -> None:
        """Test ACL data validation failure."""
        invalid_acl = {"invalid": "data"}
        result = acl_manager._validate_acl_data(invalid_acl)

        assert result.is_failure
        assert "Invalid ACL data" in result.error


class TestFlextLdapAclParsers:
    """Comprehensive test suite for FlextLdapAclParsers."""

    def test_acl_parsers_initialization(self, acl_parsers: FlextLdapAclParsers) -> None:
        """Test ACL parsers initialization."""
        assert acl_parsers is not None
        assert hasattr(acl_parsers, "_container")
        assert hasattr(acl_parsers, "_logger")

    def test_parse_openldap_aci_success(
        self,
        acl_parsers: FlextLdapAclParsers,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful OpenLDAP ACI parsing."""
        with patch.object(acl_parsers, "_parse_openldap_syntax") as mock_parse:
            mock_parse.return_value = FlextResult[dict[str, object]].ok(
                sample_acl_data["unified_acl"]
            )

            result = acl_parsers.parse_openldap_aci(sample_acl_data["openldap_aci"])

            assert result.is_success
            assert "target" in result.data
            assert "permissions" in result.data
            mock_parse.assert_called_once()

    def test_parse_openldap_aci_failure(
        self,
        acl_parsers: FlextLdapAclParsers,
    ) -> None:
        """Test OpenLDAP ACI parsing failure."""
        with patch.object(acl_parsers, "_parse_openldap_syntax") as mock_parse:
            mock_parse.return_value = FlextResult[dict[str, object]].fail(
                "Parsing failed"
            )

            result = acl_parsers.parse_openldap_aci("invalid aci format")

            assert result.is_failure
            assert "Parsing failed" in result.error

    def test_parse_oracle_aci_success(
        self,
        acl_parsers: FlextLdapAclParsers,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful Oracle ACI parsing."""
        with patch.object(acl_parsers, "_parse_oracle_syntax") as mock_parse:
            mock_parse.return_value = FlextResult[dict[str, object]].ok(
                sample_acl_data["unified_acl"]
            )

            result = acl_parsers.parse_oracle_aci(sample_acl_data["oracle_aci"])

            assert result.is_success
            assert "target" in result.data
            assert "permissions" in result.data
            mock_parse.assert_called_once()

    def test_parse_oracle_aci_failure(
        self,
        acl_parsers: FlextLdapAclParsers,
    ) -> None:
        """Test Oracle ACI parsing failure."""
        with patch.object(acl_parsers, "_parse_oracle_syntax") as mock_parse:
            mock_parse.return_value = FlextResult[dict[str, object]].fail(
                "Parsing failed"
            )

            result = acl_parsers.parse_oracle_aci("invalid aci format")

            assert result.is_failure
            assert "Parsing failed" in result.error

    def test_parse_unified_acl_success(
        self,
        acl_parsers: FlextLdapAclParsers,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful unified ACL parsing."""
        with patch.object(acl_parsers, "_validate_unified_structure") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].ok(
                sample_acl_data["unified_acl"]
            )

            result = acl_parsers.parse_unified_acl(sample_acl_data["unified_acl"])

            assert result.is_success
            assert "target" in result.data
            assert "permissions" in result.data
            mock_validate.assert_called_once()

    def test_parse_unified_acl_failure(
        self,
        acl_parsers: FlextLdapAclParsers,
    ) -> None:
        """Test unified ACL parsing failure."""
        with patch.object(acl_parsers, "_validate_unified_structure") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].fail(
                "Validation failed"
            )

            invalid_acl = {"invalid": "data"}
            result = acl_parsers.parse_unified_acl(invalid_acl)

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_validate_acl_syntax_valid(self, acl_parsers: FlextLdapAclParsers) -> None:
        """Test validating valid ACL syntax."""
        result = acl_parsers.validate_acl_syntax(
            "openldap",
            'target="ldap:///dc=example,dc=com" version 3.0; acl "test"; allow (read) userdn="ldap:///uid=test,ou=people,dc=example,dc=com";',
        )

        assert result.is_success
        assert result.data is True

    def test_validate_acl_syntax_invalid(
        self, acl_parsers: FlextLdapAclParsers
    ) -> None:
        """Test validating invalid ACL syntax."""
        result = acl_parsers.validate_acl_syntax("openldap", "invalid syntax")

        assert result.is_failure
        assert "Invalid syntax" in result.error

    def test_extract_acl_components_success(
        self, acl_parsers: FlextLdapAclParsers
    ) -> None:
        """Test successful ACL components extraction."""
        with patch.object(acl_parsers, "_extract_components") as mock_extract:
            mock_extract.return_value = FlextResult[dict[str, object]].ok({
                "target": "dc=example,dc=com",
                "permissions": ["read", "write"],
                "subjects": ["uid=test,ou=people,dc=example,dc=com"],
            })

            result = acl_parsers.extract_acl_components(
                "openldap",
                'target="ldap:///dc=example,dc=com" version 3.0; acl "test"; allow (read,write) userdn="ldap:///uid=test,ou=people,dc=example,dc=com";',
            )

            assert result.is_success
            assert "target" in result.data
            assert "permissions" in result.data
            assert "subjects" in result.data
            mock_extract.assert_called_once()

    def test_extract_acl_components_failure(
        self, acl_parsers: FlextLdapAclParsers
    ) -> None:
        """Test ACL components extraction failure."""
        with patch.object(acl_parsers, "_extract_components") as mock_extract:
            mock_extract.return_value = FlextResult[dict[str, object]].fail(
                "Extraction failed"
            )

            result = acl_parsers.extract_acl_components("openldap", "invalid acl")

            assert result.is_failure
            assert "Extraction failed" in result.error


class TestFlextLdapAclModels:
    """Comprehensive test suite for FlextLdapAclModels."""

    def test_acl_models_initialization(self, acl_models: FlextLdapAclModels) -> None:
        """Test ACL models initialization."""
        assert acl_models is not None
        assert hasattr(acl_models, "_container")
        assert hasattr(acl_models, "_logger")

    def test_create_unified_acl_success(
        self,
        acl_models: FlextLdapAclModels,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful unified ACL creation."""
        with patch.object(acl_models, "_validate_unified_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })

            result = acl_models.create_unified_acl(sample_acl_data["unified_acl"])

            assert result.is_success
            assert "target" in result.data
            assert "permissions" in result.data
            mock_validate.assert_called_once()

    def test_create_unified_acl_failure(
        self,
        acl_models: FlextLdapAclModels,
    ) -> None:
        """Test unified ACL creation failure."""
        with patch.object(acl_models, "_validate_unified_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].fail(
                "Validation failed"
            )

            invalid_data = {"invalid": "data"}
            result = acl_models.create_unified_acl(invalid_data)

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_create_permission_entry_success(
        self, acl_models: FlextLdapAclModels
    ) -> None:
        """Test successful permission entry creation."""
        with patch.object(acl_models, "_validate_permission_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })

            permission_data = {
                "subject": "uid=test,ou=people,dc=example,dc=com",
                "subject_type": "user",
                "permissions": ["read", "write"],
                "scope": "subtree",
            }
            result = acl_models.create_permission_entry(permission_data)

            assert result.is_success
            assert "subject" in result.data
            assert "permissions" in result.data
            mock_validate.assert_called_once()

    def test_create_permission_entry_failure(
        self, acl_models: FlextLdapAclModels
    ) -> None:
        """Test permission entry creation failure."""
        with patch.object(acl_models, "_validate_permission_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].fail(
                "Validation failed"
            )

            invalid_data = {"invalid": "data"}
            result = acl_models.create_permission_entry(invalid_data)

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_validate_unified_data_success(
        self,
        acl_models: FlextLdapAclModels,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test successful unified data validation."""
        result = acl_models._validate_unified_data(sample_acl_data["unified_acl"])

        assert result.is_success
        assert "valid" in result.data

    def test_validate_unified_data_failure(
        self, acl_models: FlextLdapAclModels
    ) -> None:
        """Test unified data validation failure."""
        invalid_data = {"invalid": "data"}
        result = acl_models._validate_unified_data(invalid_data)

        assert result.is_failure
        assert "Invalid unified data" in result.error

    def test_validate_permission_data_success(
        self, acl_models: FlextLdapAclModels
    ) -> None:
        """Test successful permission data validation."""
        permission_data = {
            "subject": "uid=test,ou=people,dc=example,dc=com",
            "subject_type": "user",
            "permissions": ["read", "write"],
            "scope": "subtree",
        }
        result = acl_models._validate_permission_data(permission_data)

        assert result.is_success
        assert "valid" in result.data

    def test_validate_permission_data_failure(
        self, acl_models: FlextLdapAclModels
    ) -> None:
        """Test permission data validation failure."""
        invalid_data = {"invalid": "data"}
        result = acl_models._validate_permission_data(invalid_data)

        assert result.is_failure
        assert "Invalid permission data" in result.error


class TestAclIntegration:
    """Integration tests for ACL modules."""

    def test_acl_workflow_complete_conversion(
        self,
        acl_converters: FlextLdapAclConverters,
        acl_parsers: FlextLdapAclParsers,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test complete ACL workflow from parsing to conversion."""
        # Parse OpenLDAP ACI
        with patch.object(acl_parsers, "_parse_openldap_syntax") as mock_parse:
            mock_parse.return_value = FlextResult[dict[str, object]].ok(
                sample_acl_data["unified_acl"]
            )

            parse_result = acl_parsers.parse_openldap_aci(
                sample_acl_data["openldap_aci"]
            )
            assert parse_result.is_success

            # Convert to Oracle format
            with patch.object(
                acl_converters, "_convert_to_oracle_format"
            ) as mock_convert:
                mock_convert.return_value = FlextResult[str].ok("oracle acl format")

                convert_result = acl_converters.convert_unified_to_oracle(
                    parse_result.data
                )
                assert convert_result.is_success
                assert convert_result.data == "oracle acl format"

    def test_acl_management_complete_lifecycle(
        self,
        acl_manager: FlextLdapAclManager,
        sample_acl_data: dict[str, object],
    ) -> None:
        """Test complete ACL management lifecycle."""
        with (
            patch.object(acl_manager, "_validate_acl_data") as mock_validate,
            patch.object(acl_manager, "_store_acl") as mock_store,
            patch.object(acl_manager, "_retrieve_acl_storage") as mock_retrieve,
            patch.object(acl_manager, "_update_acl_storage") as mock_update,
            patch.object(acl_manager, "_remove_acl_storage") as mock_remove,
        ):
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })
            mock_store.return_value = FlextResult[str].ok("acl_id_123")
            mock_retrieve.return_value = FlextResult[dict[str, object]].ok(
                sample_acl_data["unified_acl"]
            )
            mock_update.return_value = FlextResult[bool].ok(True)
            mock_remove.return_value = FlextResult[bool].ok(True)

            # Create ACL
            create_result = acl_manager.create_acl(sample_acl_data["unified_acl"])
            assert create_result.is_success

            # Retrieve ACL
            get_result = acl_manager.get_acl(create_result.data)
            assert get_result.is_success

            # Update ACL
            update_result = acl_manager.update_acl(
                create_result.data, sample_acl_data["unified_acl"]
            )
            assert update_result.is_success

            # Delete ACL
            delete_result = acl_manager.delete_acl(create_result.data)
            assert delete_result.is_success
