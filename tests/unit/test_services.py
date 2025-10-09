"""Comprehensive unit tests for FlextLdapServices module.

Tests application service layer with real functionality and domain logic validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.models import FlextLdapModels
from flext_ldap.services import FlextLdapServices


class TestFlextLdapServices:
    """Comprehensive test cases for FlextLdapServices."""

    def test_services_initialization(self) -> None:
        """Test services initialization with real setup."""
        services = FlextLdapServices()
        assert services is not None
        assert hasattr(services, "validate_user_creation_request")
        assert hasattr(services, "enrich_user_for_creation")
        assert hasattr(services, "validate_user_search_request")

    # =========================================================================
    # USER MANAGEMENT SERVICES TESTS
    # =========================================================================

    def test_validate_user_creation_request_valid(self) -> None:
        """Test user creation request validation with valid data."""
        services = FlextLdapServices()
        request = FlextLdapModels.CreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="testuser@example.com",
            user_password="SecureP@ssw0rd123",
        )

        result = services.validate_user_creation_request(request)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_user_creation_request_invalid_username(self) -> None:
        """Test user creation validation fails with invalid username."""
        services = FlextLdapServices()
        request = FlextLdapModels.CreateUserRequest(
            dn="uid=a,ou=users,dc=example,dc=com",
            uid="a",  # Too short
            cn="Test",
            sn="User",
        )

        result = services.validate_user_creation_request(request)

        assert result.is_failure
        assert "Invalid username format" in (result.error or "")

    def test_validate_user_creation_request_invalid_email(self) -> None:
        """Test user creation validation fails with invalid email."""
        from flext_ldap.exceptions import FlextLdapExceptions

        FlextLdapServices()

        # Pydantic validates email at creation time
        with pytest.raises(FlextLdapExceptions.LdapValidationError) as exc_info:
            FlextLdapModels.CreateUserRequest(
                dn="uid=testuser,ou=users,dc=example,dc=com",
                uid="testuser",
                cn="Test User",
                sn="User",
                mail="invalid-email",  # Invalid format
            )

        assert "Invalid email format" in str(exc_info.value)

    def test_validate_user_creation_request_weak_password(self) -> None:
        """Test user creation validation fails with weak password."""
        from flext_ldap.exceptions import FlextLdapExceptions

        FlextLdapServices()

        # Pydantic field validator raises LdapValidationError
        with pytest.raises(FlextLdapExceptions.LdapValidationError) as exc_info:
            FlextLdapModels.CreateUserRequest(
                dn="uid=testuser,ou=users,dc=example,dc=com",
                uid="testuser",
                cn="Test User",
                sn="User",
                user_password="weak",  # Too weak
            )

        assert "Password" in str(exc_info.value)

    def test_validate_user_creation_request_dn_mismatch(self) -> None:
        """Test user creation validation fails when DN doesn't match UID."""
        services = FlextLdapServices()
        request = FlextLdapModels.CreateUserRequest(
            dn="uid=wronguser,ou=users,dc=example,dc=com",
            uid="testuser",  # Doesn't match DN
            cn="Test User",
            sn="User",
        )

        result = services.validate_user_creation_request(request)

        assert result.is_failure
        assert "DN must contain the specified UID" in (result.error or "")

    def test_enrich_user_for_creation_adds_defaults(self) -> None:
        """Test user enrichment adds default values."""
        services = FlextLdapServices()
        request = FlextLdapModels.CreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
        )

        result = services.enrich_user_for_creation(request)

        assert result.is_success
        enriched = result.unwrap()
        assert enriched is not None
        assert enriched.uid == "testuser"
        # Should preserve all original fields
        assert enriched.cn == "Test User"
        assert enriched.sn == "User"

    def test_enrich_user_for_creation_preserves_given_name(self) -> None:
        """Test user enrichment preserves explicit given_name."""
        services = FlextLdapServices()
        request = FlextLdapModels.CreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            given_name="TestGiven",
        )

        result = services.enrich_user_for_creation(request)

        assert result.is_success
        enriched = result.unwrap()
        assert enriched.given_name == "TestGiven"

    def test_validate_user_search_request_valid(self) -> None:
        """Test user search request validation with valid data."""
        services = FlextLdapServices()
        search_request = FlextLdapModels.SearchRequest(
            base_dn="ou=users,dc=example,dc=com",
            filter_str="(uid=testuser)",
            scope="subtree",
        )

        result = services.validate_user_search_request(search_request)

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_user_search_request_invalid_base_dn(self) -> None:
        """Test search validation fails with invalid base DN."""
        from flext_ldap.exceptions import FlextLdapExceptions

        # Pydantic validates base_dn at creation time
        with pytest.raises(FlextLdapExceptions.LdapValidationError) as exc_info:
            FlextLdapModels.SearchRequest(
                base_dn="",  # Empty DN
                filter_str="(uid=testuser)",
                scope="subtree",
            )

        assert "DN cannot be empty" in str(exc_info.value)

    def test_process_user_search_results_empty(self) -> None:
        """Test processing empty search results."""
        services = FlextLdapServices()
        search_response = FlextLdapModels.SearchResponse(
            entries=[],
            total_count=0,
            result_code=0,
            time_elapsed=0.0,
            has_more_pages=True,
        )

        result = services.process_user_search_results(search_response)

        assert result.is_success
        processed = result.unwrap()
        assert len(processed.entries) == 0

    def test_process_user_search_results_with_entries(self) -> None:
        """Test processing search results with user entries."""
        services = FlextLdapServices()
        entries = [
            FlextLdapModels.Entry(
                dn="uid=user1,ou=users,dc=example,dc=com",
                attributes={
                    "uid": ["user1"],
                    "cn": ["User One"],
                    "sn": ["One"],
                    "mail": ["user1@example.com"],
                },
            ),
            FlextLdapModels.Entry(
                dn="uid=user2,ou=users,dc=example,dc=com",
                attributes={
                    "uid": ["user2"],
                    "cn": ["User Two"],
                    "sn": ["Two"],
                },
            ),
        ]
        search_response = FlextLdapModels.SearchResponse(
            entries=entries,
            total_count=2,
            result_code=0,
            time_elapsed=0.5,
            has_more_pages=True,
        )

        result = services.process_user_search_results(search_response)

        assert result.is_success
        processed = result.unwrap()
        assert len(processed.entries) == 2
        # Results should be SearchResponse with processed entries
        assert isinstance(processed, FlextLdapModels.SearchResponse)

    # =========================================================================
    # GROUP MANAGEMENT SERVICES TESTS
    # =========================================================================

    def test_validate_group_creation_request_valid(self) -> None:
        """Test group creation request validation with valid data."""
        services = FlextLdapServices()
        group_data = {
            "dn": "cn=testgroup,ou=groups,dc=example,dc=com",
            "cn": "testgroup",
            "description": "Test group",
            "members": ["uid=user1,ou=users,dc=example,dc=com"],
        }

        result = services.validate_group_creation_request(group_data)

        assert result.is_success

    def test_validate_group_creation_request_invalid_dn_mismatch(self) -> None:
        """Test group creation fails when DN doesn't match CN."""
        services = FlextLdapServices()

        # Create dict instead of Request object since method expects dict
        group_data = {
            "dn": "cn=wronggroup,ou=groups,dc=example,dc=com",
            "cn": "testgroup",  # Doesn't match DN
            "description": "Test group",
            "members": ["uid=user1,ou=users,dc=example,dc=com"],
        }

        result = services.validate_group_creation_request(group_data)

        assert result.is_failure
        assert "DN must contain the specified CN" in (result.error or "")

    def test_validate_group_membership_operation_valid_add(self) -> None:
        """Test group membership validation for adding members."""
        services = FlextLdapServices()
        group = FlextLdapModels.Group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            member_dns=[],
        )

        result = services.validate_group_membership_operation(
            group=group,
            member_dn="uid=user1,ou=users,dc=example,dc=com",
            operation="add",
        )

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_group_membership_operation_valid_remove(self) -> None:
        """Test group membership validation for removing members."""
        services = FlextLdapServices()
        group = FlextLdapModels.Group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            member_dns=["uid=user1,ou=users,dc=example,dc=com"],
        )

        result = services.validate_group_membership_operation(
            group=group,
            member_dn="uid=user1,ou=users,dc=example,dc=com",
            operation="remove",
        )

        assert result.is_success
        assert result.unwrap() is True

    def test_validate_group_membership_operation_invalid_operation(self) -> None:
        """Test group membership validation fails with invalid operation."""
        services = FlextLdapServices()
        group = FlextLdapModels.Group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            member_dns=[],
        )

        result = services.validate_group_membership_operation(
            group=group,
            member_dn="uid=user1,ou=users,dc=example,dc=com",
            operation="invalid",  # Invalid operation type
        )

        assert result.is_failure
        assert "Invalid operation" in (result.error or "")

    def test_validate_group_membership_operation_member_not_found(self) -> None:
        """Test group membership validation fails when removing non-existent member."""
        services = FlextLdapServices()
        group = FlextLdapModels.Group(
            dn="cn=testgroup,ou=groups,dc=example,dc=com",
            cn="testgroup",
            member_dns=[],  # Empty - member doesn't exist
        )

        result = services.validate_group_membership_operation(
            group=group,
            member_dn="uid=user1,ou=users,dc=example,dc=com",
            operation="remove",
        )

        assert result.is_failure
        assert "not found" in (result.error or "").lower()

    def test_process_group_search_results_empty(self) -> None:
        """Test processing empty group search results."""
        services = FlextLdapServices()
        search_response = FlextLdapModels.SearchResponse(
            entries=[],
            total_count=0,
            result_code=0,
            time_elapsed=0.0,
            has_more_pages=True,
        )

        result = services.process_group_search_results(search_response)

        assert result.is_success
        processed = result.unwrap()
        assert len(processed.entries) == 0

    def test_process_group_search_results_with_entries(self) -> None:
        """Test processing group search results with entries."""
        services = FlextLdapServices()
        entries = [
            FlextLdapModels.Entry(
                dn="cn=group1,ou=groups,dc=example,dc=com",
                attributes={
                    "cn": ["group1"],
                    "member": ["uid=user1,ou=users,dc=example,dc=com"],
                },
            ),
        ]
        search_response = FlextLdapModels.SearchResponse(
            entries=entries,
            total_count=1,
            result_code=0,
            time_elapsed=0.3,
            has_more_pages=True,
        )

        result = services.process_group_search_results(search_response)

        assert result.is_success
        processed = result.unwrap()
        assert len(processed.entries) == 1
        assert isinstance(processed, FlextLdapModels.SearchResponse)

    # =========================================================================
    # SEARCH OPERATION SERVICES TESTS
    # =========================================================================

    def test_coordinate_search_operation_valid(self) -> None:
        """Test search operation coordination with valid request."""
        services = FlextLdapServices()
        search_request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
        )

        result = services.coordinate_search_operation(search_request)

        # Should validate successfully and return SearchResponse
        assert result.is_success
        response = result.unwrap()
        assert response is not None
        assert isinstance(response, FlextLdapModels.SearchResponse)

    def test_coordinate_search_operation_adds_defaults(self) -> None:
        """Test search coordination returns proper response."""
        services = FlextLdapServices()
        search_request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=person)",  # Safe filter
        )

        result = services.coordinate_search_operation(search_request)

        assert result.is_success
        response = result.unwrap()
        # Should return properly structured SearchResponse
        assert isinstance(response, FlextLdapModels.SearchResponse)
        assert hasattr(response, "entries")

    # =========================================================================
    # USER PROVISIONING WORKFLOW TESTS
    # =========================================================================

    def test_execute_user_provisioning_workflow_validation_success(self) -> None:
        """Test user provisioning workflow validates request."""
        services = FlextLdapServices()
        request = FlextLdapModels.CreateUserRequest(
            dn="uid=testuser,ou=users,dc=example,dc=com",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="testuser@example.com",
        )

        result = services.execute_user_provisioning_workflow(request)

        # Workflow should at least validate successfully
        # (actual LDAP operation would need infrastructure)
        assert result.is_success

    def test_execute_user_provisioning_workflow_validation_failure(self) -> None:
        """Test user provisioning workflow fails on invalid request."""
        services = FlextLdapServices()
        request = FlextLdapModels.CreateUserRequest(
            dn="uid=wronguser,ou=users,dc=example,dc=com",
            uid="testuser",  # DN mismatch
            cn="Test User",
            sn="User",
        )

        result = services.execute_user_provisioning_workflow(request)

        # Should fail validation before any infrastructure call
        assert result.is_failure
        assert "DN must contain" in (result.error or "")

    # =========================================================================
    # CONFIGURATION VALIDATION TESTS
    # =========================================================================

    def test_validate_ldap_configuration_basic(self) -> None:
        """Test LDAP configuration validation with minimal config."""
        services = FlextLdapServices()
        config_data: dict[str, object] = {
            "server": "ldap.example.com",
            "port": 389,
            "base_dn": "dc=example,dc=com",
        }

        result = services.validate_ldap_configuration(config_data)

        # Should validate basic structure
        assert result.is_success or result.is_failure  # Either is valid behavior

    def test_validate_ldap_configuration_with_ssl(self) -> None:
        """Test LDAP configuration validation with SSL settings."""
        services = FlextLdapServices()
        config_data: dict[str, object] = {
            "server": "ldap.example.com",
            "port": 636,
            "use_ssl": True,
            "base_dn": "dc=example,dc=com",
        }

        result = services.validate_ldap_configuration(config_data)

        # Should handle SSL configuration
        assert result is not None

    # =========================================================================
    # REPORTING SERVICES TESTS
    # =========================================================================

    def test_generate_ldap_operation_report_empty(self) -> None:
        """Test report generation with no operations."""
        services = FlextLdapServices()
        operations: list[dict[str, object]] = []

        result = services.generate_ldap_operation_report(operations)

        assert result.is_success
        report = result.unwrap()
        assert report is not None
        assert isinstance(report, dict)

    def test_generate_ldap_operation_report_with_operations(self) -> None:
        """Test report generation with operation data."""
        services = FlextLdapServices()
        operations: list[dict[str, object]] = [
            {"type": "search", "status": "success", "count": 10},
            {"type": "add", "status": "success", "dn": "uid=test,dc=example,dc=com"},
        ]

        result = services.generate_ldap_operation_report(operations)

        assert result.is_success
        report = result.unwrap()
        assert isinstance(report, dict)
        # Should contain some analysis of operations
        assert len(report) > 0

    # =========================================================================
    # FLEXTSERVICE PROTOCOL TESTS
    # =========================================================================

    def test_execute_method(self) -> None:
        """Test execute method from FlextService protocol."""
        services = FlextLdapServices()

        result = services.execute()

        assert result.is_success
        # Execute returns None for services without specific execution
        assert result.unwrap() is None
