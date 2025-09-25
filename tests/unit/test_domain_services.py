"""Comprehensive tests for FlextLdapDomainServices.

This module provides complete test coverage for the FlextLdapDomainServices class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import patch

from flext_core import FlextResult
from flext_ldap import FlextLdapDomainServices, FlextLdapModels


class TestFlextLdapDomainServices:
    """Comprehensive test suite for FlextLdapDomainServices."""

    def test_domain_services_initialization(
        self, domain_services: FlextLdapDomainServices
    ) -> None:
        """Test domain services initialization."""
        assert domain_services is not None
        assert hasattr(domain_services, "_container")
        assert hasattr(domain_services, "_logger")

    def test_user_management_create_user_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test successful user creation."""
        with (
            patch.object(domain_services, "_validate_user_data") as mock_validate,
            patch.object(domain_services, "_create_user_entry") as mock_create,
        ):
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})
            mock_create.return_value = FlextResult[bool].ok(True)

            result = domain_services.create_user(sample_user)

            assert result.is_success
            assert result.data is True
            mock_validate.assert_called_once_with(sample_user)
            mock_create.assert_called_once()

    def test_user_management_create_user_validation_failure(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test user creation with validation failure."""
        with patch.object(domain_services, "_validate_user_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict].fail("Validation failed")

            result = domain_services.create_user(sample_user)

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_user_management_create_user_creation_failure(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test user creation with creation failure."""
        with (
            patch.object(domain_services, "_validate_user_data") as mock_validate,
            patch.object(domain_services, "_create_user_entry") as mock_create,
        ):
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})
            mock_create.return_value = FlextResult[bool].fail("Creation failed")

            result = domain_services.create_user(sample_user)

            assert result.is_failure
            assert "Creation failed" in result.error

    def test_user_management_update_user_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test successful user update."""
        with (
            patch.object(domain_services, "_validate_user_data") as mock_validate,
            patch.object(domain_services, "_update_user_entry") as mock_update,
        ):
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})
            mock_update.return_value = FlextResult[bool].ok(True)

            result = domain_services.update_user(sample_user)

            assert result.is_success
            assert result.data is True
            mock_validate.assert_called_once_with(sample_user)
            mock_update.assert_called_once()

    def test_user_management_delete_user_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_dn: FlextLdapModels.DistinguishedName,
    ) -> None:
        """Test successful user deletion."""
        with patch.object(domain_services, "_delete_user_entry") as mock_delete:
            mock_delete.return_value = FlextResult[bool].ok(True)

            result = domain_services.delete_user(sample_dn)

            assert result.is_success
            assert result.data is True
            mock_delete.assert_called_once()

    def test_user_management_delete_user_failure(
        self,
        domain_services: FlextLdapDomainServices,
        sample_dn: FlextLdapModels.DistinguishedName,
    ) -> None:
        """Test user deletion failure."""
        with patch.object(domain_services, "_delete_user_entry") as mock_delete:
            mock_delete.return_value = FlextResult[bool].fail("Deletion failed")

            result = domain_services.delete_user(sample_dn)

            assert result.is_failure
            assert "Deletion failed" in result.error

    def test_user_management_find_user_by_dn_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_dn: FlextLdapModels.DistinguishedName,
    ) -> None:
        """Test successful user search by DN."""
        with patch.object(domain_services, "_search_user_by_dn") as mock_search:
            mock_search.return_value = FlextResult[FlextLdapModels.User].ok(
                FlextLdapModels.User(
                    uid="testuser",
                    cn="Test User",
                    sn="User",
                    mail="testuser@example.com",
                )
            )

            result = domain_services.find_user_by_dn(sample_dn)

            assert result.is_success
            assert result.data.uid == "testuser"
            mock_search.assert_called_once()

    def test_user_management_find_user_by_dn_not_found(
        self,
        domain_services: FlextLdapDomainServices,
        sample_dn: FlextLdapModels.DistinguishedName,
    ) -> None:
        """Test user search by DN when not found."""
        with patch.object(domain_services, "_search_user_by_dn") as mock_search:
            mock_search.return_value = FlextResult[FlextLdapModels.User].fail(
                "User not found"
            )

            result = domain_services.find_user_by_dn(sample_dn)

            assert result.is_failure
            assert "User not found" in result.error

    def test_user_management_find_users_by_filter_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_filter: FlextLdapModels.Filter,
    ) -> None:
        """Test successful user search by filter."""
        with patch.object(domain_services, "_search_users_by_filter") as mock_search:
            users = [
                FlextLdapModels.User(
                    uid="user1", cn="User 1", sn="One", mail="user1@example.com"
                ),
                FlextLdapModels.User(
                    uid="user2", cn="User 2", sn="Two", mail="user2@example.com"
                ),
            ]
            mock_search.return_value = FlextResult[list[FlextLdapModels.User]].ok(users)

            result = domain_services.find_users_by_filter(sample_filter)

            assert result.is_success
            assert len(result.data) == 2
            assert result.data[0].uid == "user1"
            assert result.data[1].uid == "user2"
            mock_search.assert_called_once()

    def test_group_management_create_group_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_group: FlextLdapModels.Group,
    ) -> None:
        """Test successful group creation."""
        with (
            patch.object(domain_services, "_validate_group_data") as mock_validate,
            patch.object(domain_services, "_create_group_entry") as mock_create,
        ):
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})
            mock_create.return_value = FlextResult[bool].ok(True)

            result = domain_services.create_group(sample_group)

            assert result.is_success
            assert result.data is True
            mock_validate.assert_called_once_with(sample_group)
            mock_create.assert_called_once()

    def test_group_management_create_group_validation_failure(
        self,
        domain_services: FlextLdapDomainServices,
        sample_group: FlextLdapModels.Group,
    ) -> None:
        """Test group creation with validation failure."""
        with patch.object(domain_services, "_validate_group_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict].fail("Validation failed")

            result = domain_services.create_group(sample_group)

            assert result.is_failure
            assert "Validation failed" in result.error

    def test_group_management_update_group_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_group: FlextLdapModels.Group,
    ) -> None:
        """Test successful group update."""
        with (
            patch.object(domain_services, "_validate_group_data") as mock_validate,
            patch.object(domain_services, "_update_group_entry") as mock_update,
        ):
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})
            mock_update.return_value = FlextResult[bool].ok(True)

            result = domain_services.update_group(sample_group)

            assert result.is_success
            assert result.data is True
            mock_validate.assert_called_once_with(sample_group)
            mock_update.assert_called_once()

    def test_group_management_delete_group_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_dn: FlextLdapModels.DistinguishedName,
    ) -> None:
        """Test successful group deletion."""
        with patch.object(domain_services, "_delete_group_entry") as mock_delete:
            mock_delete.return_value = FlextResult[bool].ok(True)

            result = domain_services.delete_group(sample_dn)

            assert result.is_success
            assert result.data is True
            mock_delete.assert_called_once()

    def test_group_management_find_group_by_dn_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_dn: FlextLdapModels.DistinguishedName,
    ) -> None:
        """Test successful group search by DN."""
        with patch.object(domain_services, "_search_group_by_dn") as mock_search:
            mock_search.return_value = FlextResult[FlextLdapModels.Group].ok(
                FlextLdapModels.Group(
                    cn="testgroup",
                    description="Test Group",
                    member=["uid=testuser,ou=people,dc=example,dc=com"],
                )
            )

            result = domain_services.find_group_by_dn(sample_dn)

            assert result.is_success
            assert result.data.cn == "testgroup"
            mock_search.assert_called_once()

    def test_group_management_add_member_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_group: FlextLdapModels.Group,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test successful member addition to group."""
        with patch.object(domain_services, "_add_member_to_group") as mock_add:
            mock_add.return_value = FlextResult[bool].ok(True)

            result = domain_services.add_member_to_group(sample_group, sample_user)

            assert result.is_success
            assert result.data is True
            mock_add.assert_called_once()

    def test_group_management_remove_member_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_group: FlextLdapModels.Group,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test successful member removal from group."""
        with patch.object(domain_services, "_remove_member_from_group") as mock_remove:
            mock_remove.return_value = FlextResult[bool].ok(True)

            result = domain_services.remove_member_from_group(sample_group, sample_user)

            assert result.is_success
            assert result.data is True
            mock_remove.assert_called_once()

    def test_group_management_get_group_members_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_group: FlextLdapModels.Group,
    ) -> None:
        """Test successful group members retrieval."""
        with patch.object(domain_services, "_get_group_members") as mock_get:
            members = [
                FlextLdapModels.User(
                    uid="user1", cn="User 1", sn="One", mail="user1@example.com"
                ),
                FlextLdapModels.User(
                    uid="user2", cn="User 2", sn="Two", mail="user2@example.com"
                ),
            ]
            mock_get.return_value = FlextResult[list[FlextLdapModels.User]].ok(members)

            result = domain_services.get_group_members(sample_group)

            assert result.is_success
            assert len(result.data) == 2
            assert result.data[0].uid == "user1"
            assert result.data[1].uid == "user2"
            mock_get.assert_called_once()

    def test_authentication_authenticate_user_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test successful user authentication."""
        with patch.object(
            domain_services, "_authenticate_user_credentials"
        ) as mock_auth:
            mock_auth.return_value = FlextResult[bool].ok(True)

            result = domain_services.authenticate_user(sample_user.uid, "password123")

            assert result.is_success
            assert result.data is True
            mock_auth.assert_called_once()

    def test_authentication_authenticate_user_failure(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test user authentication failure."""
        with patch.object(
            domain_services, "_authenticate_user_credentials"
        ) as mock_auth:
            mock_auth.return_value = FlextResult[bool].fail("Invalid credentials")

            result = domain_services.authenticate_user(sample_user.uid, "wrongpassword")

            assert result.is_failure
            assert "Invalid credentials" in result.error

    def test_authentication_change_password_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test successful password change."""
        with patch.object(domain_services, "_change_user_password") as mock_change:
            mock_change.return_value = FlextResult[bool].ok(True)

            result = domain_services.change_password(sample_user, "newpassword123")

            assert result.is_success
            assert result.data is True
            mock_change.assert_called_once()

    def test_authentication_reset_password_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test successful password reset."""
        with patch.object(domain_services, "_reset_user_password") as mock_reset:
            mock_reset.return_value = FlextResult[str].ok("temp_password_123")

            result = domain_services.reset_password(sample_user)

            assert result.is_success
            assert result.data == "temp_password_123"
            mock_reset.assert_called_once()

    def test_validation_validate_user_data_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test successful user data validation."""
        with patch.object(
            domain_services, "_validate_user_business_rules"
        ) as mock_validate:
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})

            result = domain_services._validate_user_data(sample_user)

            assert result.is_success
            assert result.data["valid"] is True
            mock_validate.assert_called_once()

    def test_validation_validate_user_data_failure(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test user data validation failure."""
        with patch.object(
            domain_services, "_validate_user_business_rules"
        ) as mock_validate:
            mock_validate.return_value = FlextResult[dict].fail(
                "Business rule violation"
            )

            result = domain_services._validate_user_data(sample_user)

            assert result.is_failure
            assert "Business rule violation" in result.error

    def test_validation_validate_group_data_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_group: FlextLdapModels.Group,
    ) -> None:
        """Test successful group data validation."""
        with patch.object(
            domain_services, "_validate_group_business_rules"
        ) as mock_validate:
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})

            result = domain_services._validate_group_data(sample_group)

            assert result.is_success
            assert result.data["valid"] is True
            mock_validate.assert_called_once()

    def test_validation_validate_group_data_failure(
        self,
        domain_services: FlextLdapDomainServices,
        sample_group: FlextLdapModels.Group,
    ) -> None:
        """Test group data validation failure."""
        with patch.object(
            domain_services, "_validate_group_business_rules"
        ) as mock_validate:
            mock_validate.return_value = FlextResult[dict].fail(
                "Business rule violation"
            )

            result = domain_services._validate_group_data(sample_group)

            assert result.is_failure
            assert "Business rule violation" in result.error

    def test_business_rules_validate_user_business_rules_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test successful user business rules validation."""
        result = domain_services._validate_user_business_rules(sample_user)

        assert result.is_success
        assert "valid" in result.data

    def test_business_rules_validate_user_business_rules_failure(
        self,
        domain_services: FlextLdapDomainServices,
    ) -> None:
        """Test user business rules validation failure."""
        # Create invalid user (empty uid)
        invalid_user = FlextLdapModels.User(
            uid="",  # Invalid empty uid
            cn="Test User",
            sn="User",
            mail="testuser@example.com",
        )

        result = domain_services._validate_user_business_rules(invalid_user)

        assert result.is_failure
        assert "uid" in result.error.lower()

    def test_business_rules_validate_group_business_rules_success(
        self,
        domain_services: FlextLdapDomainServices,
        sample_group: FlextLdapModels.Group,
    ) -> None:
        """Test successful group business rules validation."""
        result = domain_services._validate_group_business_rules(sample_group)

        assert result.is_success
        assert "valid" in result.data

    def test_business_rules_validate_group_business_rules_failure(
        self,
        domain_services: FlextLdapDomainServices,
    ) -> None:
        """Test group business rules validation failure."""
        # Create invalid group (empty cn)
        invalid_group = FlextLdapModels.Group(
            cn="",  # Invalid empty cn
            description="Test Group",
            member=["uid=testuser,ou=people,dc=example,dc=com"],
        )

        result = domain_services._validate_group_business_rules(invalid_group)

        assert result.is_failure
        assert "cn" in result.error.lower()

    def test_error_handling_connection_error(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test error handling for connection errors."""
        with (
            patch.object(domain_services, "_validate_user_data") as mock_validate,
            patch.object(domain_services, "_create_user_entry") as mock_create,
        ):
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})
            mock_create.return_value = FlextResult[bool].fail("Connection failed")

            result = domain_services.create_user(sample_user)

            assert result.is_failure
            assert "Connection failed" in result.error

    def test_error_handling_validation_error(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test error handling for validation errors."""
        with patch.object(domain_services, "_validate_user_data") as mock_validate:
            mock_validate.return_value = FlextResult[dict].fail("Email format invalid")

            result = domain_services.create_user(sample_user)

            assert result.is_failure
            assert "Email format invalid" in result.error

    def test_error_handling_permission_error(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test error handling for permission errors."""
        with (
            patch.object(domain_services, "_validate_user_data") as mock_validate,
            patch.object(domain_services, "_create_user_entry") as mock_create,
        ):
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})
            mock_create.return_value = FlextResult[bool].fail(
                "Insufficient permissions"
            )

            result = domain_services.create_user(sample_user)

            assert result.is_failure
            assert "Insufficient permissions" in result.error

    def test_integration_user_lifecycle(
        self,
        domain_services: FlextLdapDomainServices,
        sample_user: FlextLdapModels.User,
    ) -> None:
        """Test complete user lifecycle integration."""
        # Create user
        with (
            patch.object(domain_services, "_validate_user_data") as mock_validate,
            patch.object(domain_services, "_create_user_entry") as mock_create,
            patch.object(domain_services, "_search_user_by_dn") as mock_search,
            patch.object(domain_services, "_update_user_entry") as mock_update,
            patch.object(domain_services, "_delete_user_entry") as mock_delete,
        ):
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})
            mock_create.return_value = FlextResult[bool].ok(True)
            mock_search.return_value = FlextResult[FlextLdapModels.User].ok(sample_user)
            mock_update.return_value = FlextResult[bool].ok(True)
            mock_delete.return_value = FlextResult[bool].ok(True)

            # Create
            create_result = domain_services.create_user(sample_user)
            assert create_result.is_success

            # Find
            find_result = domain_services.find_user_by_dn(sample_user.dn)
            assert find_result.is_success

            # Update
            update_result = domain_services.update_user(sample_user)
            assert update_result.is_success

            # Delete
            delete_result = domain_services.delete_user(sample_user.dn)
            assert delete_result.is_success

    def test_integration_group_lifecycle(
        self,
        domain_services: FlextLdapDomainServices,
        sample_group: FlextLdapModels.Group,
    ) -> None:
        """Test complete group lifecycle integration."""
        # Create group
        with (
            patch.object(domain_services, "_validate_group_data") as mock_validate,
            patch.object(domain_services, "_create_group_entry") as mock_create,
            patch.object(domain_services, "_search_group_by_dn") as mock_search,
            patch.object(domain_services, "_update_group_entry") as mock_update,
            patch.object(domain_services, "_delete_group_entry") as mock_delete,
        ):
            mock_validate.return_value = FlextResult[dict].ok({"valid": True})
            mock_create.return_value = FlextResult[bool].ok(True)
            mock_search.return_value = FlextResult[FlextLdapModels.Group].ok(
                sample_group
            )
            mock_update.return_value = FlextResult[bool].ok(True)
            mock_delete.return_value = FlextResult[bool].ok(True)

            # Create
            create_result = domain_services.create_group(sample_group)
            assert create_result.is_success

            # Find
            find_result = domain_services.find_group_by_dn(sample_group.dn)
            assert find_result.is_success

            # Update
            update_result = domain_services.update_group(sample_group)
            assert update_result.is_success

            # Delete
            delete_result = domain_services.delete_group(sample_group.dn)
            assert delete_result.is_success
