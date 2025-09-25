"""Comprehensive tests for FlextLdapAPI.

This module provides complete test coverage for the FlextLdapAPI class
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from flext_core import FlextResult
from flext_ldap import FlextLdapAPI, FlextLdapModels


class TestFlextLdapAPI:
    """Comprehensive test suite for FlextLdapAPI."""

    def test_api_initialization(self, ldap_api: FlextLdapAPI) -> None:
        """Test API initialization."""
        assert ldap_api is not None
        assert hasattr(ldap_api, "_container")
        assert hasattr(ldap_api, "_logger")

    def test_connect_success(
        self,
        ldap_api: FlextLdapAPI,
        ldap_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test successful API connection."""
        with (
            patch.object(ldap_api, "_create_client") as mock_create_client,
            patch.object(ldap_api, "_establish_connection") as mock_connect,
        ):
            mock_client = MagicMock()
            mock_create_client.return_value = FlextResult[object].ok(mock_client)
            mock_connect.return_value = FlextResult[bool].ok(True)

            result = ldap_api.connect(ldap_config)

            assert result.is_success
            assert result.data is True
            mock_create_client.assert_called_once()
            mock_connect.assert_called_once()

    def test_connect_failure(
        self,
        ldap_api: FlextLdapAPI,
        ldap_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test API connection failure."""
        with patch.object(ldap_api, "_create_client") as mock_create_client:
            mock_create_client.return_value = FlextResult[object].fail(
                "Client creation failed"
            )

            result = ldap_api.connect(ldap_config)

            assert result.is_failure
            assert "Client creation failed" in result.error

#     def test_disconnect_success(self, ldap_api: FlextLdapAPI) -> None:
#         """Test successful API disconnection."""
#         with patch.object(ldap_api, "_close_connection") as mock_close:
#             mock_close.return_value = FlextResult[bool].ok(True)
#
#             result = ldap_api.disconnect()
#
#             assert result.is_success
#             assert result.data is True
#             mock_close.assert_called_once()
#
#     def test_disconnect_failure(self, ldap_api: FlextLdapAPI) -> None:
#         """Test API disconnection failure."""
#         with patch.object(ldap_api, "_close_connection") as mock_close:
#             mock_close.return_value = FlextResult[bool].fail("Disconnect failed")
#
#             result = ldap_api.disconnect()
#
#             assert result.is_failure
#             assert "Disconnect failed" in result.error
#
#     def test_search_success(
#         self,
#         ldap_api: FlextLdapAPI,
#     ) -> None:
        """Test successful API search."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_search") as mock_search,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_search.return_value = FlextResult[list[dict[str, object]]].ok([
                {
                    "dn": "uid=testuser,ou=people,dc=example,dc=com",
                    "attributes": {"cn": ["Test User"], "sn": ["User"]},
                }
            ])

            result = ldap_api.search(
                base_dn="dc=example,dc=com",
                search_filter="(objectClass=person)",
                attributes=["cn", "sn"],
            )

            assert result.is_success
            assert len(result.data) == 1
            assert result.data[0]["dn"] == "uid=testuser,ou=people,dc=example,dc=com"
            mock_ensure.assert_called_once()
            mock_search.assert_called_once()

    def test_search_not_connected(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test API search when not connected."""
        with patch.object(ldap_api, "_ensure_connected") as mock_ensure:
            mock_ensure.return_value = FlextResult[bool].fail("Not connected")

            result = ldap_api.search(
                base_dn="dc=example,dc=com",
                search_filter="(objectClass=person)",
                attributes=["cn", "sn"],
            )

            assert result.is_failure
            assert "Not connected" in result.error

    def test_search_failure(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test API search failure."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_search") as mock_search,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_search.return_value = FlextResult[list[dict[str, object]]].fail(
                "Search failed"
            )

            result = ldap_api.search(
                base_dn="dc=example,dc=com",
                search_filter="(objectClass=person)",
                attributes=["cn", "sn"],
            )

            assert result.is_failure
            assert "Search failed" in result.error

    def test_add_entry_success(
        self,
        ldap_api: FlextLdapAPI,
        test_user_data: dict[str, object],
    ) -> None:
        """Test successful API add entry."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_add") as mock_add,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_add.return_value = FlextResult[bool].ok(True)

            result = ldap_api.add_entry(
                dn="uid=testuser,ou=people,dc=example,dc=com",
                attributes=test_user_data["attributes"],
            )

            assert result.is_success
            assert result.data is True
            mock_ensure.assert_called_once()
            mock_add.assert_called_once()

    def test_add_entry_failure(
        self,
        ldap_api: FlextLdapAPI,
        test_user_data: dict[str, object],
    ) -> None:
        """Test API add entry failure."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_add") as mock_add,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_add.return_value = FlextResult[bool].fail("Add failed")

            result = ldap_api.add_entry(
                dn="uid=testuser,ou=people,dc=example,dc=com",
                attributes=test_user_data["attributes"],
            )

            assert result.is_failure
            assert "Add failed" in result.error

    def test_modify_entry_success(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test successful API modify entry."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_modify") as mock_modify,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_modify.return_value = FlextResult[bool].ok(True)

            changes = {"cn": [("MODIFY_REPLACE", ["New Name"])]}
            result = ldap_api.modify_entry(
                dn="uid=testuser,ou=people,dc=example,dc=com", changes=changes
            )

            assert result.is_success
            assert result.data is True
            mock_ensure.assert_called_once()
            mock_modify.assert_called_once()

    def test_modify_entry_failure(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test API modify entry failure."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_modify") as mock_modify,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_modify.return_value = FlextResult[bool].fail("Modify failed")

            changes = {"cn": [("MODIFY_REPLACE", ["New Name"])]}
            result = ldap_api.modify_entry(
                dn="uid=testuser,ou=people,dc=example,dc=com", changes=changes
            )

            assert result.is_failure
            assert "Modify failed" in result.error

    def test_delete_entry_success(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test successful API delete entry."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_delete") as mock_delete,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_delete.return_value = FlextResult[bool].ok(True)

            result = ldap_api.delete_entry("uid=testuser,ou=people,dc=example,dc=com")

            assert result.is_success
            assert result.data is True
            mock_ensure.assert_called_once()
            mock_delete.assert_called_once()

    def test_delete_entry_failure(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test API delete entry failure."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_delete") as mock_delete,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_delete.return_value = FlextResult[bool].fail("Delete failed")

            result = ldap_api.delete_entry("uid=testuser,ou=people,dc=example,dc=com")

            assert result.is_failure
            assert "Delete failed" in result.error

    def test_is_connected_true(self, ldap_api: FlextLdapAPI) -> None:
        """Test is_connected when connected."""
        with patch.object(ldap_api, "_check_connection_status") as mock_check:
            mock_check.return_value = FlextResult[bool].ok(True)

            result = ldap_api.is_connected()

            assert result.is_success
            assert result.data is True
            mock_check.assert_called_once()

    def test_is_connected_false(self, ldap_api: FlextLdapAPI) -> None:
        """Test is_connected when not connected."""
        with patch.object(ldap_api, "_check_connection_status") as mock_check:
            mock_check.return_value = FlextResult[bool].ok(False)

            result = ldap_api.is_connected()

            assert result.is_success
            assert result.data is False
            mock_check.assert_called_once()

    def test_get_connection_info_success(self, ldap_api: FlextLdapAPI) -> None:
        """Test successful connection info retrieval."""
        with patch.object(ldap_api, "_retrieve_connection_info") as mock_retrieve:
            mock_info = {
                "server_uri": "ldap://localhost:389",
                "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                "base_dn": "dc=example,dc=com",
                "connected": True,
            }
            mock_retrieve.return_value = FlextResult[dict[str, object]].ok(mock_info)

            result = ldap_api.get_connection_info()

            assert result.is_success
            assert result.data["server_uri"] == "ldap://localhost:389"
            assert result.data["connected"] is True
            mock_retrieve.assert_called_once()

    def test_get_connection_info_failure(self, ldap_api: FlextLdapAPI) -> None:
        """Test connection info retrieval failure."""
        with patch.object(ldap_api, "_retrieve_connection_info") as mock_retrieve:
            mock_retrieve.return_value = FlextResult[dict[str, object]].fail(
                "Info retrieval failed"
            )

            result = ldap_api.get_connection_info()

            assert result.is_failure
            assert "Info retrieval failed" in result.error

    def test_validate_config_success(
        self,
        ldap_api: FlextLdapAPI,
        ldap_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test successful config validation."""
        with patch.object(ldap_api, "_validate_connection_config") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].ok({
                "valid": True
            })

            result = ldap_api.validate_config(ldap_config)

            assert result.is_success
            assert result.data["valid"] is True
            mock_validate.assert_called_once()

    def test_validate_config_failure(
        self,
        ldap_api: FlextLdapAPI,
        ldap_config_invalid: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test config validation failure."""
        with patch.object(ldap_api, "_validate_connection_config") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].fail(
                "Config validation failed"
            )

            result = ldap_api.validate_config(ldap_config_invalid)

            assert result.is_failure
            assert "Config validation failed" in result.error

    def test_bulk_operations_bulk_search_success(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test successful bulk search operations."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_bulk_search") as mock_bulk_search,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_bulk_search.return_value = FlextResult[
                list[list[dict[str, object]]]
            ].ok([
                [
                    {
                        "dn": "uid=user1,ou=people,dc=example,dc=com",
                        "attributes": {"cn": ["User 1"]},
                    }
                ],
                [
                    {
                        "dn": "uid=user2,ou=people,dc=example,dc=com",
                        "attributes": {"cn": ["User 2"]},
                    }
                ],
            ])

            search_requests = [
                {
                    "base_dn": "dc=example,dc=com",
                    "search_filter": "(objectClass=person)",
                    "attributes": ["cn", "sn"],
                },
                {
                    "base_dn": "dc=example,dc=com",
                    "search_filter": "(objectClass=group)",
                    "attributes": ["cn", "description"],
                },
            ]
            result = ldap_api.bulk_search(search_requests)

            assert result.is_success
            assert len(result.data) == 2
            assert len(result.data[0]) == 1
            assert len(result.data[1]) == 1
            mock_ensure.assert_called_once()
            mock_bulk_search.assert_called_once()

    def test_bulk_operations_bulk_add_success(
        self,
        ldap_api: FlextLdapAPI,
        multiple_test_users: list[dict[str, object]],
    ) -> None:
        """Test successful bulk add operations."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_bulk_add") as mock_bulk_add,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_bulk_add.return_value = FlextResult[list[bool]].ok([True, True, True])

            add_requests = [
                {"dn": user["dn"], "attributes": user["attributes"]}
                for user in multiple_test_users
            ]
            result = ldap_api.bulk_add(add_requests)

            assert result.is_success
            assert len(result.data) == 3
            assert all(result.data)
            mock_ensure.assert_called_once()
            mock_bulk_add.assert_called_once()

    def test_bulk_operations_bulk_modify_success(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test successful bulk modify operations."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_bulk_modify") as mock_bulk_modify,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_bulk_modify.return_value = FlextResult[list[bool]].ok([True, True])

            modify_requests = [
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "changes": {"cn": [("MODIFY_REPLACE", ["New Name 1"])]},
                },
                {
                    "dn": "uid=user2,ou=people,dc=example,dc=com",
                    "changes": {"cn": [("MODIFY_REPLACE", ["New Name 2"])]},
                },
            ]
            result = ldap_api.bulk_modify(modify_requests)

            assert result.is_success
            assert len(result.data) == 2
            assert all(result.data)
            mock_ensure.assert_called_once()
            mock_bulk_modify.assert_called_once()

    def test_bulk_operations_bulk_delete_success(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test successful bulk delete operations."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_bulk_delete") as mock_bulk_delete,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_bulk_delete.return_value = FlextResult[list[bool]].ok([True, True])

            delete_requests = [
                "uid=user1,ou=people,dc=example,dc=com",
                "uid=user2,ou=people,dc=example,dc=com",
            ]
            result = ldap_api.bulk_delete(delete_requests)

            assert result.is_success
            assert len(result.data) == 2
            assert all(result.data)
            mock_ensure.assert_called_once()
            mock_bulk_delete.assert_called_once()

    def test_error_handling_connection_error(
        self,
        ldap_api: FlextLdapAPI,
        ldap_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test error handling for connection errors."""
        with patch.object(ldap_api, "_create_client") as mock_create_client:
            mock_create_client.return_value = FlextResult[object].fail(
                "Connection failed"
            )

            result = ldap_api.connect(ldap_config)

            assert result.is_failure
            assert "Connection failed" in result.error

    def test_error_handling_permission_error(
        self,
        ldap_api: FlextLdapAPI,
        test_user_data: dict[str, object],
    ) -> None:
        """Test error handling for permission errors."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_add") as mock_add,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_add.return_value = FlextResult[bool].fail("Insufficient permissions")

            result = ldap_api.add_entry(
                dn="uid=testuser,ou=people,dc=example,dc=com",
                attributes=test_user_data["attributes"],
            )

            assert result.is_failure
            assert "Insufficient permissions" in result.error

    def test_error_handling_validation_error(
        self,
        ldap_api: FlextLdapAPI,
        ldap_config_invalid: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test error handling for validation errors."""
        with patch.object(ldap_api, "_validate_connection_config") as mock_validate:
            mock_validate.return_value = FlextResult[dict[str, object]].fail(
                "Invalid configuration"
            )

            result = ldap_api.validate_config(ldap_config_invalid)

            assert result.is_failure
            assert "Invalid configuration" in result.error

    def test_api_integration_complete_workflow(
        self,
        ldap_api: FlextLdapAPI,
        ldap_config: FlextLdapModels.ConnectionConfig,
        test_user_data: dict[str, object],
    ) -> None:
        """Test complete API workflow integration."""
        with (
            patch.object(ldap_api, "_create_client") as mock_create_client,
            patch.object(ldap_api, "_establish_connection") as mock_connect,
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_add") as mock_add,
            patch.object(ldap_api, "_perform_search") as mock_search,
            patch.object(ldap_api, "_perform_modify") as mock_modify,
            patch.object(ldap_api, "_perform_delete") as mock_delete,
            patch.object(ldap_api, "_close_connection") as mock_close,
        ):
            mock_client = MagicMock()
            mock_create_client.return_value = FlextResult[object].ok(mock_client)
            mock_connect.return_value = FlextResult[bool].ok(True)
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_add.return_value = FlextResult[bool].ok(True)
            mock_search.return_value = FlextResult[list[dict[str, object]]].ok([
                {
                    "dn": "uid=testuser,ou=people,dc=example,dc=com",
                    "attributes": {"cn": ["Test User"]},
                }
            ])
            mock_modify.return_value = FlextResult[bool].ok(True)
            mock_delete.return_value = FlextResult[bool].ok(True)
            mock_close.return_value = FlextResult[bool].ok(True)

            # Complete workflow
            connect_result = ldap_api.connect(ldap_config)
            assert connect_result.is_success

            add_result = ldap_api.add_entry(
                dn="uid=testuser,ou=people,dc=example,dc=com",
                attributes=test_user_data["attributes"],
            )
            assert add_result.is_success

            search_result = ldap_api.search(
                base_dn="dc=example,dc=com",
                search_filter="(objectClass=person)",
                attributes=["cn", "sn"],
            )
            assert search_result.is_success

            modify_result = ldap_api.modify_entry(
                dn="uid=testuser,ou=people,dc=example,dc=com",
                changes={"cn": [("MODIFY_REPLACE", ["Updated Name"])]},
            )
            assert modify_result.is_success

            delete_result = ldap_api.delete_entry(
                "uid=testuser,ou=people,dc=example,dc=com"
            )
            assert delete_result.is_success

            disconnect_result = ldap_api.disconnect()
            assert disconnect_result.is_success

    def test_api_performance_bulk_operations(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test API performance with bulk operations."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_bulk_search") as mock_bulk_search,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            # Mock bulk search with 100 results
            bulk_results = [
                [
                    {
                        "dn": f"uid=user{i},ou=people,dc=example,dc=com",
                        "attributes": {"cn": [f"User {i}"]},
                    }
                ]
                for i in range(100)
            ]
            mock_bulk_search.return_value = FlextResult[
                list[list[dict[str, object]]]
            ].ok(bulk_results)

            search_requests = [
                {
                    "base_dn": "dc=example,dc=com",
                    "search_filter": "(objectClass=person)",
                    "attributes": ["cn", "sn"],
                }
                for _ in range(100)
            ]
            result = ldap_api.bulk_search(search_requests)

            assert result.is_success
            assert len(result.data) == 100
            mock_ensure.assert_called_once()
            mock_bulk_search.assert_called_once()

    def test_api_consistency_error_handling(
        self,
        ldap_api: FlextLdapAPI,
    ) -> None:
        """Test consistent error handling across API methods."""
        with (
            patch.object(ldap_api, "_ensure_connected") as mock_ensure,
            patch.object(ldap_api, "_perform_search") as mock_search,
            patch.object(ldap_api, "_perform_add") as mock_add,
            patch.object(ldap_api, "_perform_modify") as mock_modify,
            patch.object(ldap_api, "_perform_delete") as mock_delete,
        ):
            mock_ensure.return_value = FlextResult[bool].ok(True)
            mock_search.return_value = FlextResult[list[dict[str, object]]].fail(
                "Search error"
            )
            mock_add.return_value = FlextResult[bool].fail("Add error")
            mock_modify.return_value = FlextResult[bool].fail("Modify error")
            mock_delete.return_value = FlextResult[bool].fail("Delete error")

            # Test consistent error handling
            search_result = ldap_api.search(
                "dc=example,dc=com", "(objectClass=person)", ["cn"]
            )
            assert search_result.is_failure
            assert "Search error" in search_result.error

            add_result = ldap_api.add_entry(
                "uid=test,ou=people,dc=example,dc=com", {"cn": ["Test"]}
            )
            assert add_result.is_failure
            assert "Add error" in add_result.error

            modify_result = ldap_api.modify_entry(
                "uid=test,ou=people,dc=example,dc=com",
                {"cn": [("MODIFY_REPLACE", ["New"])]},
            )
            assert modify_result.is_failure
            assert "Modify error" in modify_result.error

            delete_result = ldap_api.delete_entry(
                "uid=test,ou=people,dc=example,dc=com"
            )
            assert delete_result.is_failure
            assert "Delete error" in delete_result.error
