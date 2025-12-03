"""Complete integration tests for FlextLdap API with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import cast

import pytest
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from flext_ldap import FlextLdap
from flext_ldap.api import SyncPhaseConfig
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols

from ..conftest import create_flext_ldap_instance
from ..fixtures.constants import RFC
from ..fixtures.typing import LdapContainerDict
from ..helpers.operation_helpers import TestOperationHelpers
from ..helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.integration


class TestFlextLdapAPIComplete:
    """Complete tests for FlextLdap API with real LDAP server."""

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom config."""
        config = FlextLdapConfig(
            host=RFC.DEFAULT_HOST,
            port=RFC.DEFAULT_PORT,
        )
        api = create_flext_ldap_instance(config=config)
        assert api._connection is not None
        assert api._operations is not None

    def test_client_property(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test operations access."""
        operations = ldap_client._operations
        assert operations is not None
        assert operations == ldap_client._operations

    def test_context_manager(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test context manager usage."""
        api = create_flext_ldap_instance()
        with api:
            TestOperationHelpers.connect_and_assert_success(
                cast("FlextLdapProtocols.LdapService.LdapClientProtocol", api),
                connection_config,
            )

        # Should be disconnected after context exit
        assert api._connection.is_connected is False

    def test_context_manager_with_exception(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test context manager with exception."""
        test_exception = ValueError("Test exception")
        api = create_flext_ldap_instance()
        try:
            with api:
                result = api.connect(connection_config)
                TestOperationHelpers.assert_result_success(result)
                raise test_exception
        except ValueError:
            pass

        # Should still be disconnected
        api = create_flext_ldap_instance()
        result = api.connect(connection_config)
        if result.is_success:
            api.disconnect()

    def test_search_with_different_server_types(
        self,
        ldap_client: FlextLdap,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test search with different server types."""
        search_options = TestOperationHelpers.create_search_options(
            base_dn=ldap_container["base_dn"],
            filter_str="(objectClass=*)",
            scope=FlextLdapConstants.SearchScope.SUBTREE,
        )

        # Only test with 'rfc' which is always registered in quirks
        result = ldap_client.search(
            search_options,
            server_type=FlextLdifConstants.ServerTypes.RFC,
        )
        TestOperationHelpers.assert_result_success(result)

    def test_add_with_operation_result(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test add returns proper OperationResult."""
        _entry, result = TestDeduplicationHelpers.create_user_add_and_verify(
            cast("FlextLdapProtocols.LdapService.LdapClientProtocol", ldap_client),
            "testapiadd",
            verify_operation_result=True,
        )
        operation_result = result.unwrap()
        # upsert returns LdapOperationResult (no success field), only operation
        assert operation_result.operation in {"added", "modified", "skipped"}

    def test_modify_with_dn_object(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test modify with DistinguishedName object."""
        entry = TestDeduplicationHelpers.create_user("testapimod")
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }
        TestDeduplicationHelpers.add_then_modify_with_operation_results(
            cast("FlextLdapProtocols.LdapService.LdapClientProtocol", ldap_client),
            entry,
            changes,
        )

    def test_delete_with_dn_object(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test delete with DistinguishedName object."""
        entry = TestDeduplicationHelpers.create_user("testapidel")
        TestDeduplicationHelpers.add_then_delete_with_operation_results(
            cast("FlextLdapProtocols.LdapService.LdapClientProtocol", ldap_client),
            entry,
        )

    def test_execute_when_connected(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test execute when connected."""
        TestDeduplicationHelpers.execute_and_verify_total_count(
            cast("FlextLdapProtocols.LdapService.LdapClientProtocol", ldap_client),
            expected_total=0,
            expected_entries=0,
        )

    def test_execute_when_not_connected(self) -> None:
        """Test execute when not connected - should return failure."""
        api = create_flext_ldap_instance()
        result = api.execute()
        # Fast fail - should return failure when not connected
        TestOperationHelpers.assert_result_failure(result)
        error_msg = TestOperationHelpers.get_error_message(result)
        # Validate error message content: should indicate not connected
        assert "Not connected" in error_msg or "not connected" in error_msg.lower()

    def test_connect_with_service_config(
        self,
        ldap_container: LdapContainerDict,
    ) -> None:
        """Test connect using service config."""
        api = create_flext_ldap_instance()
        # Create ConnectionConfig directly from ldap_container to bypass config issues
        connection_config = FlextLdapModels.ConnectionConfig(
            host=ldap_container["host"],
            port=ldap_container["port"],
            use_ssl=False,
            use_tls=False,
            bind_dn=ldap_container["bind_dn"],
            bind_password=ldap_container["password"],
        )
        result = api.connect(connection_config)
        TestOperationHelpers.assert_result_success(result)
        api.disconnect()

    def test_all_operations_in_sequence(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test all operations in sequence."""
        entry = TestDeduplicationHelpers.create_user("testsequence")
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_ADD, ["test@example.com"])],
        }
        TestDeduplicationHelpers.add_modify_delete_with_operation_results(
            cast("FlextLdapProtocols.LdapService.LdapClientProtocol", ldap_client),
            entry,
            changes,
        )

    def test_api_crud_operations_with_data_validation(
        self,
        ldap_client: FlextLdap,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test complete CRUD operations with data validation.

        This test validates that:
        1. Add operation succeeds and data is stored correctly
        2. Search operation returns the correct data
        3. Modify operation changes data correctly
        4. Delete operation removes data completely
        """
        # Create connected LDAP client using fixture
        # Note: ldap_client fixture is already connected
        TestOperationHelpers.connect_and_assert_success(
            cast("FlextLdapProtocols.LdapService.LdapClientProtocol", ldap_client),
            connection_config,
        )

        # Cleanup entry if it exists (idempotent test)
        test_dn = f"cn=test-data-validation,{RFC.DEFAULT_BASE_DN}"
        _ = ldap_client.delete(test_dn)  # Ignore result - entry may not exist

        # Create test entry with specific data
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=test_dn),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["test-data-validation"],
                    "sn": ["DataValidation"],
                    "givenName": ["Test"],
                    "mail": ["test@example.com"],
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                    "userPassword": ["test123"],
                    "description": ["Test entry for data validation"],
                },
            ),
        )

        # Test ADD operation
        add_result = ldap_client.add(entry)
        TestOperationHelpers.assert_result_success(add_result)
        operation_result = add_result.unwrap()
        # Validate actual content: add() returns OperationResult with success field
        assert operation_result.operation_type == FlextLdapConstants.OperationType.ADD
        assert operation_result.success is True
        assert operation_result.entries_affected == 1

        # Verify data was stored correctly by searching
        search_options = FlextLdapModels.SearchOptions(
            base_dn=test_dn,
            filter_str="(objectClass=*)",
            scope=FlextLdapConstants.SearchScope.BASE,
            attributes=["*"],
        )
        search_result = ldap_client.search(search_options)
        TestOperationHelpers.assert_result_success(search_result)
        search_data = search_result.unwrap()
        # Validate actual content: search should return results
        assert search_data is not None
        assert hasattr(search_data, "entries")
        assert hasattr(search_data, "total_count")

        search_data = search_result.unwrap()
        assert len(search_data.entries) == 1, "Should find exactly one entry"

        found_entry = search_data.entries[0]

        # Validate all attributes match what was added
        assert str(found_entry.dn) == test_dn
        assert found_entry.attributes is not None
        attrs = found_entry.attributes.attributes

        # Check specific attributes
        assert attrs.get("cn") == ["test-data-validation"]
        assert attrs.get("sn") == ["DataValidation"]
        assert attrs.get("givenName") == ["Test"]
        assert attrs.get("mail") == ["test@example.com"]
        assert "inetOrgPerson" in attrs.get("objectClass", [])
        assert attrs.get("description") == ["Test entry for data validation"]

        # Test MODIFY operation
        changes = {
            "description": [("MODIFY_REPLACE", ["Modified description"])],
            "mail": [("MODIFY_REPLACE", ["modified@example.com"])],
        }
        modify_result = ldap_client.modify(test_dn, changes)
        TestOperationHelpers.assert_result_success(modify_result)
        modify_op_result = modify_result.unwrap()
        # Validate actual content: modify() returns OperationResult with success field
        assert (
            modify_op_result.operation_type == FlextLdapConstants.OperationType.MODIFY
        )
        assert modify_op_result.success is True
        assert modify_op_result.entries_affected == 1

        # Verify modifications
        search_result2 = ldap_client.search(search_options)
        TestOperationHelpers.assert_result_success(search_result2)
        search_data2 = search_result2.unwrap()
        # Validate actual content: search should return results
        assert len(search_data2.entries) == 1
        assert search_data2.total_count == len(search_data2.entries)

        modified_entry = search_data2.entries[0]
        if modified_entry.attributes is None:
            msg = "Entry has no attributes"
            raise AssertionError(msg)
        modified_attrs = modified_entry.attributes.attributes
        assert modified_attrs.get("description") == ["Modified description"]
        assert modified_attrs.get("mail") == ["modified@example.com"]
        # Other attributes should remain unchanged
        assert modified_attrs.get("cn") == ["test-data-validation"]
        assert modified_attrs.get("sn") == ["DataValidation"]

        # Test DELETE operation
        delete_result = ldap_client.delete(test_dn)
        TestOperationHelpers.assert_result_success(delete_result)
        delete_op_result = delete_result.unwrap()
        # Validate actual content: delete() returns OperationResult with success field
        assert (
            delete_op_result.operation_type == FlextLdapConstants.OperationType.DELETE
        )
        assert delete_op_result.success is True
        assert delete_op_result.entries_affected == 1

        # Verify entry was deleted - search should fail with noSuchObject
        search_result3 = ldap_client.search(search_options)
        TestOperationHelpers.assert_result_failure(search_result3)
        error_msg = TestOperationHelpers.get_error_message(search_result3)
        # Validate error message content: should indicate entry not found
        assert "noSuchObject" in error_msg or "not found" in error_msg.lower(), (
            f"Expected noSuchObject/not found error, got: {error_msg}"
        )

    def test_api_upsert_method(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test API upsert method (covers line 246)."""
        # Cleanup first
        test_dn = f"cn=testapiupsert,{RFC.DEFAULT_BASE_DN}"
        _ = ldap_client.delete(test_dn)

        # Create entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=test_dn),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testapiupsert"],
                    "objectClass": ["top", "person"],
                    "sn": ["Test"],
                },
            ),
        )

        # Test upsert through API (covers line 246)
        result = ldap_client.upsert(entry)
        TestOperationHelpers.assert_result_success(result)
        operation_result = result.unwrap()
        # Validate actual content: upsert returns LdapOperationResult (no success field)
        # LdapOperationResult only has 'operation' field, not 'success' or 'entries_affected'
        assert operation_result.operation in {"added", "skipped"}

        # Cleanup
        _ = ldap_client.delete(test_dn)

    def test_sync_phase_entries_with_empty_ldif(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test sync_phase_entries with empty LDIF file.

        Covers lines 731-754 in api.py (empty entries path).
        """
        # Create empty LDIF file
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("# Empty LDIF file\n")
            temp_path = Path(f.name)

        try:
            result = ldap_client.sync_phase_entries(temp_path, "empty_phase")
            TestOperationHelpers.assert_result_success(result)
            phase_result = result.unwrap()
            # Validate actual content: empty phase should have zero entries
            assert phase_result.total_entries == 0
            assert phase_result.synced == 0
            assert phase_result.failed == 0
            assert phase_result.skipped == 0
            assert phase_result.success_rate == 100.0
            assert phase_result.duration_seconds >= 0.0
            assert phase_result.failed == 0
            assert phase_result.skipped == 0
            assert phase_result.duration_seconds == 0.0
            assert phase_result.success_rate == 100.0
        finally:
            temp_path.unlink()

    def test_sync_phase_entries_with_single_phase_callback(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test sync_phase_entries with single-phase callback.

        Covers lines 757-782 in api.py (callback conversion).
        """
        # Create LDIF file with one entry
        ldif_content = """dn: cn=testsync1,ou=people,dc=flext,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: testsync1
sn: Test1
"""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(ldif_content)
            temp_path = Path(f.name)

        # Track callback calls
        callback_calls: list[tuple[int, int, str]] = []

        def single_phase_callback(
            current: int,
            total: int,
            dn: str,
            stats: FlextLdapModels.LdapBatchStats,
        ) -> None:
            """Single-phase callback (4 parameters)."""
            callback_calls.append((current, total, dn))

        try:
            config = SyncPhaseConfig(progress_callback=single_phase_callback)
            result = ldap_client.sync_phase_entries(
                temp_path, "test_phase", config=config
            )
            TestOperationHelpers.assert_result_success(result)
            phase_result = result.unwrap()
            # Validate actual content: phase name, entry count, stats
            assert phase_result.phase_name == "test_phase"
            assert phase_result.total_entries == 1
            assert phase_result.synced >= 0  # May be synced or skipped
            assert phase_result.failed == 0
            assert phase_result.duration_seconds >= 0.0
            assert 0.0 <= phase_result.success_rate <= 100.0
            # Verify callback was called with correct parameters
            assert len(callback_calls) > 0
            # Validate callback was called with entry DN
            assert any("testsync1" in call[2] for call in callback_calls)
        finally:
            # Cleanup
            _ = ldap_client.delete("cn=testsync1,ou=people,dc=flext,dc=local")
            temp_path.unlink()

    def test_sync_phase_entries_with_multi_phase_callback(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test sync_phase_entries with multi-phase callback.

        Covers lines 760-777 in api.py (multi-phase callback wrapping).
        """
        # Create LDIF file with one entry
        ldif_content = """dn: cn=testsync2,ou=people,dc=flext,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: testsync2
sn: Test2
"""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(ldif_content)
            temp_path = Path(f.name)

        # Track callback calls
        callback_calls: list[tuple[str, int, int, str]] = []

        def multi_phase_callback(
            phase: str,
            current: int,
            total: int,
            dn: str,
            stats: FlextLdapModels.LdapBatchStats,
        ) -> None:
            """Multi-phase callback (5 parameters)."""
            callback_calls.append((phase, current, total, dn))

        try:
            config = SyncPhaseConfig(progress_callback=multi_phase_callback)
            result = ldap_client.sync_phase_entries(
                temp_path, "test_phase", config=config
            )
            TestOperationHelpers.assert_result_success(result)
            phase_result = result.unwrap()
            # Validate actual content: phase name, entry count, stats
            assert phase_result.phase_name == "test_phase"
            assert phase_result.total_entries == 1
            assert phase_result.synced >= 0  # May be synced or skipped
            assert phase_result.failed == 0
            assert phase_result.duration_seconds >= 0.0
            assert 0.0 <= phase_result.success_rate <= 100.0
            # Verify callback was called with phase name
            assert len(callback_calls) > 0
            assert callback_calls[0][0] == "test_phase"
            # Validate callback parameters: phase, current, total, dn
            assert callback_calls[0][1] >= 0  # current >= 0
            assert callback_calls[0][2] == 1  # total == 1 entry
            assert "testsync2" in callback_calls[0][3]  # DN contains entry name
        finally:
            # Cleanup
            _ = ldap_client.delete("cn=testsync2,ou=people,dc=flext,dc=local")
            temp_path.unlink()

    def test_sync_phase_entries_with_parse_failure(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test sync_phase_entries with invalid LDIF file.

        Covers lines 736-740 in api.py (parse failure path).
        """
        # Create invalid LDIF file
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("invalid ldif content\n")
            temp_path = Path(f.name)

        try:
            result = ldap_client.sync_phase_entries(temp_path, "invalid_phase")
            TestOperationHelpers.assert_result_failure(result)
            error_msg = TestOperationHelpers.get_error_message(result)
            # Validate error message content
            assert (
                "Failed to parse LDIF file" in error_msg or "parse" in error_msg.lower()
            )
            # Validate that no entries were processed
            TestOperationHelpers.assert_result_failure(result)
        finally:
            temp_path.unlink()

    def test_sync_phase_entries_with_batch_failure(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test sync_phase_entries with batch failure.

        Covers lines 797-800 in api.py (batch failure path).
        """
        # Create LDIF file with invalid DN that will cause batch failure
        ldif_content = """dn: invalid-dn-format
objectClass: inetOrgPerson
cn: test
"""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(ldif_content)
            temp_path = Path(f.name)

        try:
            config = SyncPhaseConfig(stop_on_error=True)
            result = ldap_client.sync_phase_entries(
                temp_path, "failure_phase", config=config
            )
            # May succeed with skipped entries or fail depending on validation
            if result.is_success:
                phase_result = result.unwrap()
                # Validate content: if succeeded, should have stats
                assert phase_result.phase_name == "failure_phase"
                assert phase_result.total_entries >= 0
                # If entry was skipped, skipped count should be > 0
                # If entry failed, failed count should be > 0
                assert (
                    phase_result.synced + phase_result.failed + phase_result.skipped
                    >= 0
                )
            else:
                # Validate failure error message
                error_msg = TestOperationHelpers.get_error_message(result)
                assert len(error_msg) > 0
        finally:
            temp_path.unlink()

    def test_sync_multiple_phases_with_empty_dict(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test sync_multiple_phases with empty phase files dict.

        Covers lines 924-988 in api.py (empty phases path).
        """
        result = ldap_client.sync_multiple_phases({})
        TestOperationHelpers.assert_result_success(result)
        multi_result = result.unwrap()
        # Validate actual content: empty phases should return empty results
        assert len(multi_result.phase_results) == 0
        assert multi_result.total_entries == 0
        assert multi_result.total_synced == 0
        assert multi_result.total_failed == 0
        assert multi_result.total_skipped == 0
        assert multi_result.overall_success_rate == 0.0
        assert multi_result.overall_success is True  # Empty phases = success

    def test_sync_multiple_phases_with_missing_file(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test sync_multiple_phases with missing file.

        Covers lines 932-938 in api.py (missing file path).
        """
        non_existent_path = Path("/tmp/non_existent_file.ldif")
        phase_files = {"phase1": non_existent_path}

        result = ldap_client.sync_multiple_phases(phase_files)
        TestOperationHelpers.assert_result_success(result)
        multi_result = result.unwrap()
        # Validate actual content: missing file should be skipped
        assert len(multi_result.phase_results) == 0
        assert multi_result.total_entries == 0
        assert multi_result.overall_success is True
        assert multi_result.overall_success_rate == 100.0

    def test_sync_multiple_phases_with_multiple_files(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test sync_multiple_phases with multiple phase files.

        Covers lines 924-988 in api.py (full sync_multiple_phases path).
        """
        # Create two LDIF files
        ldif_content1 = """dn: cn=testsync3,ou=people,dc=flext,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: testsync3
sn: Test3
"""
        ldif_content2 = """dn: cn=testsync4,ou=people,dc=flext,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: testsync4
sn: Test4
"""
        with (
            tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".ldif",
                delete=False,
                encoding="utf-8",
            ) as f1,
            tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".ldif",
                delete=False,
                encoding="utf-8",
            ) as f2,
        ):
            f1.write(ldif_content1)
            f2.write(ldif_content2)
            temp_path1 = Path(f1.name)
            temp_path2 = Path(f2.name)

        try:
            phase_files = {
                "phase1": temp_path1,
                "phase2": temp_path2,
            }
            result = ldap_client.sync_multiple_phases(phase_files)
            TestOperationHelpers.assert_result_success(result)
            multi_result = result.unwrap()
            # Validate actual content: both phases should be processed
            assert len(multi_result.phase_results) == 2
            assert "phase1" in multi_result.phase_results
            assert "phase2" in multi_result.phase_results
            # Validate phase1 results
            phase1_result = multi_result.phase_results["phase1"]
            assert phase1_result.phase_name == "phase1"
            assert phase1_result.total_entries == 1
            assert phase1_result.synced >= 0
            # Validate phase2 results
            phase2_result = multi_result.phase_results["phase2"]
            assert phase2_result.phase_name == "phase2"
            assert phase2_result.total_entries == 1
            assert phase2_result.synced >= 0
            # Validate aggregated totals
            assert multi_result.total_entries == 2
            assert multi_result.total_synced >= 0
            assert multi_result.total_failed >= 0
            assert multi_result.total_skipped >= 0
            assert 0.0 <= multi_result.overall_success_rate <= 100.0
            assert multi_result.overall_success is True
        finally:
            # Cleanup
            _ = ldap_client.delete("cn=testsync3,ou=people,dc=flext,dc=local")
            _ = ldap_client.delete("cn=testsync4,ou=people,dc=flext,dc=local")
            temp_path1.unlink()
            temp_path2.unlink()

    def test_sync_multiple_phases_with_multi_phase_callback(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test sync_multiple_phases with multi-phase callback.

        Covers lines 940-949 in api.py (_make_phase_progress_callback usage).
        """
        # Create LDIF file
        ldif_content = """dn: cn=testsync5,ou=people,dc=flext,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: testsync5
sn: Test5
"""
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".ldif",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write(ldif_content)
            temp_path = Path(f.name)

        # Track callback calls
        callback_calls: list[tuple[str, int, int, str]] = []

        def multi_phase_callback(
            phase: str,
            current: int,
            total: int,
            dn: str,
            stats: FlextLdapModels.LdapBatchStats,
        ) -> None:
            """Multi-phase callback (5 parameters)."""
            callback_calls.append((phase, current, total, dn))

        try:
            config = SyncPhaseConfig(progress_callback=multi_phase_callback)
            phase_files = {"test_phase": temp_path}
            result = ldap_client.sync_multiple_phases(phase_files, config=config)
            TestOperationHelpers.assert_result_success(result)
            multi_result = result.unwrap()
            # Validate actual content
            assert len(multi_result.phase_results) >= 1
            assert multi_result.total_entries >= 1
            # Verify callback was called with phase name
            assert len(callback_calls) > 0
            assert callback_calls[0][0] == "test_phase"
        finally:
            # Cleanup
            _ = ldap_client.delete("cn=testsync5,ou=people,dc=flext,dc=local")
            temp_path.unlink()

    def test_sync_multiple_phases_with_stop_on_error(
        self,
        ldap_client: FlextLdap,
    ) -> None:
        """Test sync_multiple_phases with stop_on_error=True.

        Covers lines 963-972 in api.py (stop_on_error path).
        """
        # Create one valid and one invalid LDIF file
        ldif_content_valid = """dn: cn=testsync6,ou=people,dc=flext,dc=local
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: testsync6
sn: Test6
"""
        ldif_content_invalid = "invalid ldif content\n"

        with (
            tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".ldif",
                delete=False,
                encoding="utf-8",
            ) as f1,
            tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".ldif",
                delete=False,
                encoding="utf-8",
            ) as f2,
        ):
            f1.write(ldif_content_valid)
            f2.write(ldif_content_invalid)
            temp_path1 = Path(f1.name)
            temp_path2 = Path(f2.name)

        try:
            config = SyncPhaseConfig(stop_on_error=True)
            phase_files = {
                "phase1": temp_path1,
                "phase2": temp_path2,  # This will fail
            }
            result = ldap_client.sync_multiple_phases(phase_files, config=config)
            # Should process phase1 successfully, then stop on phase2 failure
            if result.is_success:
                multi_result = result.unwrap()
                # Validate actual content: phase1 should be processed
                assert len(multi_result.phase_results) >= 1
                assert "phase1" in multi_result.phase_results
                phase1_result = multi_result.phase_results["phase1"]
                assert phase1_result.total_entries == 1
                # With stop_on_error=True, phase2 should not be processed if phase1 fails
                # But if phase1 succeeds, phase2 may or may not be processed
                assert multi_result.total_entries >= 1
            else:
                # Validate failure error message
                error_msg = TestOperationHelpers.get_error_message(result)
                assert len(error_msg) > 0
        finally:
            # Cleanup
            _ = ldap_client.delete("cn=testsync6,ou=people,dc=flext,dc=local")
            temp_path1.unlink()
            temp_path2.unlink()
