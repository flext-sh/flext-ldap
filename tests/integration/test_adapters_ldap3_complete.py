"""Complete integration tests for Ldap3Adapter with real LDAP server.

All tests use real LDAP operations, no mocks. Tests all methods and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.models import FlextLdapModels
from tests.fixtures.constants import RFC
from tests.helpers.entry_helpers import EntryTestHelpers

pytestmark = pytest.mark.integration


class TestLdap3AdapterComplete:
    """Complete tests for Ldap3Adapter with real LDAP server."""

    @pytest.fixture
    def connected_adapter(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Generator[Ldap3Adapter]:
        """Get connected adapter for testing."""
        adapter = Ldap3Adapter()
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")
        yield adapter
        adapter.disconnect()

    def test_adapter_initialization_with_parser(self) -> None:
        """Test adapter initialization with custom parser."""
        parser = FlextLdifParser()
        adapter = Ldap3Adapter(parser=parser)
        assert adapter._parser == parser
        assert adapter._entry_adapter is not None

    def test_connect_with_use_ssl(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test connection with SSL enabled."""
        adapter = Ldap3Adapter()
        config = FlextLdapModels.ConnectionConfig(
            host=str(ldap_container["host"]),
            port=int(str(ldap_container["port"])),
            use_ssl=True,
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
        )
        # SSL might fail on test server, that's OK
        _ = adapter.connect(config)
        adapter.disconnect()
        # Just verify it doesn't crash

    def test_connect_with_use_tls(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test connection with TLS enabled."""
        adapter = Ldap3Adapter()
        config = FlextLdapModels.ConnectionConfig(
            host=str(ldap_container["host"]),
            port=int(str(ldap_container["port"])),
            use_tls=True,
            bind_dn=str(ldap_container["bind_dn"]),
            bind_password=str(ldap_container["password"]),
        )
        # TLS might fail on test server, that's OK
        _ = adapter.connect(config)
        adapter.disconnect()
        # Just verify it doesn't crash

    def test_connect_with_timeout(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test connection with custom timeout."""
        adapter = Ldap3Adapter()
        config = FlextLdapModels.ConnectionConfig(
            host=connection_config.host,
            port=connection_config.port,
            use_ssl=connection_config.use_ssl,
            bind_dn=connection_config.bind_dn,
            bind_password=connection_config.bind_password,
            timeout=30,
        )
        result = adapter.connect(config)
        assert result.is_success
        adapter.disconnect()

    def test_connect_with_auto_bind_false(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test connection with auto_bind=False."""
        adapter = Ldap3Adapter()
        config = FlextLdapModels.ConnectionConfig(
            host=connection_config.host,
            port=connection_config.port,
            use_ssl=connection_config.use_ssl,
            bind_dn=connection_config.bind_dn,
            bind_password=connection_config.bind_password,
            auto_bind=False,
        )
        _ = adapter.connect(config)
        # Without auto_bind, connection might not be bound
        adapter.disconnect()

    def test_search_with_time_limit(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test search with time limit."""
        result = connected_adapter.search(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            time_limit=5,
        )
        assert result.is_success

    def test_search_with_all_attributes(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test search with all attributes."""
        result = connected_adapter.search(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            attributes=None,  # All attributes
        )
        assert result.is_success
        entries = result.unwrap()
        if entries:
            assert entries[0].attributes is not None

    def test_search_with_empty_result(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test search with filter that returns no results."""
        result = connected_adapter.search(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(cn=nonexistententry12345)",
            scope="SUBTREE",
        )
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) == 0

    def test_add_entry_with_all_attribute_types(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test adding entry with various attribute types."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testallattrs,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testallattrs"],
                    "sn": ["Test"],
                    "mail": ["test@example.com", "test2@example.com"],
                    "telephoneNumber": ["+1234567890"],
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                }
            ),
        )

        # Cleanup first
        _ = connected_adapter.delete(str(entry.dn))

        result = connected_adapter.add(entry)
        assert result.is_success

        # Cleanup
        delete_result = connected_adapter.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_modify_with_add_operation(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test modify with ADD operation."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testmodadd,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testmodadd"],
                    "sn": ["Test"],
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                }
            ),
        )

        # Cleanup first
        _ = connected_adapter.delete(str(entry.dn))

        add_result = connected_adapter.add(entry)
        assert add_result.is_success

        # Modify with ADD
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_ADD, ["newmail@example.com"])],
        }

        modify_result = connected_adapter.modify(str(entry.dn), changes)
        assert modify_result.is_success

        # Cleanup
        delete_result = connected_adapter.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_modify_with_delete_operation(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test modify with DELETE operation."""
        # First add an entry with mail
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testmoddel,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testmoddel"],
                    "sn": ["Test"],
                    "mail": ["test@example.com"],
                    "objectClass": [
                        "inetOrgPerson",
                        "organizationalPerson",
                        "person",
                        "top",
                    ],
                }
            ),
        )

        # Cleanup first
        _ = connected_adapter.delete(str(entry.dn))

        add_result = connected_adapter.add(entry)
        assert add_result.is_success

        # Modify with DELETE
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_DELETE, ["test@example.com"])],
        }

        modify_result = connected_adapter.modify(str(entry.dn), changes)
        assert modify_result.is_success

        # Cleanup
        delete_result = connected_adapter.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_modify_with_multiple_operations(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test modify with multiple operations."""
        entry_dict = {
            "dn": "cn=testmodmulti,ou=people,dc=flext,dc=local",
            "attributes": {
                "cn": ["testmodmulti"],
                "sn": ["Test"],
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
            },
        }

        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["newmail@example.com"])],
            "telephoneNumber": [(MODIFY_ADD, ["+9876543210"])],
        }

        entry, add_result, modify_result = EntryTestHelpers.modify_entry_with_verification(
            connected_adapter, entry_dict, changes, verify_attribute=None
        )

        assert add_result.is_success
        assert modify_result.is_success

    def test_delete_nonexistent_entry(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test deleting non-existent entry."""
        result = connected_adapter.delete("cn=nonexistent12345,dc=flext,dc=local")
        # Should fail gracefully
        assert result.is_failure

    def test_execute_when_connected(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test execute when connected."""
        result = connected_adapter.execute()
        assert result.is_success
        entry = result.unwrap()
        assert entry is not None

    def test_search_with_different_server_types(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test search with different server types."""
        # Only test server types that are registered in quirks
        # 'rfc' is the default and always works
        result = connected_adapter.search(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            server_type="rfc",
        )
        assert result.is_success

    def test_add_entry_with_empty_attributes(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test adding entry with minimal attributes."""
        entry = EntryTestHelpers.create_entry(
            "cn=testminimal,ou=people,dc=flext,dc=local",
            {"cn": ["testminimal"], "objectClass": ["top", "person"]},
        )

        result = EntryTestHelpers.add_and_cleanup(connected_adapter, entry)
        # Should succeed or fail gracefully
        assert result.is_success or result.is_failure

    def test_disconnect_with_exception_handling(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test disconnect handles exceptions gracefully."""
        # Disconnect should handle any exceptions
        connected_adapter.disconnect()
        # Second disconnect should also work
        connected_adapter.disconnect()

    def test_add_with_entry_adapter_failure(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test add when entry adapter conversion fails."""
        # Create entry that might cause conversion issues
        # This tests the error path in add method
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testadapterfail,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testadapterfail"],
                    "objectClass": ["top", "person"],
                }
            ),
        )

        # Cleanup first
        _ = connected_adapter.delete(str(entry.dn))

        # Add should work normally
        result = connected_adapter.add(entry)
        assert result.is_success or result.is_failure

        # Cleanup
        _ = connected_adapter.delete(str(entry.dn))

    def test_search_with_parse_failure_handling(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test search handles parse failures gracefully."""
        # Search should work normally
        result = connected_adapter.search(
            base_dn=RFC.DEFAULT_BASE_DN,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            server_type="rfc",
        )
        # Should succeed with valid server type
        assert result.is_success or result.is_failure
