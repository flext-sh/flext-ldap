"""Integration tests for Ldap3Adapter with real LDAP server.

Tests all LDAP operations with real server, flext-ldif integration,
and quirks support for different server types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser
from ldap3 import MODIFY_REPLACE

from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.models import FlextLdapModels
from tests.fixtures.constants import RFC

pytestmark = pytest.mark.integration


class TestLdap3AdapterConnection:
    """Tests for Ldap3Adapter connection management."""

    def test_adapter_initialization(self) -> None:
        """Test adapter initialization."""
        adapter = Ldap3Adapter()
        assert adapter is not None
        assert adapter._parser is not None
        assert adapter._entry_adapter is not None
        assert adapter.is_connected is False

    def test_adapter_initialization_with_parser(self) -> None:
        """Test adapter initialization with custom parser."""
        parser = FlextLdifParser()
        adapter = Ldap3Adapter(parser=parser)
        assert adapter._parser == parser

    def test_connect_success(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test successful connection."""
        adapter = Ldap3Adapter()
        result = adapter.connect(connection_config)
        assert result.is_success, f"Connection failed: {result.error}"
        assert adapter.is_connected is True
        assert adapter.connection is not None

        # Cleanup
        adapter.disconnect()

    def test_connect_failure_invalid_host(self) -> None:
        """Test connection failure with invalid host."""
        adapter = Ldap3Adapter()
        config = FlextLdapModels.ConnectionConfig(
            host="invalid-host-that-does-not-exist",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
            bind_password="password",
        )
        result = adapter.connect(config)
        assert result.is_failure

    def test_disconnect(
        self, connection_config: FlextLdapModels.ConnectionConfig
    ) -> None:
        """Test disconnection."""
        adapter = Ldap3Adapter()
        connect_result = adapter.connect(connection_config)
        assert connect_result.is_success
        assert adapter.is_connected is True

        adapter.disconnect()
        assert adapter.is_connected is False
        assert adapter.connection is None

    def test_disconnect_when_not_connected(self) -> None:
        """Test disconnect when not connected."""
        adapter = Ldap3Adapter()
        # Should not raise exception
        adapter.disconnect()
        assert adapter.is_connected is False

    def test_connection_property(
        self, connection_config: FlextLdapModels.ConnectionConfig
    ) -> None:
        """Test connection property access."""
        adapter = Ldap3Adapter()
        assert adapter.connection is None

        connect_result = adapter.connect(connection_config)
        assert connect_result.is_success
        assert adapter.connection is not None

        adapter.disconnect()
        assert adapter.connection is None

    def test_execute_when_not_connected(self) -> None:
        """Test execute when not connected."""
        adapter = Ldap3Adapter()
        result = adapter.execute()
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_execute_when_connected(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test execute when connected."""
        adapter = Ldap3Adapter()
        connect_result = adapter.connect(connection_config)
        assert connect_result.is_success

        result = adapter.execute()
        assert result.is_success
        entry = result.unwrap()
        assert entry is not None

        adapter.disconnect()


class TestLdap3AdapterSearch:
    """Tests for Ldap3Adapter search operations."""

    @pytest.fixture
    def connected_adapter(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Ldap3Adapter:
        """Get connected adapter for testing."""
        adapter = Ldap3Adapter()
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")
        return adapter

    def test_search_all_entries(
        self,
        connected_adapter: Ldap3Adapter,
        ldap_container: dict[str, object],
    ) -> None:
        """Test searching all entries."""
        base_dn = str(ldap_container["base_dn"])
        result = connected_adapter.search(
            base_dn=base_dn,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )
        assert result.is_success, f"Search failed: {result.error}"
        entries = result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

    def test_search_with_base_scope(
        self,
        connected_adapter: Ldap3Adapter,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with BASE scope."""
        base_dn = str(ldap_container["base_dn"])
        result = connected_adapter.search(
            base_dn=base_dn,
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)
        # BASE scope should return at most 1 entry
        assert len(entries) <= 1

    def test_search_with_onelevel_scope(
        self,
        connected_adapter: Ldap3Adapter,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with ONELEVEL scope."""
        base_dn = str(ldap_container["base_dn"])
        result = connected_adapter.search(
            base_dn=base_dn,
            filter_str="(objectClass=*)",
            scope="ONELEVEL",
        )
        assert result.is_success
        entries = result.unwrap()
        assert isinstance(entries, list)

    def test_search_with_attributes(
        self,
        connected_adapter: Ldap3Adapter,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with specific attributes."""
        # Note: "dn" is not a searchable attribute, it's part of entry structure
        base_dn = str(ldap_container["base_dn"])
        result = connected_adapter.search(
            base_dn=base_dn,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            attributes=["objectClass", "cn"],  # Removed "dn", added "cn"
        )
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) > 0
        # Check that entries have requested attributes or DN
        for entry in entries:
            assert entry.attributes is not None
            # DN is always present in entry.dn, attributes may vary
            assert entry.dn is not None
            # At least one requested attribute should be present
            assert (
                "objectClass" in entry.attributes.attributes
                or "cn" in entry.attributes.attributes
            )

    def test_search_with_size_limit(
        self,
        connected_adapter: Ldap3Adapter,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with size limit."""
        base_dn = str(ldap_container["base_dn"])
        result = connected_adapter.search(
            base_dn=base_dn,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
            size_limit=2,
        )
        assert result.is_success
        entries = result.unwrap()
        assert len(entries) <= 2

    def test_search_when_not_connected(
        self,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search when not connected."""
        adapter = Ldap3Adapter()
        base_dn = str(ldap_container["base_dn"])
        result = adapter.search(
            base_dn=base_dn,
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_search_with_different_server_types(
        self,
        connected_adapter: Ldap3Adapter,
        ldap_container: dict[str, object],
    ) -> None:
        """Test search with different server type detection."""
        base_dn = str(ldap_container["base_dn"])
        # Test only with server types registered in quirks registry
        # Using constants from RFC
        result = connected_adapter.search(
            base_dn=base_dn,
            filter_str=RFC.DEFAULT_FILTER,
            scope=RFC.DEFAULT_SCOPE,
            server_type=RFC.SERVER_TYPE,
        )
        assert result.is_success, (
            f"Search failed for server_type={RFC.SERVER_TYPE}: {result.error}"
        )


class TestLdap3AdapterAdd:
    """Tests for Ldap3Adapter add operations."""

    @pytest.fixture
    def connected_adapter(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Ldap3Adapter:
        """Get connected adapter for testing."""
        adapter = Ldap3Adapter()
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")
        return adapter

    def test_add_entry(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test adding an entry."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testadd,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testadd"],
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

        result = connected_adapter.add(entry)
        assert result.is_success, f"Add failed: {result.error}"

        # Verify entry was added
        search_result = connected_adapter.search(
            base_dn=str(entry.dn),
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert search_result.is_success
        entries = search_result.unwrap()
        assert len(entries) == 1

        # Cleanup
        delete_result = connected_adapter.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_add_entry_when_not_connected(self) -> None:
        """Test add when not connected."""
        adapter = Ldap3Adapter()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["top", "person"]}
            ),
        )
        result = adapter.add(entry)
        assert result.is_failure
        assert "Not connected" in (result.error or "")

    def test_add_entry_with_complex_attributes(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test adding entry with complex attributes."""
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testcomplex,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testcomplex"],
                    "sn": ["Complex"],
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
        assert result.is_success, f"Add failed: {result.error}"

        # Cleanup
        delete_result = connected_adapter.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure


class TestLdap3AdapterModify:
    """Tests for Ldap3Adapter modify operations."""

    @pytest.fixture
    def connected_adapter(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Ldap3Adapter:
        """Get connected adapter for testing."""
        adapter = Ldap3Adapter()
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")
        return adapter

    def test_modify_entry(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test modifying an entry."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testmodify,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testmodify"],
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

        # Modify entry
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["modified@example.com"])],
        }

        modify_result = connected_adapter.modify(str(entry.dn), changes)
        assert modify_result.is_success, f"Modify failed: {modify_result.error}"

        # Verify modification
        search_result = connected_adapter.search(
            base_dn=str(entry.dn),
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert search_result.is_success
        entries = search_result.unwrap()
        if entries and entries[0].attributes:
            mail_attrs = entries[0].attributes.attributes.get("mail", [])
            if isinstance(mail_attrs, list):
                assert "modified@example.com" in mail_attrs

        # Cleanup
        delete_result = connected_adapter.delete(str(entry.dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_modify_with_dn_object(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test modify with DistinguishedName object."""
        dn = FlextLdifModels.DistinguishedName(
            value="cn=testmodify2,ou=people,dc=flext,dc=local"
        )

        # Cleanup first
        _ = connected_adapter.delete(str(dn))

        # Add entry first
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testmodify2"],
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
        add_result = connected_adapter.add(entry)
        assert add_result.is_success

        # Modify using DN object
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }
        modify_result = connected_adapter.modify(dn, changes)
        assert modify_result.is_success

        # Cleanup
        delete_result = connected_adapter.delete(str(dn))
        assert delete_result.is_success or delete_result.is_failure

    def test_modify_when_not_connected(self) -> None:
        """Test modify when not connected."""
        adapter = Ldap3Adapter()
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }
        result = adapter.modify("cn=test,dc=example,dc=com", changes)
        assert result.is_failure
        assert "Not connected" in (result.error or "")


class TestLdap3AdapterDelete:
    """Tests for Ldap3Adapter delete operations."""

    @pytest.fixture
    def connected_adapter(
        self,
        connection_config: FlextLdapModels.ConnectionConfig,
    ) -> Ldap3Adapter:
        """Get connected adapter for testing."""
        adapter = Ldap3Adapter()
        connect_result = adapter.connect(connection_config)
        if connect_result.is_failure:
            pytest.skip(f"Failed to connect: {connect_result.error}")
        return adapter

    def test_delete_entry(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test deleting an entry."""
        # First add an entry
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testdelete,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testdelete"],
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

        # Delete entry
        delete_result = connected_adapter.delete(str(entry.dn))
        assert delete_result.is_success, f"Delete failed: {delete_result.error}"

        # Verify deletion
        search_result = connected_adapter.search(
            base_dn=str(entry.dn),
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert search_result.is_success
        entries = search_result.unwrap()
        assert len(entries) == 0

    def test_delete_with_dn_object(
        self,
        connected_adapter: Ldap3Adapter,
    ) -> None:
        """Test delete with DistinguishedName object."""
        dn = FlextLdifModels.DistinguishedName(
            value="cn=testdelete2,ou=people,dc=flext,dc=local"
        )

        # Cleanup first
        _ = connected_adapter.delete(str(dn))

        # Add entry first
        entry = FlextLdifModels.Entry(
            dn=dn,
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "cn": ["testdelete2"],
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
        add_result = connected_adapter.add(entry)
        assert add_result.is_success

        # Delete using DN object
        delete_result = connected_adapter.delete(dn)
        assert delete_result.is_success

    def test_delete_when_not_connected(self) -> None:
        """Test delete when not connected."""
        adapter = Ldap3Adapter()
        result = adapter.delete("cn=test,dc=example,dc=com")
        assert result.is_failure
        assert "Not connected" in (result.error or "")
