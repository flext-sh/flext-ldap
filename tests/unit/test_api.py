"""Unit tests for FlextLdap API.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldap import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels


class TestFlextLdapAPI:
    """Tests for FlextLdap main API facade."""

    def test_api_initialization(self) -> None:
        """Test API initialization."""
        api = FlextLdap()
        assert api is not None
        assert api._connection is not None
        assert api._operations is not None
        assert api._config is not None
        assert api.is_connected is False

    def test_api_initialization_with_config(self) -> None:
        """Test API initialization with custom config."""
        config = FlextLdapConfig(
            ldap_host="test.example.com",
            ldap_port=389,
        )
        api = FlextLdap(config=config)
        assert api._config == config

    def test_is_connected_property(self) -> None:
        """Test is_connected property."""
        api = FlextLdap()
        assert api.is_connected is False

    def test_search_when_not_connected(self) -> None:
        """Test search when not connected."""
        api = FlextLdap()
        search_options = FlextLdapModels.SearchOptions(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )

        result = api.search(search_options)
        assert result.is_failure

    def test_add_when_not_connected(self) -> None:
        """Test add when not connected."""
        from flext_ldif.models import FlextLdifModels

        api = FlextLdap()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"cn": ["test"], "objectClass": ["top", "person"]}
            ),
        )

        result = api.add(entry)
        assert result.is_failure

    def test_modify_when_not_connected(self) -> None:
        """Test modify when not connected."""
        from ldap3 import MODIFY_REPLACE

        api = FlextLdap()
        changes: dict[str, list[tuple[str, list[str]]]] = {
            "mail": [(MODIFY_REPLACE, ["test@example.com"])],
        }

        result = api.modify("cn=test,dc=example,dc=com", changes)
        assert result.is_failure

    def test_delete_when_not_connected(self) -> None:
        """Test delete when not connected."""
        api = FlextLdap()
        result = api.delete("cn=test,dc=example,dc=com")
        assert result.is_failure

    def test_disconnect_when_not_connected(self) -> None:
        """Test disconnect when not connected."""
        api = FlextLdap()
        # Should not raise exception
        api.disconnect()
        assert api.is_connected is False

    def test_execute_when_not_connected(self) -> None:
        """Test execute when not connected."""
        api = FlextLdap()
        result = api.execute()
        # Execute returns empty result, not failure
        assert result.is_success
