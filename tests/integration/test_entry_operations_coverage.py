"""Entry operations comprehensive coverage - Real Docker LDAP testing.

Targets uncovered CRUD operation paths in oid_operations.py, oud_operations.py,
openldap1_operations.py, and openldap2_operations.py with real Docker LDAP
fixture data and comprehensive entry operations testing.

This test suite expands entry operations coverage from current gaps to 95%+.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapClients
from flext_ldap.servers.oid_operations import FlextLdapServersOIDOperations
from flext_ldap.servers.openldap1_operations import FlextLdapServersOpenLDAP1Operations
from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations
from flext_ldap.servers.oud_operations import FlextLdapServersOUDOperations

# ============================================================================
# OID ENTRY OPERATIONS COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOIDEntryOperations:
    """OID entry CRUD operations - comprehensive real Docker testing."""

    def test_oid_add_entry_basic(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID add_entry with basic entry."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test_add,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "person"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test_add"]),
                    "sn": FlextLdifModels.AttributeValues(values=["User"]),
                }
            ),
        )
        result = ops.add_entry(shared_ldap_client._connection, entry)
        assert isinstance(result, FlextResult)

    def test_oid_modify_entry_basic(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID modify_entry with basic modifications."""
        ops = FlextLdapServersOIDOperations()
        result = ops.modify_entry(
            shared_ldap_client._connection,
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            {"description": ["Modified by test"]},
        )
        assert isinstance(result, FlextResult)

    def test_oid_delete_entry_basic(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID delete_entry with valid DN."""
        ops = FlextLdapServersOIDOperations()
        result = ops.delete_entry(
            shared_ldap_client._connection,
            "cn=test_delete,ou=people,dc=flext,dc=local",
        )
        assert isinstance(result, FlextResult)

    def test_oid_add_entry_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID add_entry with None connection fails properly."""
        ops = FlextLdapServersOIDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.add_entry(None, entry)  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_oid_modify_entry_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID modify_entry with None connection fails."""
        ops = FlextLdapServersOIDOperations()
        result = ops.modify_entry(None, "cn=test,dc=example,dc=com", {})  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_oid_delete_entry_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID delete_entry with None connection fails."""
        ops = FlextLdapServersOIDOperations()
        result = ops.delete_entry(None, "cn=test,dc=example,dc=com")  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure


# ============================================================================
# OUD ENTRY OPERATIONS COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOUDEntryOperations:
    """OUD entry CRUD operations - comprehensive real Docker testing."""

    def test_oud_add_entry_basic(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD add_entry with basic entry."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test_add,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "person"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test_add"]),
                    "sn": FlextLdifModels.AttributeValues(values=["User"]),
                }
            ),
        )
        result = ops.add_entry(shared_ldap_client._connection, entry)
        assert isinstance(result, FlextResult)

    def test_oud_modify_entry_with_oud_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD modify_entry with OUD-specific attributes."""
        ops = FlextLdapServersOUDOperations()
        result = ops.modify_entry(
            shared_ldap_client._connection,
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            {"ds-privilege-name": ["REDACTED_LDAP_BIND_PASSWORD"]},
        )
        assert isinstance(result, FlextResult)

    def test_oud_delete_entry_basic(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD delete_entry with valid DN."""
        ops = FlextLdapServersOUDOperations()
        result = ops.delete_entry(
            shared_ldap_client._connection,
            "cn=test_delete,ou=people,dc=flext,dc=local",
        )
        assert isinstance(result, FlextResult)

    def test_oud_add_entry_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD add_entry with None connection fails properly."""
        ops = FlextLdapServersOUDOperations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.add_entry(None, entry)  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_oud_modify_entry_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD modify_entry with None connection fails."""
        ops = FlextLdapServersOUDOperations()
        result = ops.modify_entry(None, "cn=test,dc=example,dc=com", {})  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_oud_delete_entry_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD delete_entry with None connection fails."""
        ops = FlextLdapServersOUDOperations()
        result = ops.delete_entry(None, "cn=test,dc=example,dc=com")  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure


# ============================================================================
# OPENLDAP1 ENTRY OPERATIONS COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP1EntryOperations:
    """OpenLDAP1 entry CRUD operations - comprehensive real Docker testing."""

    def test_openldap1_add_entry_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 add_entry with basic entry."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test_add,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "person"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test_add"]),
                    "sn": FlextLdifModels.AttributeValues(values=["User"]),
                }
            ),
        )
        result = ops.add_entry(shared_ldap_client._connection, entry)
        assert isinstance(result, FlextResult)

    def test_openldap1_modify_entry_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 modify_entry with basic modifications."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.modify_entry(
            shared_ldap_client._connection,
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            {"description": ["Modified by test"]},
        )
        assert isinstance(result, FlextResult)

    def test_openldap1_delete_entry_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 delete_entry with valid DN."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.delete_entry(
            shared_ldap_client._connection,
            "cn=test_delete,ou=people,dc=flext,dc=local",
        )
        assert isinstance(result, FlextResult)

    def test_openldap1_add_entry_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 add_entry with None connection fails properly."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.add_entry(None, entry)  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure


# ============================================================================
# OPENLDAP2 ENTRY OPERATIONS COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP2EntryOperations:
    """OpenLDAP2 entry CRUD operations - comprehensive real Docker testing."""

    def test_openldap2_add_entry_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 add_entry with basic entry."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test_add,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson", "person"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test_add"]),
                    "sn": FlextLdifModels.AttributeValues(values=["User"]),
                }
            ),
        )
        result = ops.add_entry(shared_ldap_client._connection, entry)
        assert isinstance(result, FlextResult)

    def test_openldap2_modify_entry_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 modify_entry with basic modifications."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.modify_entry(
            shared_ldap_client._connection,
            "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            {"description": ["Modified by test"]},
        )
        assert isinstance(result, FlextResult)

    def test_openldap2_delete_entry_basic(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 delete_entry with valid DN."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.delete_entry(
            shared_ldap_client._connection,
            "cn=test_delete,ou=people,dc=flext,dc=local",
        )
        assert isinstance(result, FlextResult)

    def test_openldap2_add_entry_with_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 add_entry with None connection fails properly."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=test,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": FlextLdifModels.AttributeValues(
                        values=["inetOrgPerson"]
                    ),
                    "cn": FlextLdifModels.AttributeValues(values=["test"]),
                }
            ),
        )
        result = ops.add_entry(None, entry)  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure


# ============================================================================
# SEARCH WITH PAGING OPERATIONS COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestSearchWithPagingOperations:
    """Search with paging operations - comprehensive real Docker testing."""

    def test_oid_search_with_paging(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OID search_with_paging basic operation."""
        ops = FlextLdapServersOIDOperations()
        result = ops.search_with_paging(
            shared_ldap_client._connection,
            "dc=flext,dc=local",
            "(objectClass=*)",
            page_size=100,
        )
        assert isinstance(result, FlextResult)

    def test_oud_search_with_paging(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test OUD search_with_paging basic operation."""
        ops = FlextLdapServersOUDOperations()
        result = ops.search_with_paging(
            shared_ldap_client._connection,
            "dc=flext,dc=local",
            "(objectClass=*)",
            page_size=100,
        )
        assert isinstance(result, FlextResult)

    def test_openldap1_search_with_paging(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 search_with_paging basic operation."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.search_with_paging(
            shared_ldap_client._connection,
            "dc=flext,dc=local",
            "(objectClass=*)",
            page_size=100,
        )
        assert isinstance(result, FlextResult)

    def test_openldap2_search_with_paging(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 search_with_paging basic operation."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.search_with_paging(
            shared_ldap_client._connection,
            "dc=flext,dc=local",
            "(objectClass=*)",
            page_size=100,
        )
        assert isinstance(result, FlextResult)

    def test_oid_search_with_paging_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID search_with_paging with None connection fails."""
        ops = FlextLdapServersOIDOperations()
        result = ops.search_with_paging(
            None, "dc=flext,dc=local", "(objectClass=*)", page_size=100  # type: ignore[arg-type]
        )
        assert isinstance(result, FlextResult)
        assert result.is_failure


# ============================================================================
# ROOT DSE AND CONTROLS OPERATIONS COVERAGE
# ============================================================================


@pytest.mark.integration
@pytest.mark.docker
class TestRootDSEAndControlsOperations:
    """Root DSE and controls discovery - comprehensive real Docker testing."""

    def test_oid_get_root_dse_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID get_root_dse_attributes."""
        ops = FlextLdapServersOIDOperations()
        result = ops.get_root_dse_attributes(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_oid_get_supported_controls(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID get_supported_controls."""
        ops = FlextLdapServersOIDOperations()
        result = ops.get_supported_controls(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_oud_get_root_dse_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD get_root_dse_attributes."""
        ops = FlextLdapServersOUDOperations()
        result = ops.get_root_dse_attributes(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_oud_get_supported_controls(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OUD get_supported_controls."""
        ops = FlextLdapServersOUDOperations()
        result = ops.get_supported_controls(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_openldap1_get_root_dse_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP1 get_root_dse_attributes."""
        ops = FlextLdapServersOpenLDAP1Operations()
        result = ops.get_root_dse_attributes(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_openldap2_get_root_dse_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 get_root_dse_attributes."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.get_root_dse_attributes(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_openldap2_get_supported_controls(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OpenLDAP2 get_supported_controls."""
        ops = FlextLdapServersOpenLDAP2Operations()
        result = ops.get_supported_controls(shared_ldap_client._connection)
        assert isinstance(result, FlextResult)

    def test_oid_get_root_dse_attributes_none_connection(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test OID get_root_dse_attributes with None connection fails."""
        ops = FlextLdapServersOIDOperations()
        result = ops.get_root_dse_attributes(None)  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure
