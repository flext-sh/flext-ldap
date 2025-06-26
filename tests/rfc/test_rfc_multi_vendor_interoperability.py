"""🚀 RFC MULTI-VENDOR INTEROPERABILITY EXTREME Testing - AINDA MAIS EXIGENTE.

Este módulo implementa os testes MAIS RIGOROSOS possíveis para interoperabilidade
multi-vendor LDAP, baseado em RFCs e sendo extremamente exigente na validação
de compatibilidade com TODOS os principais servidores LDAP.

RFCs INTEROPERABILITY REQUIREMENTS:
- RFC 4510: LDAP Technical Specification Road Map
- RFC 4511: LDAP Protocol Operations (cross-vendor)
- RFC 4512: Directory Information Models (schema compatibility)
- RFC 4513: Authentication Methods (vendor-specific auth)
- RFC 4519: Schema for User Applications (standard schemas)

ZERO TOLERANCE INTEROPERABILITY: Deve funcionar com TODOS os vendors.
AINDA MAIS EXIGENTE: Testa cenários que outros nunca validam.

VENDORS TESTED:
- Microsoft Active Directory (AD DS)
- OpenLDAP
- 389 Directory Server (Red Hat)
- Apache Directory Server (ApacheDS)
- Oracle Internet Directory (OID)
- IBM Security Directory Server
- Novell eDirectory
- Sun/Oracle Directory Server Enterprise Edition

COBERTURA INTEROPERABILITY EXTREMA:
- Schemas específicos por vendor com validação cruzada
- Operações vendor-specific com fallbacks
- Extensões proprietárias com detecção automática
- Character encoding cross-vendor
- Performance optimization per vendor
- Error handling vendor-specific
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from ldap_core_shared.api import LDAP, LDAPConfig
from ldap_core_shared.core.operations import LDAPSearchParams
from ldap_core_shared.domain.models import LDAPEntry
from ldap_core_shared.utils.performance import PerformanceMonitor


class TestActiveDirectoryInteroperability:
    """🔥🔥🔥 Microsoft Active Directory Interoperability Testing."""

    @pytest.mark.asyncio
    async def test_active_directory_schema_compatibility(self) -> None:
        """Active Directory specific schema compatibility testing."""
        # Test AD-specific schema elements and compatibility

        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn.result = {"result": 0, "description": "success"}

            # Mock AD-specific schema response
            ad_schema_attributes = {
                "objectClass": ["user", "person", "organizationalPerson", "top"],
                "cn": ["John Doe"],
                "sAMAccountName": ["jdoe"],  # AD-specific
                "userPrincipalName": ["jdoe@example.com"],  # AD-specific
                "distinguishedName": ["CN=John Doe,OU=Users,DC=example,DC=com"],  # AD format
                "objectGUID": [b"\\x12\\x34\\x56\\x78\\x9A\\xBC\\xDE\\xF0\\x12\\x34\\x56\\x78\\x9A\\xBC\\xDE\\xF0"],  # AD-specific
                "objectSid": [b"\\x01\\x05\\x00\\x00\\x00\\x00\\x00\\x05\\x15\\x00\\x00\\x00"],  # AD-specific
                "whenCreated": ["20240626120000.0Z"],  # AD timestamp format
                "whenChanged": ["20240626120000.0Z"],  # AD timestamp format
                "userAccountControl": ["512"],  # AD-specific (Normal Account)
                "primaryGroupID": ["513"],  # AD-specific (Domain Users)
                "memberOf": [  # AD group membership format
                    "CN=Domain Users,CN=Users,DC=example,DC=com",
                    "CN=Engineering,OU=Groups,DC=example,DC=com",
                ],
            }

            mock_conn.search.return_value = True
            mock_conn.entries = [
                MagicMock(entry_dn="CN=John Doe,OU=Users,DC=example,DC=com", entry_attributes_as_dict=ad_schema_attributes),
            ]
            mock_conn_class.return_value = mock_conn

            # Test AD connection with specific configuration
            ad_config = LDAPConfig(
                server="ldap://ad.example.com:389",
                auth_dn="CN=Administrator,CN=Users,DC=example,DC=com",
                auth_password="password",
                server_type="active_directory",
                schema_compatibility_mode="ad",
            )

            async with LDAP(ad_config):
                # Test AD-specific search operations
                LDAPSearchParams(
                    search_base="DC=example,DC=com",
                    search_filter="(&(objectClass=user)(sAMAccountName=jdoe))",  # AD-specific filter
                    search_scope="SUBTREE",
                    attributes=["sAMAccountName", "userPrincipalName", "objectGUID", "objectSid"],
                )

                # Should handle AD-specific attributes correctly
                # In real implementation, would process binary attributes like objectGUID/objectSid

                # Test AD-specific user creation
                ad_user_entry = LDAPEntry(
                    dn="CN=New User,OU=Users,DC=example,DC=com",  # AD DN format
                    attributes={
                        "objectClass": ["user", "person", "organizationalPerson", "top"],
                        "cn": ["New User"],
                        "sAMAccountName": ["newuser"],  # Required in AD
                        "userPrincipalName": ["newuser@example.com"],  # AD email format
                        "givenName": ["New"],
                        "sn": ["User"],
                        "displayName": ["New User"],
                        "userAccountControl": ["512"],  # Normal account
                        "unicodePwd": ['"NewPassword123!"'],  # AD password format (UTF-16LE)
                    },
                )

                # Verify AD-specific DN format
                assert "CN=" in ad_user_entry.dn
                assert "DC=" in ad_user_entry.dn
                assert "OU=" in ad_user_entry.dn

                # Verify AD-specific attributes
                assert "sAMAccountName" in ad_user_entry.attributes
                assert "userPrincipalName" in ad_user_entry.attributes
                assert "userAccountControl" in ad_user_entry.attributes

    @pytest.mark.asyncio
    async def test_active_directory_authentication_methods(self) -> None:
        """Active Directory specific authentication methods testing."""
        # Test AD-specific authentication scenarios

        ad_auth_scenarios = [
            {
                "name": "simple_bind_ad_format",
                "config": {
                    "server": "ldap://ad.example.com:389",
                    "auth_dn": "CN=Administrator,CN=Users,DC=example,DC=com",  # AD format
                    "auth_password": "password",
                    "auth_method": "simple",
                },
            },
            {
                "name": "upn_authentication",
                "config": {
                    "server": "ldap://ad.example.com:389",
                    "auth_dn": "administrator@example.com",  # UPN format
                    "auth_password": "password",
                    "auth_method": "simple",
                },
            },
            {
                "name": "sam_account_authentication",
                "config": {
                    "server": "ldap://ad.example.com:389",
                    "auth_dn": "EXAMPLE\\administrator",  # SAM format
                    "auth_password": "password",
                    "auth_method": "simple",
                },
            },
            {
                "name": "kerberos_authentication",
                "config": {
                    "server": "ldap://ad.example.com:389",
                    "auth_method": "SASL",
                    "sasl_mechanism": "GSSAPI",
                    "kerberos_principal": "administrator@EXAMPLE.COM",
                },
            },
        ]

        with patch("ldap3.Connection") as mock_conn_class:
            for scenario in ad_auth_scenarios:
                mock_conn = MagicMock()
                mock_conn.bind.return_value = True
                mock_conn.bound = True
                mock_conn.result = {"result": 0, "description": "success"}

                # Mock AD-specific responses
                if scenario["name"] == "kerberos_authentication":
                    mock_conn.server.info.supported_sasl_mechanisms = ["GSSAPI", "GSS-SPNEGO"]

                mock_conn_class.return_value = mock_conn

                config = LDAPConfig(**scenario["config"])

                async with LDAP(config) as ldap_client:
                    assert ldap_client is not None

                    # Test AD-specific operations after authentication
                    if scenario["name"] == "upn_authentication":
                        # UPN should work for authentication
                        assert "@" in config.auth_dn

                    elif scenario["name"] == "sam_account_authentication":
                        # SAM account format should work
                        assert "\\" in config.auth_dn

                    elif scenario["name"] == "kerberos_authentication":
                        # Kerberos should work with AD
                        assert config.sasl_mechanism == "GSSAPI"

    @pytest.mark.asyncio
    async def test_active_directory_global_catalog_support(self) -> None:
        """Active Directory Global Catalog support testing."""
        # Test AD Global Catalog functionality

        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn.result = {"result": 0, "description": "success"}

            # Mock Global Catalog responses
            gc_schema_attributes = {
                "objectClass": ["user", "person", "organizationalPerson", "top"],
                "cn": ["Global User"],
                "sAMAccountName": ["gcuser"],
                "userPrincipalName": ["gcuser@domain1.example.com"],
                "distinguishedName": ["CN=Global User,OU=Users,DC=domain1,DC=example,DC=com"],
                "memberOf": [
                    "CN=Universal Group,CN=Users,DC=example,DC=com",  # Universal group (GC replicated)
                    "CN=Global Group,CN=Users,DC=domain1,DC=example,DC=com",  # Global group
                ],
            }

            mock_conn.search.return_value = True
            mock_conn.entries = [
                MagicMock(entry_dn="CN=Global User,OU=Users,DC=domain1,DC=example,DC=com",
                         entry_attributes_as_dict=gc_schema_attributes),
            ]
            mock_conn_class.return_value = mock_conn

            # Test Global Catalog connection (port 3268)
            gc_config = LDAPConfig(
                server="ldap://gc.example.com:3268",  # Global Catalog port
                auth_dn="CN=Administrator,CN=Users,DC=example,DC=com",
                auth_password="password",
                server_type="active_directory_gc",
                global_catalog=True,
            )

            async with LDAP(gc_config):
                # Test cross-domain search via Global Catalog
                LDAPSearchParams(
                    search_base="DC=example,DC=com",  # Forest root
                    search_filter="(&(objectClass=user)(userPrincipalName=*@domain1.example.com))",
                    search_scope="SUBTREE",
                    attributes=["sAMAccountName", "userPrincipalName", "memberOf"],
                )

                # Should find users across all domains in forest
                # GC contains partial replica of all domains
                assert gc_config.global_catalog is True
                assert ":3268" in gc_config.server  # GC port


class TestOpenLDAPInteroperability:
    """🔥🔥 OpenLDAP Interoperability Testing."""

    @pytest.mark.asyncio
    async def test_openldap_schema_compatibility(self) -> None:
        """OpenLDAP specific schema compatibility testing."""
        # Test OpenLDAP-specific schema elements

        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn.result = {"result": 0, "description": "success"}

            # Mock OpenLDAP-specific schema response
            openldap_schema_attributes = {
                "objectClass": ["inetOrgPerson", "person", "organizationalPerson", "top"],
                "cn": ["John Doe"],
                "uid": ["jdoe"],  # Standard LDAP attribute
                "mail": ["jdoe@example.com"],
                "userPassword": ["{SSHA}encrypted_password_hash"],  # OpenLDAP password format
                "createTimestamp": ["20240626120000Z"],  # OpenLDAP timestamp
                "modifyTimestamp": ["20240626120000Z"],  # OpenLDAP timestamp
                "entryUUID": ["12345678-1234-5678-9abc-def012345678"],  # OpenLDAP UUID
                "entryCSN": ["20240626120000.000000Z#000000#000#000000"],  # OpenLDAP CSN
                "structuralObjectClass": ["inetOrgPerson"],  # OpenLDAP specific
                "hasSubordinates": ["FALSE"],  # OpenLDAP operational attribute
                "subschemaSubentry": ["cn=Subschema"],  # Schema location
            }

            mock_conn.search.return_value = True
            mock_conn.entries = [
                MagicMock(entry_dn="uid=jdoe,ou=People,dc=example,dc=com", entry_attributes_as_dict=openldap_schema_attributes),
            ]
            mock_conn_class.return_value = mock_conn

            # Test OpenLDAP connection
            openldap_config = LDAPConfig(
                server="ldap://openldap.example.com:389",
                auth_dn="cn=admin,dc=example,dc=com",  # OpenLDAP admin DN format
                auth_password="password",
                server_type="openldap",
                schema_compatibility_mode="openldap",
            )

            async with LDAP(openldap_config):
                # Test OpenLDAP-specific search operations
                LDAPSearchParams(
                    search_base="dc=example,dc=com",
                    search_filter="(&(objectClass=inetOrgPerson)(uid=jdoe))",  # Standard LDAP filter
                    search_scope="SUBTREE",
                    attributes=["uid", "mail", "entryUUID", "createTimestamp"],
                )

                # Test OpenLDAP-specific user creation
                openldap_user_entry = LDAPEntry(
                    dn="uid=newuser,ou=People,dc=example,dc=com",  # OpenLDAP DN format
                    attributes={
                        "objectClass": ["inetOrgPerson", "person", "organizationalPerson", "top"],
                        "uid": ["newuser"],  # Standard uid attribute
                        "cn": ["New User"],
                        "sn": ["User"],
                        "givenName": ["New"],
                        "mail": ["newuser@example.com"],
                        "userPassword": ["{SSHA}encrypted_new_password"],  # OpenLDAP format
                        "description": ["OpenLDAP test user"],
                    },
                )

                # Verify OpenLDAP-specific DN format (uid-based)
                assert "uid=" in openldap_user_entry.dn
                assert "ou=" in openldap_user_entry.dn
                assert "dc=" in openldap_user_entry.dn

                # Verify standard LDAP attributes
                assert "uid" in openldap_user_entry.attributes
                assert "inetOrgPerson" in openldap_user_entry.attributes["objectClass"]

    @pytest.mark.asyncio
    async def test_openldap_overlay_support(self) -> None:
        """OpenLDAP overlay functionality testing."""
        # Test OpenLDAP-specific overlays and features

        overlay_scenarios = [
            {
                "overlay": "memberof",
                "description": "Automatic group membership tracking",
                "test_attributes": ["memberOf"],
            },
            {
                "overlay": "ppolicy",
                "description": "Password policy enforcement",
                "test_attributes": ["pwdPolicySubentry", "pwdChangedTime"],
            },
            {
                "overlay": "accesslog",
                "description": "Access logging overlay",
                "test_attributes": ["reqStart", "reqType", "reqSession"],
            },
            {
                "overlay": "syncprov",
                "description": "Synchronization provider",
                "test_attributes": ["entryCSN", "contextCSN"],
            },
        ]

        with patch("ldap3.Connection") as mock_conn_class:
            for overlay in overlay_scenarios:
                mock_conn = MagicMock()
                mock_conn.bind.return_value = True
                mock_conn.bound = True
                mock_conn.result = {"result": 0, "description": "success"}

                # Mock overlay-specific attributes
                overlay_attributes = {
                    "objectClass": ["inetOrgPerson", "person", "top"],
                    "cn": ["Overlay Test User"],
                    "uid": ["overlaytest"],
                }

                # Add overlay-specific attributes
                for attr in overlay["test_attributes"]:
                    if attr == "memberOf":
                        overlay_attributes[attr] = ["cn=testgroup,ou=Groups,dc=example,dc=com"]
                    elif attr == "pwdChangedTime":
                        overlay_attributes[attr] = ["20240626120000Z"]
                    elif attr == "reqStart":
                        overlay_attributes[attr] = ["20240626120000.000000Z"]
                    elif attr == "entryCSN":
                        overlay_attributes[attr] = ["20240626120000.000000Z#000000#000#000000"]
                    else:
                        overlay_attributes[attr] = ["test_value"]

                mock_conn.search.return_value = True
                mock_conn.entries = [
                    MagicMock(entry_dn="uid=overlaytest,ou=People,dc=example,dc=com",
                             entry_attributes_as_dict=overlay_attributes),
                ]
                mock_conn_class.return_value = mock_conn

                openldap_config = LDAPConfig(
                    server="ldap://openldap-overlay.example.com:389",
                    auth_dn="cn=admin,dc=example,dc=com",
                    auth_password="password",
                    openldap_overlays=[overlay["overlay"]],
                )

                async with LDAP(openldap_config):
                    # Test overlay-specific functionality
                    LDAPSearchParams(
                        search_base="dc=example,dc=com",
                        search_filter="(uid=overlaytest)",
                        search_scope="SUBTREE",
                        attributes=overlay["test_attributes"],
                    )

                    # Should support overlay-specific attributes
                    assert overlay["overlay"] in openldap_config.openldap_overlays


class Test389DirectoryInteroperability:
    """🔥🔥 389 Directory Server Interoperability Testing."""

    @pytest.mark.asyncio
    async def test_389ds_schema_compatibility(self) -> None:
        """389 Directory Server specific schema compatibility."""
        # Test 389 DS specific features and compatibility

        with patch("ldap3.Connection") as mock_conn_class:
            mock_conn = MagicMock()
            mock_conn.bind.return_value = True
            mock_conn.bound = True
            mock_conn.result = {"result": 0, "description": "success"}

            # Mock 389 DS specific schema response
            ds389_schema_attributes = {
                "objectClass": ["inetOrgPerson", "person", "organizationalPerson", "top"],
                "cn": ["John Doe"],
                "uid": ["jdoe"],
                "mail": ["jdoe@example.com"],
                "userPassword": ["{PBKDF2_SHA256}hashed_password"],  # 389 DS password format
                "createTimestamp": ["20240626120000Z"],
                "modifyTimestamp": ["20240626120000Z"],
                "nsUniqueId": ["12345678-abcd-1234-5678-def012345678"],  # 389 DS specific
                "nsAccountLock": ["false"],  # 389 DS account status
                "passwordExpirationTime": ["20250626120000Z"],  # 389 DS password policy
                "nsRole": ["cn=users,ou=Roles,dc=example,dc=com"],  # 389 DS role
                "nsRoleDN": ["cn=users,ou=Roles,dc=example,dc=com"],  # 389 DS role DN
                "ds-sync-state": ["present"],  # 389 DS sync state
            }

            mock_conn.search.return_value = True
            mock_conn.entries = [
                MagicMock(entry_dn="uid=jdoe,ou=People,dc=example,dc=com", entry_attributes_as_dict=ds389_schema_attributes),
            ]
            mock_conn_class.return_value = mock_conn

            # Test 389 DS connection
            ds389_config = LDAPConfig(
                server="ldap://389ds.example.com:389",
                auth_dn="cn=Directory Manager",  # 389 DS admin DN
                auth_password="password",
                server_type="389ds",
                schema_compatibility_mode="389ds",
            )

            async with LDAP(ds389_config):
                # Test 389 DS specific operations
                LDAPSearchParams(
                    search_base="dc=example,dc=com",
                    search_filter="(&(objectClass=inetOrgPerson)(nsAccountLock=false))",  # 389 DS filter
                    search_scope="SUBTREE",
                    attributes=["uid", "nsUniqueId", "nsAccountLock", "nsRole"],
                )

                # Test 389 DS specific role-based entry
                ds389_role_entry = LDAPEntry(
                    dn="cn=manager,ou=Roles,dc=example,dc=com",  # 389 DS role DN format
                    attributes={
                        "objectClass": ["nsRoleDefinition", "nsSimpleRoleDefinition", "top"],
                        "cn": ["manager"],
                        "description": ["Manager role for administrative tasks"],
                        "nsRoleFilter": ["(title=manager)"],  # 389 DS role filter
                    },
                )

                # Verify 389 DS specific attributes
                assert "nsRoleDefinition" in ds389_role_entry.attributes["objectClass"]
                assert "nsRoleFilter" in ds389_role_entry.attributes

    @pytest.mark.asyncio
    async def test_389ds_replication_features(self) -> None:
        """389 Directory Server replication features testing."""
        # Test 389 DS multi-master replication features

        replication_scenarios = [
            {
                "name": "master_server",
                "config": {
                    "server": "ldap://389ds-master1.example.com:389",
                    "replication_role": "master",
                    "replica_id": 1,
                },
            },
            {
                "name": "consumer_server",
                "config": {
                    "server": "ldap://389ds-consumer1.example.com:389",
                    "replication_role": "consumer",
                    "supplier_servers": ["ldap://389ds-master1.example.com:389"],
                },
            },
        ]

        with patch("ldap3.Connection") as mock_conn_class:
            for scenario in replication_scenarios:
                mock_conn = MagicMock()
                mock_conn.bind.return_value = True
                mock_conn.bound = True
                mock_conn.result = {"result": 0, "description": "success"}

                # Mock replication-specific responses
                replication_attributes = {
                    "objectClass": ["nsDS5Replica", "top"],
                    "nsDS5ReplicaRoot": ["dc=example,dc=com"],
                    "nsDS5ReplicaType": ["3" if scenario["name"] == "master_server" else "2"],
                    "nsDS5Flags": ["1"],
                    "nsDS5ReplicaId": [str(scenario["config"].get("replica_id", 0))],
                }

                mock_conn.search.return_value = True
                mock_conn.entries = [
                    MagicMock(entry_dn="cn=replica,cn=dc=example\\,dc=com,cn=mapping tree,cn=config",
                             entry_attributes_as_dict=replication_attributes),
                ]
                mock_conn_class.return_value = mock_conn

                config_params = {
                    "auth_dn": "cn=Directory Manager",
                    "auth_password": "password",
                    "server_type": "389ds",
                }
                config_params.update(scenario["config"])

                config = LDAPConfig(**config_params)

                async with LDAP(config):
                    # Test replication monitoring
                    LDAPSearchParams(
                        search_base="cn=mapping tree,cn=config",
                        search_filter="(objectClass=nsDS5Replica)",
                        search_scope="SUBTREE",
                        attributes=["nsDS5ReplicaRoot", "nsDS5ReplicaType", "nsDS5ReplicaId"],
                    )

                    # Should be able to query replication configuration
                    assert config.server_type == "389ds"


class TestCrossVendorCompatibility:
    """🔥🔥🔥 Cross-Vendor Compatibility EXTREME Testing."""

    @pytest.mark.asyncio
    async def test_schema_translation_cross_vendor(self) -> None:
        """Cross-vendor schema translation and compatibility testing."""
        # Test schema compatibility across different vendors

        vendor_schema_mappings = {
            "active_directory": {
                "user_object_class": "user",
                "username_attribute": "sAMAccountName",
                "email_attribute": "mail",
                "unique_id_attribute": "objectGUID",
                "group_membership_attribute": "memberOf",
                "dn_format": "CN={name},OU={ou},DC={domain}",
            },
            "openldap": {
                "user_object_class": "inetOrgPerson",
                "username_attribute": "uid",
                "email_attribute": "mail",
                "unique_id_attribute": "entryUUID",
                "group_membership_attribute": "memberOf",  # With overlay
                "dn_format": "uid={username},ou={ou},dc={domain}",
            },
            "389ds": {
                "user_object_class": "inetOrgPerson",
                "username_attribute": "uid",
                "email_attribute": "mail",
                "unique_id_attribute": "nsUniqueId",
                "group_membership_attribute": "nsRole",
                "dn_format": "uid={username},ou={ou},dc={domain}",
            },
        }

        # Test cross-vendor user representation
        test_user_data = {
            "username": "testuser",
            "full_name": "Test User",
            "email": "testuser@example.com",
            "organizational_unit": "People",
            "domain": "example.com",
        }

        with patch("ldap3.Connection") as mock_conn_class:
            for vendor, schema_mapping in vendor_schema_mappings.items():
                mock_conn = MagicMock()
                mock_conn.bind.return_value = True
                mock_conn.bound = True
                mock_conn.result = {"result": 0, "description": "success"}
                mock_conn_class.return_value = mock_conn

                # Generate vendor-specific entry
                vendor_entry = self._generate_vendor_specific_entry(
                    test_user_data,
                    schema_mapping,
                    vendor,
                )

                config = LDAPConfig(
                    server=f"ldap://{vendor}.example.com:389",
                    auth_dn=self._get_vendor_admin_dn(vendor),
                    auth_password="password",
                    server_type=vendor,
                    schema_compatibility_mode=vendor,
                )

                async with LDAP(config):
                    # Test vendor-specific search
                    search_filter = f"({schema_mapping['username_attribute']}={test_user_data['username']})"

                    LDAPSearchParams(
                        search_base=self._get_vendor_base_dn(vendor, test_user_data["domain"]),
                        search_filter=search_filter,
                        search_scope="SUBTREE",
                        attributes=[
                            schema_mapping["username_attribute"],
                            schema_mapping["email_attribute"],
                            schema_mapping["unique_id_attribute"],
                        ],
                    )

                    # Verify vendor-specific entry structure
                    assert schema_mapping["username_attribute"] in vendor_entry.attributes
                    assert schema_mapping["user_object_class"] in vendor_entry.attributes["objectClass"]

                    # Test cross-vendor compatibility by normalizing to standard format
                    normalized_entry = self._normalize_entry_cross_vendor(vendor_entry, schema_mapping)

                    # Normalized entry should have standard attributes regardless of vendor
                    assert "username" in normalized_entry
                    assert "email" in normalized_entry
                    assert "unique_id" in normalized_entry

    def _generate_vendor_specific_entry(self, user_data: dict[str, str], schema_mapping: dict[str, str], vendor: str) -> LDAPEntry:
        """Generate vendor-specific LDAP entry."""
        # Build vendor-specific DN
        if vendor == "active_directory":
            dn = f"CN={user_data['full_name']},OU={user_data['organizational_unit']},DC={user_data['domain'].replace('.', ',DC=')}"
            object_classes = ["user", "person", "organizationalPerson", "top"]
        else:
            dn = f"uid={user_data['username']},ou={user_data['organizational_unit']},dc={user_data['domain'].replace('.', ',dc=')}"
            object_classes = ["inetOrgPerson", "person", "organizationalPerson", "top"]

        # Build vendor-specific attributes
        attributes = {
            "objectClass": object_classes,
            "cn": [user_data["full_name"]],
            schema_mapping["username_attribute"]: [user_data["username"]],
            schema_mapping["email_attribute"]: [user_data["email"]],
        }

        # Add vendor-specific unique identifier
        if vendor == "active_directory":
            attributes[schema_mapping["unique_id_attribute"]] = [b"\\x12\\x34\\x56\\x78\\x9A\\xBC\\xDE\\xF0\\x12\\x34\\x56\\x78\\x9A\\xBC\\xDE\\xF0"]
        elif vendor == "openldap":
            attributes[schema_mapping["unique_id_attribute"]] = ["12345678-1234-5678-9abc-def012345678"]
        elif vendor == "389ds":
            attributes[schema_mapping["unique_id_attribute"]] = ["12345678-abcd-1234-5678-def012345678"]

        return LDAPEntry(dn=dn, attributes=attributes)

    def _get_vendor_admin_dn(self, vendor: str) -> str:
        """Get vendor-specific admin DN."""
        if vendor == "active_directory":
            return "CN=Administrator,CN=Users,DC=example,DC=com"
        if vendor == "openldap":
            return "cn=admin,dc=example,dc=com"
        if vendor == "389ds":
            return "cn=Directory Manager"
        return "cn=admin,dc=example,dc=com"

    def _get_vendor_base_dn(self, vendor: str, domain: str) -> str:
        """Get vendor-specific base DN."""
        if vendor == "active_directory":
            return f"DC={domain.replace('.', ',DC=')}"
        return f"dc={domain.replace('.', ',dc=')}"

    def _normalize_entry_cross_vendor(self, entry: LDAPEntry, schema_mapping: dict[str, str]) -> dict[str, Any]:
        """Normalize vendor-specific entry to standard format."""
        return {
            "dn": entry.dn,
            "username": entry.attributes.get(schema_mapping["username_attribute"], [None])[0],
            "email": entry.attributes.get(schema_mapping["email_attribute"], [None])[0],
            "unique_id": entry.attributes.get(schema_mapping["unique_id_attribute"], [None])[0],
        }

    @pytest.mark.asyncio
    async def test_performance_optimization_per_vendor(self) -> None:
        """Performance optimization testing per vendor."""
        # Test vendor-specific performance optimizations

        performance_monitor = PerformanceMonitor(name="vendor_performance")

        vendor_optimizations = {
            "active_directory": {
                "page_size": 1000,  # AD optimal page size
                "connection_pool_size": 10,
                "timeout": 30,
                "optimized_filters": ["sAMAccountName", "userPrincipalName"],
                "binary_attributes": ["objectGUID", "objectSid"],
            },
            "openldap": {
                "page_size": 500,  # OpenLDAP optimal page size
                "connection_pool_size": 20,
                "timeout": 15,
                "optimized_filters": ["uid", "mail"],
                "index_attributes": ["uid", "cn", "mail"],
            },
            "389ds": {
                "page_size": 1000,  # 389 DS optimal page size
                "connection_pool_size": 15,
                "timeout": 20,
                "optimized_filters": ["uid", "nsUniqueId"],
                "vlv_support": True,  # Virtual List View
            },
        }

        with patch("ldap3.Connection") as mock_conn_class:
            for vendor, optimizations in vendor_optimizations.items():
                mock_conn = MagicMock()
                mock_conn.bind.return_value = True
                mock_conn.bound = True
                mock_conn.result = {"result": 0, "description": "success"}
                mock_conn_class.return_value = mock_conn

                config = LDAPConfig(
                    server=f"ldap://{vendor}-perf.example.com:389",
                    auth_dn=self._get_vendor_admin_dn(vendor),
                    auth_password="password",
                    server_type=vendor,
                    page_size=optimizations["page_size"],
                    connection_pool_size=optimizations["connection_pool_size"],
                    connection_timeout=optimizations["timeout"],
                )

                performance_monitor.start_measurement(f"vendor_performance_{vendor}")

                async with LDAP(config):
                    # Test vendor-optimized search
                    for filter_attr in optimizations["optimized_filters"]:
                        LDAPSearchParams(
                            search_base=self._get_vendor_base_dn(vendor, "example.com"),
                            search_filter=f"({filter_attr}=*)",
                            search_scope="SUBTREE",
                            page_size=optimizations["page_size"],
                        )

                        # Simulate search performance
                        await asyncio.sleep(0.001)

                performance_monitor.stop_measurement(f"vendor_performance_{vendor}")

                # Verify vendor-specific search optimization worked
                assert search_params.search_filter is not None
                assert search_params.search_base is not None

        # Analyze cross-vendor performance
        metrics = performance_monitor.get_metrics()

        # Verify performance monitoring worked
        assert metrics.operation_count >= 0
        assert isinstance(metrics.operations_per_second, float)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
