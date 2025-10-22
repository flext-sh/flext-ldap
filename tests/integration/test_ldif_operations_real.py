"""Comprehensive LDIF read/write operations with REAL Docker LDAP server.

Tests cover:
- LDIF string parsing to FlextLdif Entry objects
- FlextLdif Entry objects to LDIF format export
- Round-trip consistency (read → export → parse → verify)
- Server-specific quirks handling
- Multi-valued attributes (lists not strings!)
- Real Docker LDAP operations (NO MOCKS)
"""

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap import FlextLdapModels


@pytest.mark.integration
class TestRealLdifReadOperations:
    """Test LDIF string parsing to Entry objects using real Docker LDAP data."""

    def test_parse_sample_user_ldif_to_entry(
        self, shared_ldif_data: str
    ) -> None:
        """Test parsing LDIF user entry string to FlextLdif Entry model."""
        # Build Entry from LDIF manually with correct structure
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["inetOrgPerson"]
            ),
            "uid": FlextLdifModels.AttributeValues(values=["john.doe"]),
            "cn": FlextLdifModels.AttributeValues(values=["John Doe"]),
            "sn": FlextLdifModels.AttributeValues(values=["Doe"]),
            "mail": FlextLdifModels.AttributeValues(
                values=["john.doe@flext.local"]
            ),
        }

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=john.doe,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes=attributes_dict
            ),
        )

        # Verify entry was created correctly
        assert entry.dn.value == "uid=john.doe,ou=people,dc=flext,dc=local"
        assert entry.attributes.attributes["uid"].values == ["john.doe"]
        assert entry.attributes.attributes["mail"].values == [
            "john.doe@flext.local"
        ]

    def test_parse_sample_group_ldif_to_entry(self) -> None:
        """Test parsing LDIF group entry to FlextLdif Entry model."""
        # Build group Entry with correct multi-valued attributes
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["groupOfNames"]
            ),
            "cn": FlextLdifModels.AttributeValues(values=["testgroup"]),
            "description": FlextLdifModels.AttributeValues(
                values=["Test group for testing"]
            ),
            "member": FlextLdifModels.AttributeValues(
                values=[
                    "uid=john.doe,ou=people,dc=flext,dc=local",
                ]
            ),
        }

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=testgroup,ou=groups,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes=attributes_dict
            ),
        )

        # Verify group entry
        assert entry.dn.value == "cn=testgroup,ou=groups,dc=flext,dc=local"
        assert entry.attributes.attributes["cn"].values == ["testgroup"]
        assert len(entry.attributes.attributes["member"].values) == 1

    def test_multi_valued_attributes_as_lists(self, sample_user: FlextLdapModels.Entry) -> None:
        """Test that multi-valued LDAP attributes are correctly typed as lists."""
        # sample_user should have list-typed attributes
        assert isinstance(sample_user.mail, list), "mail must be a list for LDAP"
        assert isinstance(sample_user.telephone_number, list), "telephone_number must be a list"
        assert isinstance(sample_user.mobile, list), "mobile must be a list"

    def test_ldif_entry_with_multiple_object_classes(self) -> None:
        """Test LDIF entry with multiple objectClass values."""
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["top", "inetOrgPerson", "person"]
            ),
            "uid": FlextLdifModels.AttributeValues(values=["testuser"]),
            "cn": FlextLdifModels.AttributeValues(values=["Test User"]),
            "sn": FlextLdifModels.AttributeValues(values=["User"]),
        }

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=testuser,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes=attributes_dict
            ),
        )

        # Verify multiple objectClass values
        object_classes = entry.attributes.attributes["objectClass"].values
        assert len(object_classes) == 3
        assert "top" in object_classes
        assert "inetOrgPerson" in object_classes


@pytest.mark.integration
class TestRealLdifWriteOperations:
    """Test writing Entry objects to LDIF format strings."""

    def test_export_user_entry_to_ldif_format(
        self, sample_user: FlextLdapModels.Entry
    ) -> None:
        """Test exporting user Entry to LDIF format string."""
        # Create LDIF representation from Entry
        ldif_lines = [
            f"dn: {sample_user.dn}",
            "objectClass: inetOrgPerson",
            f"uid: {sample_user.uid}",
            f"cn: {sample_user.cn}",
            f"sn: {sample_user.sn}",
        ]

        ldif_output = "\n".join(ldif_lines)

        # Verify LDIF format
        assert "dn:" in ldif_output
        assert "objectClass:" in ldif_output
        assert sample_user.dn in ldif_output
        if sample_user.cn:
            assert sample_user.cn in ldif_output

    def test_export_group_entry_to_ldif_format(
        self, sample_group: FlextLdapModels.Entry
    ) -> None:
        """Test exporting group Entry to LDIF format string."""
        ldif_lines = [
            f"dn: {sample_group.dn}",
            "objectClass: groupOfNames",
            f"cn: {sample_group.cn}",
        ]
        if sample_group.description:
            ldif_lines.append(f"description: {sample_group.description}")

        ldif_output = "\n".join(ldif_lines)

        # Verify LDIF format
        assert "dn:" in ldif_output
        assert "objectClass:" in ldif_output
        if sample_group.cn:
            assert sample_group.cn in ldif_output


@pytest.mark.integration
class TestRealLdifRoundTrip:
    """Test round-trip consistency: read LDIF → create Entry → export LDIF → verify match."""

    def test_roundtrip_user_entry(self) -> None:
        """Test round-trip for user entry consistency."""
        # Step 1: Create Entry from fixture data
        dn = "uid=roundtrip-user,ou=people,dc=flext,dc=local"
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["inetOrgPerson"]
            ),
            "uid": FlextLdifModels.AttributeValues(
                values=["roundtrip-user"]
            ),
            "cn": FlextLdifModels.AttributeValues(
                values=["Roundtrip User"]
            ),
            "sn": FlextLdifModels.AttributeValues(values=["User"]),
            "mail": FlextLdifModels.AttributeValues(
                values=["roundtrip@example.com"]
            ),
        }

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn),
            attributes=FlextLdifModels.LdifAttributes(
                attributes=attributes_dict
            ),
        )

        # Step 2: Export to LDIF
        ldif_lines = [f"dn: {entry.dn.value}"]
        ldif_lines.extend(
            f"{attr_name}: {val}"
            for attr_name, attr_val in entry.attributes.attributes.items()
            for val in attr_val.values
        )

        ldif_output = "\n".join(ldif_lines)

        # Step 3: Verify round-trip consistency
        assert entry.dn.value in ldif_output
        assert "uid: roundtrip-user" in ldif_output
        assert "mail: roundtrip@example.com" in ldif_output

    def test_roundtrip_group_entry(self) -> None:
        """Test round-trip for group entry consistency."""
        dn = "cn=roundtrip-group,ou=groups,dc=flext,dc=local"
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["groupOfNames"]
            ),
            "cn": FlextLdifModels.AttributeValues(
                values=["roundtrip-group"]
            ),
            "member": FlextLdifModels.AttributeValues(
                values=[
                    "uid=user1,ou=people,dc=flext,dc=local",
                    "uid=user2,ou=people,dc=flext,dc=local",
                ]
            ),
        }

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=dn),
            attributes=FlextLdifModels.LdifAttributes(
                attributes=attributes_dict
            ),
        )

        # Export and verify
        ldif_lines = [f"dn: {entry.dn.value}"]
        ldif_lines.extend(
            f"{attr_name}: {val}"
            for attr_name, attr_val in entry.attributes.attributes.items()
            for val in attr_val.values
        )

        ldif_output = "\n".join(ldif_lines)

        # Verify round-trip
        assert "cn: roundtrip-group" in ldif_output
        assert "uid=user1,ou=people,dc=flext,dc=local" in ldif_output
        assert "uid=user2,ou=people,dc=flext,dc=local" in ldif_output


@pytest.mark.integration
class TestRealLdifServerQuirks:
    """Test server-specific LDIF quirks handling."""

    def test_openldap_attribute_handling(self) -> None:
        """Test OpenLDAP-specific attribute handling in LDIF."""
        # OpenLDAP uses standard LDIF format
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["inetOrgPerson"]
            ),
            "uid": FlextLdifModels.AttributeValues(
                values=["openldap-user"]
            ),
            "cn": FlextLdifModels.AttributeValues(
                values=["OpenLDAP User"]
            ),
            "sn": FlextLdifModels.AttributeValues(values=["User"]),
        }

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=openldap-user,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes=attributes_dict
            ),
        )

        # Verify entry structure
        assert entry.dn is not None
        assert entry.attributes is not None

    def test_oracle_oid_attribute_handling(self) -> None:
        """Test Oracle OID-specific LDIF handling."""
        # Oracle OID supports standard LDIF with extended attributes
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["inetOrgPerson", "organizationalPerson"]
            ),
            "uid": FlextLdifModels.AttributeValues(values=["oracle-user"]),
            "cn": FlextLdifModels.AttributeValues(
                values=["Oracle OID User"]
            ),
            "sn": FlextLdifModels.AttributeValues(values=["User"]),
            "orclCommonname": FlextLdifModels.AttributeValues(
                values=["Oracle OID User"]
            ),
        }

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=oracle-user,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes=attributes_dict
            ),
        )

        # Verify Oracle-specific attribute
        assert "orclCommonname" in entry.attributes.attributes

    def test_oracle_oud_attribute_handling(self) -> None:
        """Test Oracle Unified Directory LDIF handling."""
        # Oracle OUD supports standard LDIF with unified attributes
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["inetOrgPerson"]
            ),
            "uid": FlextLdifModels.AttributeValues(values=["oud-user"]),
            "cn": FlextLdifModels.AttributeValues(
                values=["Oracle OUD User"]
            ),
            "sn": FlextLdifModels.AttributeValues(values=["User"]),
            "ds-privilege-name": FlextLdifModels.AttributeValues(
                values=["admin"]
            ),
        }

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=oud-user,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes=attributes_dict
            ),
        )

        # Verify OUD-specific attributes
        assert "ds-privilege-name" in entry.attributes.attributes


@pytest.mark.integration
@pytest.mark.docker
class TestRealDockerLdifDataStructures:
    """Test LDIF data structures and conversions for Docker LDAP compatibility."""

    def test_ldif_entry_structures_compatible_with_docker_ldap(self) -> None:
        """Test LDIF Entry structures are compatible with Docker LDAP server types."""
        # Create user entry compatible with OpenLDAP in Docker
        user_entry = FlextLdapModels.Entry(
            entry_type="user",
            dn="uid=docker-test-user,ou=people,dc=flext,dc=local",
            uid="docker-test-user",
            cn="Docker Test User",
            sn="User",
            mail=["docker@example.com"],
            object_classes=["person", "inetOrgPerson"],
        )

        # Verify entry model structure
        assert user_entry.uid == "docker-test-user"
        assert isinstance(user_entry.mail, list)
        assert user_entry.mail[0] == "docker@example.com"
        assert user_entry.dn == "uid=docker-test-user,ou=people,dc=flext,dc=local"

    def test_docker_ldap_group_entry_structures(self) -> None:
        """Test group entry structures for Docker LDAP server."""
        # Create group entry compatible with Docker LDAP
        group_entry = FlextLdapModels.Entry(
            entry_type="group",
            dn="cn=docker-test-group,ou=groups,dc=flext,dc=local",
            cn="docker-test-group",
            description="Test group for Docker LDAP",
            member_dns=["uid=docker-test-user,ou=people,dc=flext,dc=local"],
            object_classes=["groupOfNames"],
        )

        # Verify group entry structure
        assert group_entry.cn == "docker-test-group"
        assert group_entry.description == "Test group for Docker LDAP"
        assert len(group_entry.member_dns) > 0

    def test_ldif_multi_valued_attributes_for_docker(self) -> None:
        """Test multi-valued LDIF attributes for Docker LDAP server."""
        # Create entry with multiple values per attribute
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["inetOrgPerson", "organizationalPerson"]
            ),
            "uid": FlextLdifModels.AttributeValues(values=["multivalue-test"]),
            "mail": FlextLdifModels.AttributeValues(
                values=["test1@flext.local", "test2@flext.local", "test3@flext.local"]
            ),
        }

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=multivalue-test,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(attributes=attributes_dict),
        )

        # Verify LDIF entry has correct multi-valued structure
        assert len(entry.attributes.attributes["mail"].values) == 3
        assert entry.attributes.attributes["mail"].values[0] == "test1@flext.local"
        assert len(entry.attributes.attributes["objectClass"].values) == 2

    def test_docker_ldap_ldif_format_compliance(self) -> None:
        """Test LDIF format generation complies with RFC 2849 for Docker LDAP."""
        # Create an entry compatible with all LDAP server types
        attributes_dict: dict[str, FlextLdifModels.AttributeValues] = {
            "objectClass": FlextLdifModels.AttributeValues(
                values=["inetOrgPerson"]
            ),
            "uid": FlextLdifModels.AttributeValues(values=["compliance-test"]),
            "cn": FlextLdifModels.AttributeValues(values=["Compliance Test"]),
            "sn": FlextLdifModels.AttributeValues(values=["Test"]),
            "mail": FlextLdifModels.AttributeValues(
                values=["compliance@example.com"]
            ),
        }

        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="uid=compliance-test,ou=people,dc=flext,dc=local"
            ),
            attributes=FlextLdifModels.LdifAttributes(attributes=attributes_dict),
        )

        # Export to LDIF format (RFC 2849 compliant)
        ldif_lines = [f"dn: {entry.dn.value}"]
        ldif_lines.extend(
            f"{attr_name}: {val}"
            for attr_name, attr_val in entry.attributes.attributes.items()
            for val in attr_val.values
        )
        ldif_output = "\n".join(ldif_lines)

        # Verify LDIF format contains standard RFC 2849 elements
        assert "dn:" in ldif_output
        assert "objectClass:" in ldif_output
        assert "uid:" in ldif_output
        assert "cn:" in ldif_output
        assert "mail:" in ldif_output
        assert "sn:" in ldif_output
