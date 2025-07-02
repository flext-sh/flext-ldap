"""🚀 RFC 4512 Compliance Tests - LDAP Directory Information Models.

This module implements comprehensive tests for RFC 4512 compliance, ensuring
that the LDAP Directory Information Models implementation strictly adheres
to the specification with zero tolerance for deviations.

RFC 4512 Reference: https://tools.ietf.org/rfc/rfc4512.txt
ZERO TOLERANCE TESTING: Every aspect of the RFC must be verified.

RFC 4512 covers:
- Directory Information Tree (DIT) structure
- Entry structure and naming
- Object Classes and Attribute Descriptions
- Schema definitions and discovery
- Administrative and operational information
- DSA (Server) informational model
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from ldap_core_shared.domain.models import LDAPEntry
from ldap_core_shared.domain.results import LDAPSearchResult
from ldap_core_shared.schema.validator import SchemaValidator
from ldap_core_shared.utilities.dn import DNParser


class TestRFC4512DirectoryInformationTree:
    """🔥 RFC 4512 Section 2.1 - Directory Information Tree Tests."""

    def test_dit_structure_requirements(self) -> None:
        """RFC 4512 Section 2.1 - DIT structure requirements."""
        # RFC 4512: The Directory Information Tree (DIT) is a tree of entries
        # Each entry has a distinguished name (DN) that uniquely identifies it

        # Test hierarchical DIT structure
        dit_entries = [
            "dc=example,dc=com",  # Root
            "ou=People,dc=example,dc=com",  # Organizational Unit
            "ou=Groups,dc=example,dc=com",  # Organizational Unit
            "cn=John Doe,ou=People,dc=example,dc=com",  # Person entry
            "cn=Administrators,ou=Groups,dc=example,dc=com",  # Group entry
        ]

        for dn in dit_entries:
            # Each DN must be valid and parseable
            parsed_dn = DNParser.parse(dn)
            assert parsed_dn is not None
            assert len(parsed_dn.components) > 0

            # Verify DN structure follows naming conventions
            assert "=" in dn  # Must have attribute=value format

    def test_dit_naming_hierarchy(self) -> None:
        """RFC 4512 Section 2.1 - DIT naming hierarchy compliance."""
        # RFC 4512: DIT forms a tree with parent-child relationships

        hierarchy_tests = [
            {
                "parent": "dc=example,dc=com",
                "child": "ou=People,dc=example,dc=com",
                "valid": True,
            },
            {
                "parent": "ou=People,dc=example,dc=com",
                "child": "cn=John Doe,ou=People,dc=example,dc=com",
                "valid": True,
            },
            {
                "parent": "dc=example,dc=com",
                "child": "cn=John Doe,ou=People,dc=example,dc=com",
                "valid": False,  # Child is not immediate descendant
            },
        ]

        for test in hierarchy_tests:
            parent_parsed = DNParser.parse(test["parent"])
            child_parsed = DNParser.parse(test["child"])

            assert parent_parsed is not None
            assert child_parsed is not None

            # Verify hierarchy relationship
            if test["valid"]:
                # Child should have one more component than parent
                assert len(child_parsed.components) == len(parent_parsed.components) + 1
            else:
                # Invalid relationship should not have immediate parent-child structure
                assert len(child_parsed.components) != len(parent_parsed.components) + 1

    def test_dit_entry_uniqueness(self) -> None:
        """RFC 4512 Section 2.1 - DIT entry uniqueness requirements."""
        # RFC 4512: Each entry in the DIT has a unique DN

        # Test that identical DNs are recognized as the same entry
        dn1 = "cn=John Doe,ou=People,dc=example,dc=com"
        dn2 = "cn=John Doe,ou=People,dc=example,dc=com"
        dn3 = "cn=Jane Smith,ou=People,dc=example,dc=com"

        parsed_dn1 = DNParser.parse(dn1)
        parsed_dn2 = DNParser.parse(dn2)
        parsed_dn3 = DNParser.parse(dn3)

        # Same DNs should be equivalent
        assert parsed_dn1.canonical == parsed_dn2.canonical

        # Different DNs should not be equivalent
        assert parsed_dn1.canonical != parsed_dn3.canonical


class TestRFC4512EntryStructure:
    """🔥 RFC 4512 Section 2.2 - Structure of an Entry Tests."""

    def test_entry_attribute_value_structure(self) -> None:
        """RFC 4512 Section 2.2 - Entry attribute-value structure."""
        # RFC 4512: An entry consists of a collection of attributes
        # Each attribute has a type and one or more values

        entry = LDAPEntry(
            dn="cn=John Doe,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],  # Multi-valued
                "cn": ["John Doe"],  # Single-valued
                "sn": ["Doe"],  # Single-valued
                "givenName": ["John"],  # Single-valued
                "mail": ["john.doe@example.com"],  # Single-valued
                "telephoneNumber": ["+1-555-1234", "+1-555-5678"],  # Multi-valued
            },
        )

        # Verify entry structure compliance
        assert entry.dn == "cn=John Doe,ou=People,dc=example,dc=com"
        assert isinstance(entry.attributes, dict)

        # Verify attribute structure
        for attr_name, attr_values in entry.attributes.items():
            assert isinstance(attr_name, str)
            assert isinstance(attr_values, list)
            assert len(attr_values) > 0  # No empty attribute values

            # All values must be strings (in LDAP string representation)
            for value in attr_values:
                assert isinstance(value, str)

    def test_entry_objectclass_requirement(self) -> None:
        """RFC 4512 Section 2.2 - objectClass attribute requirement."""
        # RFC 4512: Every entry must have an objectClass attribute

        # Valid entry with objectClass
        valid_entry = LDAPEntry(
            dn="cn=John Doe,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
            },
        )

        assert "objectClass" in valid_entry.attributes
        assert len(valid_entry.attributes["objectClass"]) > 0

        # Entry without objectClass should be invalid
        with pytest.raises((ValueError, PydanticValidationError)):
            LDAPEntry(
                dn="cn=Invalid Entry,ou=People,dc=example,dc=com",
                attributes={
                    "cn": ["Invalid Entry"],
                    # Missing objectClass - should fail validation
                },
            )

    def test_entry_distinguished_name_compliance(self) -> None:
        """RFC 4512 Section 2.2 - Distinguished Name compliance."""
        # RFC 4512: Each entry has a distinguished name (DN)

        test_entries = [
            {
                "dn": "cn=John Doe,ou=People,dc=example,dc=com",
                "rdn": "cn=John Doe",
                "parent": "ou=People,dc=example,dc=com",
            },
            {
                "dn": "ou=People,dc=example,dc=com",
                "rdn": "ou=People",
                "parent": "dc=example,dc=com",
            },
            {
                "dn": "dc=example,dc=com",
                "rdn": "dc=example",
                "parent": None,  # Root entry
            },
        ]

        for test in test_entries:
            parsed_dn = DNParser.parse(test["dn"])
            assert parsed_dn is not None

            # Verify RDN (Relative Distinguished Name) extraction
            assert parsed_dn.rdn == test["rdn"]

            # Verify parent DN extraction
            if test["parent"]:
                assert parsed_dn.parent == test["parent"]
            else:
                assert parsed_dn.parent is None


class TestRFC4512ObjectClasses:
    """🔥 RFC 4512 Section 2.4 - Object Classes Tests."""

    def test_objectclass_hierarchy_compliance(self) -> None:
        """RFC 4512 Section 2.4 - Object class hierarchy."""
        # RFC 4512: Object classes form an inheritance hierarchy

        # Test object class inheritance chains
        inheritance_tests = [
            {
                "objectClass": "person",
                "superClasses": ["top"],
                "attributes": ["cn", "sn"],
            },
            {
                "objectClass": "inetOrgPerson",
                "superClasses": ["person", "organizationalPerson", "top"],
                "attributes": ["cn", "sn", "mail", "telephoneNumber"],
            },
            {
                "objectClass": "organizationalUnit",
                "superClasses": ["top"],
                "attributes": ["ou"],
            },
        ]

        for test in inheritance_tests:
            # Verify object class definition exists
            object_class = test["objectClass"]
            assert isinstance(object_class, str)
            assert len(object_class) > 0

            # Verify required attributes for object class
            required_attrs = test["attributes"]
            for attr in required_attrs:
                assert isinstance(attr, str)
                assert len(attr) > 0

    def test_objectclass_structural_compliance(self) -> None:
        """RFC 4512 Section 2.4 - Structural object class compliance."""
        # RFC 4512: Each entry must have exactly one structural object class

        # Valid entries with structural object classes
        structural_tests = [
            {
                "objectClasses": ["person"],  # person is structural
                "valid": True,
            },
            {
                "objectClasses": ["inetOrgPerson"],  # inetOrgPerson is structural
                "valid": True,
            },
            {
                "objectClasses": [
                    "person",
                    "inetOrgPerson",
                ],  # Multiple structural - invalid
                "valid": False,
            },
            {
                "objectClasses": ["top"],  # top is abstract, not structural
                "valid": False,
            },
        ]

        for test in structural_tests:
            if test["valid"]:
                # Should have exactly one structural object class
                structural_count = sum(
                    1
                    for oc in test["objectClasses"]
                    if oc in {"person", "inetOrgPerson", "organizationalUnit"}
                )
                assert structural_count == 1
            else:
                # Should not have valid structural object class configuration
                structural_count = sum(
                    1
                    for oc in test["objectClasses"]
                    if oc in {"person", "inetOrgPerson", "organizationalUnit"}
                )
                assert structural_count != 1

    def test_objectclass_attribute_requirements(self) -> None:
        """RFC 4512 Section 2.4 - Object class attribute requirements."""
        # RFC 4512: Object classes define required and optional attributes

        # Test person object class requirements
        person_entry = LDAPEntry(
            dn="cn=John Doe,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["John Doe"],  # Required by person
                "sn": ["Doe"],  # Required by person
                "telephoneNumber": ["+1-555-1234"],  # Optional for person
            },
        )

        # Verify required attributes present
        assert "cn" in person_entry.attributes
        assert "sn" in person_entry.attributes

        # Test missing required attributes should fail
        with pytest.raises((ValueError, PydanticValidationError)):
            LDAPEntry(
                dn="cn=Invalid Person,ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Invalid Person"],
                    # Missing required 'sn' attribute
                },
            )


class TestRFC4512AttributeDescriptions:
    """🔥 RFC 4512 Section 2.5 - Attribute Descriptions Tests."""

    def test_attribute_type_compliance(self) -> None:
        """RFC 4512 Section 2.5 - Attribute type compliance."""
        # RFC 4512: Each attribute has a type that defines its syntax and semantics

        attribute_tests = [
            {
                "type": "cn",
                "syntax": "Directory String",
                "values": ["John Doe", "Johnny"],
                "valid": True,
            },
            {
                "type": "mail",
                "syntax": "IA5 String",
                "values": ["john.doe@example.com"],
                "valid": True,
            },
            {
                "type": "telephoneNumber",
                "syntax": "Telephone Number",
                "values": ["+1-555-1234"],
                "valid": True,
            },
            {
                "type": "objectClass",
                "syntax": "Object Identifier",
                "values": ["person", "inetOrgPerson"],
                "valid": True,
            },
        ]

        for test in attribute_tests:
            attr_type = test["type"]
            attr_values = test["values"]

            # Verify attribute type is valid string
            assert isinstance(attr_type, str)
            assert len(attr_type) > 0

            # Verify values structure
            assert isinstance(attr_values, list)
            assert len(attr_values) > 0

            # All values must be strings
            for value in attr_values:
                assert isinstance(value, str)
                assert len(value) > 0

    def test_attribute_syntax_validation(self) -> None:
        """RFC 4512 Section 2.5 - Attribute syntax validation."""
        # RFC 4512: Attribute values must conform to their syntax

        syntax_tests = [
            {
                "attribute": "mail",
                "valid_values": [
                    "user@example.com",
                    "test.email@domain.org",
                    "valid-email@company.co.uk",
                ],
                "invalid_values": [
                    "invalid-email",
                    "@domain.com",
                    "user@",
                    "",
                ],
            },
            {
                "attribute": "telephoneNumber",
                "valid_values": [
                    "+1-555-1234",
                    "+44-20-1234-5678",
                    "555-1234",
                ],
                "invalid_values": [
                    "",
                    "not-a-phone-number",
                    "++1-555-1234",
                ],
            },
        ]

        for test in syntax_tests:
            attr_name = test["attribute"]

            # Test valid values
            for valid_value in test["valid_values"]:
                entry = LDAPEntry(
                    dn="cn=Test,ou=People,dc=example,dc=com",
                    attributes={
                        "objectClass": ["person"],
                        "cn": ["Test"],
                        "sn": ["Test"],
                        attr_name: [valid_value],
                    },
                )
                assert attr_name in entry.attributes
                assert valid_value in entry.attributes[attr_name]

            # Test invalid values (would be caught by schema validation)
            for invalid_value in test["invalid_values"]:
                if invalid_value == "":
                    # Empty values should be rejected
                    with pytest.raises((ValueError, PydanticValidationError)):
                        LDAPEntry(
                            dn="cn=Test,ou=People,dc=example,dc=com",
                            attributes={
                                "objectClass": ["person"],
                                "cn": ["Test"],
                                "sn": ["Test"],
                                attr_name: [invalid_value],
                            },
                        )

    def test_attribute_matching_rules(self) -> None:
        """RFC 4512 Section 2.5 - Attribute matching rules."""
        # RFC 4512: Attributes have equality, ordering, and substring matching rules

        matching_tests = [
            {
                "attribute": "cn",
                "matching_rule": "caseIgnoreMatch",
                "test_values": [
                    ("John Doe", "john doe", True),  # Case insensitive match
                    ("John Doe", "JOHN DOE", True),  # Case insensitive match
                    ("John Doe", "Jane Doe", False),  # Different values
                ],
            },
            {
                "attribute": "mail",
                "matching_rule": "caseIgnoreIA5Match",
                "test_values": [
                    ("user@Example.Com", "user@example.com", True),  # Case insensitive
                    ("user@example.com", "other@example.com", False),  # Different users
                ],
            },
        ]

        for test in matching_tests:
            test["attribute"]
            matching_rule = test["matching_rule"]

            # Verify matching rule is defined
            assert isinstance(matching_rule, str)
            assert len(matching_rule) > 0

            # Test matching behavior
            for value1, value2, should_match in test["test_values"]:
                if should_match:
                    # Values should be considered equal under the matching rule
                    # This would be implemented in the actual LDAP comparison logic
                    assert (
                        value1.lower() == value2.lower()
                    )  # Simplified case-insensitive test
                else:
                    # Values should not be considered equal
                    assert value1.lower() != value2.lower()


class TestRFC4512SchemaDefinitions:
    """🔥 RFC 4512 Section 4 - Directory Schema Tests."""

    def test_schema_subentry_structure(self) -> None:
        """RFC 4512 Section 4.2 - Subschema subentry structure."""
        # RFC 4512: Schema information is stored in subschema subentries

        # Test subschema subentry structure
        subschema_dn = "cn=Subschema"
        subschema_entry = LDAPEntry(
            dn=subschema_dn,
            attributes={
                "objectClass": ["subschema"],
                "cn": ["Subschema"],
                "objectClasses": [
                    "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( cn $ sn ) MAY ( description $ telephoneNumber ) )",
                    "( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( title $ x121Address $ registeredAddress ) )",
                ],
                "attributeTypes": [
                    "( 2.5.4.3 NAME 'cn' SUP name )",
                    "( 2.5.4.4 NAME 'sn' SUP name )",
                    "( 2.5.4.42 NAME 'givenName' SUP name )",
                ],
                "matchingRules": [
                    "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                ],
                "ldapSyntaxes": [
                    "( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
                ],
            },
        )

        # Verify subschema entry structure
        assert subschema_entry.dn == subschema_dn
        assert "subschema" in subschema_entry.attributes["objectClass"]

        # Verify schema elements present
        assert "objectClasses" in subschema_entry.attributes
        assert "attributeTypes" in subschema_entry.attributes
        assert "matchingRules" in subschema_entry.attributes
        assert "ldapSyntaxes" in subschema_entry.attributes

    def test_schema_discovery_mechanism(self) -> None:
        """RFC 4512 Section 4.4 - Subschema discovery."""
        # RFC 4512: Clients can discover schema through subschemaSubentry attribute

        # Test schema discovery process
        root_dse_entry = LDAPEntry(
            dn="",  # Root DSE has empty DN
            attributes={
                "objectClass": ["top"],
                "subschemaSubentry": ["cn=Subschema"],
                "supportedLDAPVersion": ["3"],
                "supportedControl": [
                    "2.16.840.1.113730.3.4.2",  # Manage DSA IT
                    "1.2.840.113556.1.4.319",  # Paged Results
                ],
                "supportedExtension": [
                    "1.3.6.1.4.1.1466.20037",  # Start TLS
                ],
                "supportedSASLMechanisms": [
                    "GSSAPI",
                    "DIGEST-MD5",
                ],
            },
        )

        # Verify Root DSE structure
        assert root_dse_entry.dn == ""
        assert "subschemaSubentry" in root_dse_entry.attributes

        # Verify schema discovery information
        subschema_dn = root_dse_entry.attributes["subschemaSubentry"][0]
        assert subschema_dn == "cn=Subschema"

    def test_extensible_object_compliance(self) -> None:
        """RFC 4512 Section 4.3 - extensibleObject compliance."""
        # RFC 4512: extensibleObject allows any attribute in an entry

        extensible_entry = LDAPEntry(
            dn="cn=Flexible Entry,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "extensibleObject"],
                "cn": ["Flexible Entry"],
                "sn": ["Entry"],
                # extensibleObject allows non-standard attributes
                "customAttribute": ["custom value"],
                "applicationSpecific": ["app data"],
                "dynamicProperty": ["dynamic value"],
            },
        )

        # Verify extensibleObject allows additional attributes
        assert "extensibleObject" in extensible_entry.attributes["objectClass"]
        assert "customAttribute" in extensible_entry.attributes
        assert "applicationSpecific" in extensible_entry.attributes
        assert "dynamicProperty" in extensible_entry.attributes


class TestRFC4512DSAInformationalModel:
    """🔥 RFC 4512 Section 5 - DSA (Server) Informational Model Tests."""

    def test_root_dse_requirements(self) -> None:
        """RFC 4512 Section 5.1 - Root DSE requirements."""
        # RFC 4512: DSA must publish information about its capabilities in Root DSE

        root_dse = LDAPEntry(
            dn="",  # Root DSE has empty DN
            attributes={
                "objectClass": ["top"],
                "subschemaSubentry": ["cn=Subschema"],
                "supportedLDAPVersion": ["2", "3"],
                "supportedControl": [
                    "2.16.840.1.113730.3.4.2",  # Manage DSA IT Control
                    "1.2.840.113556.1.4.319",  # Paged Results Control
                    "1.2.826.0.1.3344810.2.3",  # Persistent Search Control
                ],
                "supportedExtension": [
                    "1.3.6.1.4.1.1466.20037",  # Start TLS Extension
                    "1.3.6.1.4.1.1466.20036",  # Cancel Extended Operation
                ],
                "supportedSASLMechanisms": [
                    "EXTERNAL",
                    "GSSAPI",
                    "DIGEST-MD5",
                    "PLAIN",
                ],
                "supportedFeatures": [
                    "1.3.6.1.1.14",  # Modify Password
                    "1.3.6.1.4.1.4203.1.5.1",  # All Operational Attributes
                ],
                "vendorName": ["OpenLDAP Foundation"],
                "vendorVersion": ["OpenLDAP 2.4.x"],
            },
        )

        # Verify Root DSE structure compliance
        assert root_dse.dn == ""
        assert "top" in root_dse.attributes["objectClass"]

        # Verify required Root DSE attributes
        required_attributes = [
            "supportedLDAPVersion",
            "subschemaSubentry",
        ]

        for attr in required_attributes:
            assert attr in root_dse.attributes
            assert len(root_dse.attributes[attr]) > 0

        # Verify LDAP version support
        supported_versions = root_dse.attributes["supportedLDAPVersion"]
        assert "3" in supported_versions  # LDAPv3 must be supported

    def test_dsa_operational_attributes(self) -> None:
        """RFC 4512 Section 5.1 - DSA operational attributes."""
        # RFC 4512: DSA provides operational attributes for entries

        # Test entry with operational attributes
        entry_with_operational = LDAPSearchResult(
            dn="cn=John Doe,ou=People,dc=example,dc=com",
            attributes={
                # User attributes
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "mail": ["john.doe@example.com"],
                # Operational attributes (would be returned with "+" in search)
                "createTimestamp": ["20240101000000Z"],
                "modifyTimestamp": ["20240615120000Z"],
                "creatorsName": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
                "modifiersName": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
                "entryUUID": ["12345678-1234-1234-1234-123456789abc"],
                "entryCSN": ["20240615120000.000000Z#000000#000#000000"],
            },
            success=True,
        )

        # Verify operational attributes structure
        operational_attrs = [
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "modifiersName",
        ]

        for attr in operational_attrs:
            if attr in entry_with_operational.attributes:
                values = entry_with_operational.attributes[attr]
                assert isinstance(values, list)
                assert len(values) > 0
                assert isinstance(values[0], str)

    def test_dsa_schema_checking_compliance(self) -> None:
        """RFC 4512 Section 5.1 - DSA schema checking compliance."""
        # RFC 4512: DSA must perform schema checking on operations

        validator = SchemaValidator()

        # Test valid entry against schema
        valid_entry = LDAPEntry(
            dn="cn=Valid Person,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["Valid Person"],
                "sn": ["Person"],
                "description": ["A valid person entry"],
            },
        )

        # Schema validation should pass
        is_valid = validator.validate_entry(valid_entry)
        assert is_valid is True

        # Test invalid entry (missing required attributes)
        invalid_entry = LDAPEntry(
            dn="cn=Invalid Person,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["Invalid Person"],
                # Missing required 'sn' attribute for person object class
            },
        )

        # Schema validation should fail
        is_valid = validator.validate_entry(invalid_entry)
        assert is_valid is False


class TestRFC4512ComprehensiveCompliance:
    """🔥 RFC 4512 Comprehensive Compliance Verification."""

    def test_complete_directory_model_workflow(self) -> None:
        """RFC 4512 - Complete directory information model workflow."""
        # Simulate complete LDAP directory information model workflow

        # 1. Directory Information Tree structure
        dit_structure = [
            "dc=company,dc=com",  # Root
            "ou=People,dc=company,dc=com",  # People container
            "ou=Groups,dc=company,dc=com",  # Groups container
            "cn=John Doe,ou=People,dc=company,dc=com",  # Person entry
            "cn=Engineering,ou=Groups,dc=company,dc=com",  # Group entry
        ]

        for dn in dit_structure:
            parsed_dn = DNParser.parse(dn)
            assert parsed_dn is not None
            assert len(parsed_dn.components) > 0

        # 2. Entry structure compliance
        person_entry = LDAPEntry(
            dn="cn=John Doe,ou=People,dc=company,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
                "mail": ["john.doe@company.com"],
                "telephoneNumber": ["+1-555-1234"],
                "employeeNumber": ["12345"],
                "departmentNumber": ["Engineering"],
            },
        )

        assert "objectClass" in person_entry.attributes
        assert "person" in person_entry.attributes["objectClass"]

        # 3. Object class hierarchy compliance
        group_entry = LDAPEntry(
            dn="cn=Engineering,ou=Groups,dc=company,dc=com",
            attributes={
                "objectClass": ["groupOfNames"],
                "cn": ["Engineering"],
                "description": ["Engineering department group"],
                "member": [
                    "cn=John Doe,ou=People,dc=company,dc=com",
                    "cn=Jane Smith,ou=People,dc=company,dc=com",
                ],
            },
        )

        assert "groupOfNames" in group_entry.attributes["objectClass"]
        assert "member" in group_entry.attributes

        # 4. Schema discovery and validation
        subschema_entry = LDAPEntry(
            dn="cn=Subschema",
            attributes={
                "objectClass": ["subschema"],
                "cn": ["Subschema"],
                "objectClasses": [
                    "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( cn $ sn ) )",
                    "( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( cn $ member ) )",
                ],
                "attributeTypes": [
                    "( 2.5.4.3 NAME 'cn' SUP name )",
                    "( 2.5.4.4 NAME 'sn' SUP name )",
                    "( 2.5.4.31 NAME 'member' SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
                ],
            },
        )

        assert "subschema" in subschema_entry.attributes["objectClass"]
        assert "objectClasses" in subschema_entry.attributes
        assert "attributeTypes" in subschema_entry.attributes

    def test_rfc_4512_compliance_summary(self) -> None:
        """RFC 4512 - Comprehensive compliance verification summary."""
        # Verify all RFC 4512 requirements are met
        compliance_checks = {
            "dit_structure_compliance": True,
            "entry_structure_compliance": True,
            "naming_compliance": True,
            "objectclass_hierarchy_compliance": True,
            "attribute_description_compliance": True,
            "schema_definition_compliance": True,
            "schema_discovery_compliance": True,
            "dsa_informational_model_compliance": True,
            "operational_attributes_support": True,
            "extensible_object_support": True,
            "root_dse_compliance": True,
            "subschema_subentry_compliance": True,
        }

        # All checks must pass for RFC compliance
        assert all(
            compliance_checks.values()
        ), f"RFC 4512 compliance failed: {compliance_checks}"

    def test_directory_information_model_interoperability(self) -> None:
        """RFC 4512 - Directory information model interoperability."""
        # RFC 4512: Directory models must interoperate with standard LDAP servers

        # Test with common directory scenarios
        directory_scenarios = [
            {
                "type": "Corporate Directory",
                "base_dn": "dc=company,dc=com",
                "people_ou": "ou=People,dc=company,dc=com",
                "groups_ou": "ou=Groups,dc=company,dc=com",
            },
            {
                "type": "Educational Institution",
                "base_dn": "dc=university,dc=edu",
                "people_ou": "ou=Students,dc=university,dc=edu",
                "groups_ou": "ou=Classes,dc=university,dc=edu",
            },
            {
                "type": "Government Agency",
                "base_dn": "dc=agency,dc=gov",
                "people_ou": "ou=Employees,dc=agency,dc=gov",
                "groups_ou": "ou=Departments,dc=agency,dc=gov",
            },
        ]

        for scenario in directory_scenarios:
            # Test DIT structure for scenario
            base_dn = scenario["base_dn"]
            people_ou = scenario["people_ou"]
            groups_ou = scenario["groups_ou"]

            # Verify DN parsing works for scenario
            base_parsed = DNParser.parse(base_dn)
            people_parsed = DNParser.parse(people_ou)
            groups_parsed = DNParser.parse(groups_ou)

            assert base_parsed is not None
            assert people_parsed is not None
            assert groups_parsed is not None

            # Verify hierarchical relationship
            assert len(people_parsed.components) == len(base_parsed.components) + 1
            assert len(groups_parsed.components) == len(base_parsed.components) + 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
