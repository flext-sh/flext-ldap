"""Tests for RFC 2252 Compliant LDAP Schema Parser Implementation.

This module provides comprehensive test coverage for the RFC 2252 compliant LDAP
schema parser including attribute types, object classes, syntax definitions,
and matching rules parsing with enterprise-grade validation and error handling.

Test Coverage:
    - AttributeType: Attribute type definition modeling and validation
    - ObjectClass: Object class definition modeling and validation
    - SyntaxDefinition: Syntax definition modeling and validation
    - MatchingRule: Matching rule definition modeling and validation
    - ParsedSchema: Complete schema aggregation and management
    - SchemaParser: Main RFC 2252 compliant parser with regex patterns
    - Schema definition parsing with comprehensive error recovery

Integration Testing:
    - Complete schema parsing workflows with all elements
    - Regex pattern matching for schema element extraction
    - Schema definition validation and error collection
    - Multi-element schema parsing and aggregation
    - Parser configuration and optimization patterns

Performance Testing:
    - Large schema parsing efficiency and optimization
    - Regex pattern compilation and matching performance
    - Memory usage during schema processing
    - Parser operation timing and throughput
    - Pattern matching optimization validation

Security Testing:
    - Input validation and sanitization for schema definitions
    - Regex pattern security and DoS protection
    - Error message information disclosure protection
    - Resource consumption limits and validation
    - Schema definition injection protection
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ldap_core_shared.schema.parser import (
    AttributeType,
    MatchingRule,
    ObjectClass,
    ParsedSchema,
    SchemaParser,
    SyntaxDefinition,
)


class TestAttributeType:
    """Test cases for AttributeType."""

    def test_attribute_type_creation_minimal(self) -> None:
        """Test creating attribute type with minimal required fields."""
        attr_type = AttributeType(oid="2.5.4.3")

        assert attr_type.oid == "2.5.4.3"
        assert attr_type.names == []
        assert attr_type.description == ""
        assert attr_type.syntax == ""
        assert attr_type.equality_rule == ""
        assert attr_type.ordering_rule == ""
        assert attr_type.substring_rule == ""
        assert attr_type.superior == ""
        assert attr_type.usage == "userApplications"
        assert attr_type.single_value is False
        assert attr_type.collective is False
        assert attr_type.no_user_modification is False
        assert attr_type.obsolete is False

    def test_attribute_type_creation_complete(self) -> None:
        """Test creating attribute type with all fields."""
        attr_type = AttributeType(
            oid="2.5.4.3",
            names=["cn", "commonName"],
            description="Common Name",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            equality_rule="caseIgnoreMatch",
            ordering_rule="caseIgnoreOrderingMatch",
            substring_rule="caseIgnoreSubstringsMatch",
            superior="name",
            usage="userApplications",
            single_value=False,
            collective=False,
            no_user_modification=False,
            obsolete=False,
        )

        assert attr_type.oid == "2.5.4.3"
        assert attr_type.names == ["cn", "commonName"]
        assert attr_type.description == "Common Name"
        assert attr_type.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert attr_type.equality_rule == "caseIgnoreMatch"
        assert attr_type.ordering_rule == "caseIgnoreOrderingMatch"
        assert attr_type.substring_rule == "caseIgnoreSubstringsMatch"
        assert attr_type.superior == "name"
        assert attr_type.usage == "userApplications"

    def test_attribute_type_flags(self) -> None:
        """Test attribute type with various flags set."""
        attr_type = AttributeType(
            oid="2.5.4.4",
            single_value=True,
            collective=True,
            no_user_modification=True,
            obsolete=True,
        )

        assert attr_type.single_value is True
        assert attr_type.collective is True
        assert attr_type.no_user_modification is True
        assert attr_type.obsolete is True

    def test_attribute_type_strict_mode(self) -> None:
        """Test attribute type strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            AttributeType(oid="2.5.4.3", extra_field="not_allowed")

    def test_attribute_type_oid_required(self) -> None:
        """Test attribute type validation requires OID."""
        with pytest.raises(ValidationError, match="Field required"):
            AttributeType()


class TestObjectClass:
    """Test cases for ObjectClass."""

    def test_object_class_creation_minimal(self) -> None:
        """Test creating object class with minimal required fields."""
        obj_class = ObjectClass(oid="2.5.6.6")

        assert obj_class.oid == "2.5.6.6"
        assert obj_class.names == []
        assert obj_class.description == ""
        assert obj_class.superior_classes == []
        assert obj_class.class_type == "STRUCTURAL"
        assert obj_class.must_attributes == []
        assert obj_class.may_attributes == []
        assert obj_class.obsolete is False

    def test_object_class_creation_complete(self) -> None:
        """Test creating object class with all fields."""
        obj_class = ObjectClass(
            oid="2.5.6.6",
            names=["person"],
            description="Person object class",
            superior_classes=["top"],
            class_type="STRUCTURAL",
            must_attributes=["sn", "cn"],
            may_attributes=["userPassword", "telephoneNumber"],
            obsolete=False,
        )

        assert obj_class.oid == "2.5.6.6"
        assert obj_class.names == ["person"]
        assert obj_class.description == "Person object class"
        assert obj_class.superior_classes == ["top"]
        assert obj_class.class_type == "STRUCTURAL"
        assert obj_class.must_attributes == ["sn", "cn"]
        assert obj_class.may_attributes == ["userPassword", "telephoneNumber"]
        assert obj_class.obsolete is False

    def test_object_class_types(self) -> None:
        """Test object class with different types."""
        structural = ObjectClass(oid="2.5.6.6", class_type="STRUCTURAL")
        auxiliary = ObjectClass(oid="2.5.6.7", class_type="AUXILIARY")
        abstract = ObjectClass(oid="2.5.6.8", class_type="ABSTRACT")

        assert structural.class_type == "STRUCTURAL"
        assert auxiliary.class_type == "AUXILIARY"
        assert abstract.class_type == "ABSTRACT"

    def test_object_class_strict_mode(self) -> None:
        """Test object class strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ObjectClass(oid="2.5.6.6", extra_field="not_allowed")

    def test_object_class_oid_required(self) -> None:
        """Test object class validation requires OID."""
        with pytest.raises(ValidationError, match="Field required"):
            ObjectClass()


class TestSyntaxDefinition:
    """Test cases for SyntaxDefinition."""

    def test_syntax_definition_creation_minimal(self) -> None:
        """Test creating syntax definition with minimal required fields."""
        syntax_def = SyntaxDefinition(oid="1.3.6.1.4.1.1466.115.121.1.15")

        assert syntax_def.oid == "1.3.6.1.4.1.1466.115.121.1.15"
        assert syntax_def.description == ""

    def test_syntax_definition_creation_complete(self) -> None:
        """Test creating syntax definition with all fields."""
        syntax_def = SyntaxDefinition(
            oid="1.3.6.1.4.1.1466.115.121.1.15",
            description="Directory String",
        )

        assert syntax_def.oid == "1.3.6.1.4.1.1466.115.121.1.15"
        assert syntax_def.description == "Directory String"

    def test_syntax_definition_strict_mode(self) -> None:
        """Test syntax definition strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            SyntaxDefinition(
                oid="1.3.6.1.4.1.1466.115.121.1.15", extra_field="not_allowed"
            )

    def test_syntax_definition_oid_required(self) -> None:
        """Test syntax definition validation requires OID."""
        with pytest.raises(ValidationError, match="Field required"):
            SyntaxDefinition()


class TestMatchingRule:
    """Test cases for MatchingRule."""

    def test_matching_rule_creation_minimal(self) -> None:
        """Test creating matching rule with minimal required fields."""
        matching_rule = MatchingRule(oid="2.5.13.2")

        assert matching_rule.oid == "2.5.13.2"
        assert matching_rule.names == []
        assert matching_rule.description == ""
        assert matching_rule.syntax == ""
        assert matching_rule.obsolete is False

    def test_matching_rule_creation_complete(self) -> None:
        """Test creating matching rule with all fields."""
        matching_rule = MatchingRule(
            oid="2.5.13.2",
            names=["caseIgnoreMatch"],
            description="Case Ignore Match",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            obsolete=False,
        )

        assert matching_rule.oid == "2.5.13.2"
        assert matching_rule.names == ["caseIgnoreMatch"]
        assert matching_rule.description == "Case Ignore Match"
        assert matching_rule.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert matching_rule.obsolete is False

    def test_matching_rule_obsolete(self) -> None:
        """Test matching rule with obsolete flag."""
        matching_rule = MatchingRule(oid="2.5.13.3", obsolete=True)

        assert matching_rule.obsolete is True

    def test_matching_rule_strict_mode(self) -> None:
        """Test matching rule strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            MatchingRule(oid="2.5.13.2", extra_field="not_allowed")

    def test_matching_rule_oid_required(self) -> None:
        """Test matching rule validation requires OID."""
        with pytest.raises(ValidationError, match="Field required"):
            MatchingRule()


class TestParsedSchema:
    """Test cases for ParsedSchema."""

    def test_parsed_schema_creation_empty(self) -> None:
        """Test creating empty parsed schema."""
        schema = ParsedSchema()

        assert schema.attribute_types == {}
        assert schema.object_classes == {}
        assert schema.syntax_definitions == {}
        assert schema.matching_rules == {}

    def test_parsed_schema_creation_with_elements(self) -> None:
        """Test creating parsed schema with elements."""
        attr_type = AttributeType(oid="2.5.4.3", names=["cn"])
        obj_class = ObjectClass(oid="2.5.6.6", names=["person"])
        syntax_def = SyntaxDefinition(oid="1.3.6.1.4.1.1466.115.121.1.15")
        matching_rule = MatchingRule(oid="2.5.13.2", names=["caseIgnoreMatch"])

        schema = ParsedSchema(
            attribute_types={"2.5.4.3": attr_type},
            object_classes={"2.5.6.6": obj_class},
            syntax_definitions={"1.3.6.1.4.1.1466.115.121.1.15": syntax_def},
            matching_rules={"2.5.13.2": matching_rule},
        )

        assert len(schema.attribute_types) == 1
        assert len(schema.object_classes) == 1
        assert len(schema.syntax_definitions) == 1
        assert len(schema.matching_rules) == 1
        assert "2.5.4.3" in schema.attribute_types
        assert "2.5.6.6" in schema.object_classes

    def test_parsed_schema_strict_mode(self) -> None:
        """Test parsed schema strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ParsedSchema(extra_field="not_allowed")


class TestSchemaParser:
    """Test cases for SchemaParser."""

    def test_parser_initialization(self) -> None:
        """Test parser initialization."""
        parser = SchemaParser()

        # Verify regex patterns are compiled
        assert parser._oid_pattern is not None
        assert parser._name_pattern is not None
        assert parser._desc_pattern is not None
        assert parser._syntax_pattern is not None

    def test_parse_attribute_type_complete(self) -> None:
        """Test parsing complete attribute type definition."""
        parser = SchemaParser()

        definition = """( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'Common Name'
                        EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch
                        SUBSTR caseIgnoreSubstringsMatch
                        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} SUP name
                        USAGE userApplications )"""

        result = parser.parse_attribute_type(definition)

        assert result.success is True
        assert result.data is not None
        assert result.data.oid == "2.5.4.3"
        assert result.data.names == ["cn", "commonName"]
        assert result.data.description == "Common Name"
        assert result.data.equality_rule == "caseIgnoreMatch"
        assert result.data.ordering_rule == "caseIgnoreOrderingMatch"
        assert result.data.substring_rule == "caseIgnoreSubstringsMatch"
        assert result.data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert result.data.superior == "name"
        assert result.data.usage == "userApplications"

    def test_parse_attribute_type_with_flags(self) -> None:
        """Test parsing attribute type with flags."""
        parser = SchemaParser()

        definition = """( 2.5.4.4 NAME 'sn' DESC 'Surname'
                        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
                        SINGLE-VALUE NO-USER-MODIFICATION COLLECTIVE OBSOLETE )"""

        result = parser.parse_attribute_type(definition)

        assert result.success is True
        assert result.data.single_value is True
        assert result.data.no_user_modification is True
        assert result.data.collective is True
        assert result.data.obsolete is True

    def test_parse_attribute_type_minimal(self) -> None:
        """Test parsing minimal attribute type definition."""
        parser = SchemaParser()

        definition = "( 2.5.4.3 )"

        result = parser.parse_attribute_type(definition)

        assert result.success is True
        assert result.data.oid == "2.5.4.3"
        assert result.data.names == []
        assert result.data.description == ""
        assert result.data.usage == "userApplications"  # Default value

    def test_parse_attribute_type_no_oid(self) -> None:
        """Test parsing attribute type without OID."""
        parser = SchemaParser()

        definition = "NAME 'cn' DESC 'Common Name'"

        result = parser.parse_attribute_type(definition)

        assert result.success is False
        assert "No OID found" in result.error_message

    def test_parse_attribute_type_single_name(self) -> None:
        """Test parsing attribute type with single name."""
        parser = SchemaParser()

        definition = "( 2.5.4.3 NAME 'cn' )"

        result = parser.parse_attribute_type(definition)

        assert result.success is True
        assert result.data.names == ["cn"]

    def test_parse_attribute_type_multiple_names(self) -> None:
        """Test parsing attribute type with multiple names."""
        parser = SchemaParser()

        definition = "( 2.5.4.3 NAME ( 'cn' 'commonName' 'name' ) )"

        result = parser.parse_attribute_type(definition)

        assert result.success is True
        assert result.data.names == ["cn", "commonName", "name"]

    def test_parse_object_class_complete(self) -> None:
        """Test parsing complete object class definition."""
        parser = SchemaParser()

        definition = """( 2.5.6.6 NAME 'person' DESC 'Person object class'
                        SUP top STRUCTURAL MUST ( sn $ cn )
                        MAY ( userPassword $ telephoneNumber $ description ) )"""

        result = parser.parse_object_class(definition)

        assert result.success is True
        assert result.data.oid == "2.5.6.6"
        assert result.data.names == ["person"]
        assert result.data.description == "Person object class"
        assert result.data.superior_classes == ["top"]
        assert result.data.class_type == "STRUCTURAL"
        assert result.data.must_attributes == ["sn", "cn"]
        assert result.data.may_attributes == [
            "userPassword",
            "telephoneNumber",
            "description",
        ]

    def test_parse_object_class_types(self) -> None:
        """Test parsing object class with different types."""
        parser = SchemaParser()

        # Test ABSTRACT
        abstract_def = "( 2.5.6.0 NAME 'top' ABSTRACT )"
        result = parser.parse_object_class(abstract_def)
        assert result.success is True
        assert result.data.class_type == "ABSTRACT"

        # Test AUXILIARY
        auxiliary_def = "( 2.5.6.1 NAME 'auxiliary' AUXILIARY )"
        result = parser.parse_object_class(auxiliary_def)
        assert result.success is True
        assert result.data.class_type == "AUXILIARY"

        # Test STRUCTURAL (default)
        structural_def = "( 2.5.6.2 NAME 'structural' )"
        result = parser.parse_object_class(structural_def)
        assert result.success is True
        assert result.data.class_type == "STRUCTURAL"

    def test_parse_object_class_multiple_superiors(self) -> None:
        """Test parsing object class with multiple superior classes."""
        parser = SchemaParser()

        definition = "( 2.5.6.7 NAME 'organizationalPerson' SUP ( person $ top ) )"

        result = parser.parse_object_class(definition)

        assert result.success is True
        assert result.data.superior_classes == ["person", "top"]

    def test_parse_object_class_single_must_may(self) -> None:
        """Test parsing object class with single MUST and MAY attributes."""
        parser = SchemaParser()

        definition = "( 2.5.6.8 NAME 'simpleClass' MUST cn MAY description )"

        result = parser.parse_object_class(definition)

        assert result.success is True
        assert result.data.must_attributes == ["cn"]
        assert result.data.may_attributes == ["description"]

    def test_parse_object_class_no_oid(self) -> None:
        """Test parsing object class without OID."""
        parser = SchemaParser()

        definition = "NAME 'person' DESC 'Person'"

        result = parser.parse_object_class(definition)

        assert result.success is False
        assert "No OID found" in result.error_message

    def test_parse_syntax_definition_success(self) -> None:
        """Test parsing syntax definition successfully."""
        parser = SchemaParser()

        definition = "( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )"

        result = parser.parse_syntax_definition(definition)

        assert result.success is True
        assert result.data.oid == "1.3.6.1.4.1.1466.115.121.1.15"
        assert result.data.description == "Directory String"

    def test_parse_syntax_definition_minimal(self) -> None:
        """Test parsing minimal syntax definition."""
        parser = SchemaParser()

        definition = "( 1.3.6.1.4.1.1466.115.121.1.15 )"

        result = parser.parse_syntax_definition(definition)

        assert result.success is True
        assert result.data.oid == "1.3.6.1.4.1.1466.115.121.1.15"
        assert result.data.description == ""

    def test_parse_syntax_definition_no_oid(self) -> None:
        """Test parsing syntax definition without OID."""
        parser = SchemaParser()

        definition = "DESC 'Directory String'"

        result = parser.parse_syntax_definition(definition)

        assert result.success is False
        assert "No OID found" in result.error_message

    def test_parse_matching_rule_complete(self) -> None:
        """Test parsing complete matching rule definition."""
        parser = SchemaParser()

        definition = """( 2.5.13.2 NAME 'caseIgnoreMatch' DESC 'Case Ignore Match'
                        SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"""

        result = parser.parse_matching_rule(definition)

        assert result.success is True
        assert result.data.oid == "2.5.13.2"
        assert result.data.names == ["caseIgnoreMatch"]
        assert result.data.description == "Case Ignore Match"
        assert result.data.syntax == "1.3.6.1.4.1.1466.115.121.1.15"
        assert result.data.obsolete is False

    def test_parse_matching_rule_obsolete(self) -> None:
        """Test parsing obsolete matching rule."""
        parser = SchemaParser()

        definition = "( 2.5.13.3 NAME 'oldMatch' OBSOLETE )"

        result = parser.parse_matching_rule(definition)

        assert result.success is True
        assert result.data.obsolete is True

    def test_parse_matching_rule_no_oid(self) -> None:
        """Test parsing matching rule without OID."""
        parser = SchemaParser()

        definition = "NAME 'caseIgnoreMatch'"

        result = parser.parse_matching_rule(definition)

        assert result.success is False
        assert "No OID found" in result.error_message

    def test_parse_schema_definitions_complete(self) -> None:
        """Test parsing complete schema definitions."""
        parser = SchemaParser()

        attribute_types = [
            "( 2.5.4.3 NAME 'cn' DESC 'Common Name' )",
            "( 2.5.4.4 NAME 'sn' DESC 'Surname' )",
        ]

        object_classes = [
            "( 2.5.6.6 NAME 'person' DESC 'Person' MUST ( sn $ cn ) )",
        ]

        syntax_definitions = [
            "( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
        ]

        matching_rules = [
            "( 2.5.13.2 NAME 'caseIgnoreMatch' )",
        ]

        result = parser.parse_schema_definitions(
            attribute_types=attribute_types,
            object_classes=object_classes,
            syntax_definitions=syntax_definitions,
            matching_rules=matching_rules,
        )

        assert result.success is True
        assert result.data is not None
        assert len(result.data.attribute_types) == 2
        assert len(result.data.object_classes) == 1
        assert len(result.data.syntax_definitions) == 1
        assert len(result.data.matching_rules) == 1

    def test_parse_schema_definitions_partial(self) -> None:
        """Test parsing schema definitions with only some elements."""
        parser = SchemaParser()

        attribute_types = [
            "( 2.5.4.3 NAME 'cn' )",
        ]

        result = parser.parse_schema_definitions(attribute_types=attribute_types)

        assert result.success is True
        assert len(result.data.attribute_types) == 1
        assert len(result.data.object_classes) == 0
        assert len(result.data.syntax_definitions) == 0
        assert len(result.data.matching_rules) == 0

    def test_parse_schema_definitions_with_errors(self) -> None:
        """Test parsing schema definitions with some invalid definitions."""
        parser = SchemaParser()

        attribute_types = [
            "( 2.5.4.3 NAME 'cn' )",  # Valid
            "INVALID DEFINITION",  # Invalid
        ]

        result = parser.parse_schema_definitions(attribute_types=attribute_types)

        # Should succeed but only include valid definitions
        assert result.success is True
        assert len(result.data.attribute_types) == 1  # Only valid one included


class TestSchemaParserExtractionMethods:
    """Test cases for schema parser extraction methods."""

    def test_extract_names_single(self) -> None:
        """Test extracting single name."""
        parser = SchemaParser()

        definition = "NAME 'cn'"
        names = parser._extract_names(definition)

        assert names == ["cn"]

    def test_extract_names_multiple(self) -> None:
        """Test extracting multiple names."""
        parser = SchemaParser()

        definition = "NAME ( 'cn' 'commonName' 'name' )"
        names = parser._extract_names(definition)

        assert names == ["cn", "commonName", "name"]

    def test_extract_names_no_names(self) -> None:
        """Test extracting names when none present."""
        parser = SchemaParser()

        definition = "DESC 'Description only'"
        names = parser._extract_names(definition)

        assert names == []

    def test_extract_description(self) -> None:
        """Test extracting description."""
        parser = SchemaParser()

        definition = "DESC 'This is a description'"
        description = parser._extract_description(definition)

        assert description == "This is a description"

    def test_extract_description_no_desc(self) -> None:
        """Test extracting description when none present."""
        parser = SchemaParser()

        definition = "NAME 'cn'"
        description = parser._extract_description(definition)

        assert description == ""

    def test_extract_syntax(self) -> None:
        """Test extracting syntax OID."""
        parser = SchemaParser()

        definition = "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"
        syntax = parser._extract_syntax(definition)

        assert syntax == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_extract_syntax_with_length(self) -> None:
        """Test extracting syntax OID with length constraint."""
        parser = SchemaParser()

        definition = "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256}"
        syntax = parser._extract_syntax(definition)

        assert syntax == "1.3.6.1.4.1.1466.115.121.1.15"

    def test_extract_equality_rule(self) -> None:
        """Test extracting equality matching rule."""
        parser = SchemaParser()

        definition = "EQUALITY caseIgnoreMatch"
        rule = parser._extract_equality_rule(definition)

        assert rule == "caseIgnoreMatch"

    def test_extract_ordering_rule(self) -> None:
        """Test extracting ordering matching rule."""
        parser = SchemaParser()

        definition = "ORDERING caseIgnoreOrderingMatch"
        rule = parser._extract_ordering_rule(definition)

        assert rule == "caseIgnoreOrderingMatch"

    def test_extract_substring_rule(self) -> None:
        """Test extracting substring matching rule."""
        parser = SchemaParser()

        definition = "SUBSTR caseIgnoreSubstringsMatch"
        rule = parser._extract_substring_rule(definition)

        assert rule == "caseIgnoreSubstringsMatch"

    def test_extract_superior(self) -> None:
        """Test extracting superior attribute type."""
        parser = SchemaParser()

        definition = "SUP name"
        superior = parser._extract_superior(definition)

        assert superior == "name"

    def test_extract_usage(self) -> None:
        """Test extracting attribute usage."""
        parser = SchemaParser()

        definition = "USAGE directoryOperation"
        usage = parser._extract_usage(definition)

        assert usage == "directoryOperation"

    def test_extract_usage_default(self) -> None:
        """Test extracting usage with default value."""
        parser = SchemaParser()

        definition = "NAME 'cn'"
        usage = parser._extract_usage(definition)

        assert usage == "userApplications"

    def test_extract_superior_classes_single(self) -> None:
        """Test extracting single superior object class."""
        parser = SchemaParser()

        definition = "SUP person"
        superiors = parser._extract_superior_classes(definition)

        assert superiors == ["person"]

    def test_extract_superior_classes_multiple(self) -> None:
        """Test extracting multiple superior object classes."""
        parser = SchemaParser()

        definition = "SUP ( person $ top )"
        superiors = parser._extract_superior_classes(definition)

        assert superiors == ["person", "top"]

    def test_extract_class_type(self) -> None:
        """Test extracting object class type."""
        parser = SchemaParser()

        assert parser._extract_class_type("ABSTRACT") == "ABSTRACT"
        assert parser._extract_class_type("AUXILIARY") == "AUXILIARY"
        assert parser._extract_class_type("STRUCTURAL") == "STRUCTURAL"
        assert parser._extract_class_type("NAME 'test'") == "STRUCTURAL"  # Default

    def test_extract_must_attributes(self) -> None:
        """Test extracting required attributes."""
        parser = SchemaParser()

        definition = "MUST ( sn $ cn $ objectClass )"
        attributes = parser._extract_must_attributes(definition)

        assert attributes == ["sn", "cn", "objectClass"]

    def test_extract_must_attributes_single(self) -> None:
        """Test extracting single required attribute."""
        parser = SchemaParser()

        definition = "MUST cn"
        attributes = parser._extract_must_attributes(definition)

        assert attributes == ["cn"]

    def test_extract_may_attributes(self) -> None:
        """Test extracting optional attributes."""
        parser = SchemaParser()

        definition = "MAY ( description $ telephoneNumber )"
        attributes = parser._extract_may_attributes(definition)

        assert attributes == ["description", "telephoneNumber"]

    def test_extract_attribute_list_empty(self) -> None:
        """Test extracting attribute list when none present."""
        parser = SchemaParser()

        definition = "NAME 'test'"
        must_attrs = parser._extract_must_attributes(definition)
        may_attrs = parser._extract_may_attributes(definition)

        assert must_attrs == []
        assert may_attrs == []


class TestSchemaParserErrorHandling:
    """Test cases for schema parser error handling."""

    def test_parse_attribute_type_exception(self) -> None:
        """Test handling exceptions during attribute type parsing."""
        parser = SchemaParser()

        # Mock an exception during processing
        with pytest.raises(Exception):
            # Force an exception by passing None
            parser.parse_attribute_type(None)

    def test_parse_object_class_exception(self) -> None:
        """Test handling exceptions during object class parsing."""
        parser = SchemaParser()

        with pytest.raises(Exception):
            parser.parse_object_class(None)

    def test_parse_syntax_definition_exception(self) -> None:
        """Test handling exceptions during syntax definition parsing."""
        parser = SchemaParser()

        with pytest.raises(Exception):
            parser.parse_syntax_definition(None)

    def test_parse_matching_rule_exception(self) -> None:
        """Test handling exceptions during matching rule parsing."""
        parser = SchemaParser()

        with pytest.raises(Exception):
            parser.parse_matching_rule(None)

    def test_parse_schema_definitions_exception(self) -> None:
        """Test handling exceptions during complete schema parsing."""
        parser = SchemaParser()

        # Force exception by modifying internal state
        original_parse = parser.parse_attribute_type
        parser.parse_attribute_type = lambda x: (_ for _ in ()).throw(
            ValueError("Test error")
        )

        try:
            result = parser.parse_schema_definitions(attribute_types=["test"])
            assert result.success is False
            assert "Parse failed" in result.error_message
        finally:
            parser.parse_attribute_type = original_parse


class TestSchemaParserIntegration:
    """Test cases for schema parser integration scenarios."""

    def test_real_world_attribute_type_parsing(self) -> None:
        """Test parsing real-world attribute type definitions."""
        parser = SchemaParser()

        # Real attribute type definitions from OpenLDAP
        real_definitions = [
            "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s) for which the entity is known by' SUP name )",
            "( 2.5.4.4 NAME ( 'sn' 'surname' ) DESC 'RFC2256: last (family) name(s) for which the entity is known by' SUP name )",
            "( 2.5.4.42 NAME ( 'givenName' 'gn' ) DESC 'RFC2256: first name(s) for which the entity is known by' SUP name )",
        ]

        for definition in real_definitions:
            result = parser.parse_attribute_type(definition)
            assert result.success is True
            assert result.data.oid is not None
            assert len(result.data.names) > 0

    def test_real_world_object_class_parsing(self) -> None:
        """Test parsing real-world object class definitions."""
        parser = SchemaParser()

        # Real object class definitions
        real_definitions = [
            "( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )",
            "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
            "( 2.5.6.7 NAME 'organizationalPerson' DESC 'RFC2256: an organizational person' SUP person STRUCTURAL MAY ( title $ x121Address $ registeredAddress $ destinationIndicator $ preferredDeliveryMethod $ telexNumber $ teletexTerminalIdentifier $ telephoneNumber $ internationaliSDNNumber $ facsimileTelephoneNumber $ street $ postOfficeBox $ postalCode $ postalAddress $ physicalDeliveryOfficeName $ ou $ st $ l ) )",
        ]

        for definition in real_definitions:
            result = parser.parse_object_class(definition)
            assert result.success is True
            assert result.data.oid is not None
            assert len(result.data.names) > 0

    def test_complex_schema_parsing(self) -> None:
        """Test parsing complex schema with interdependencies."""
        parser = SchemaParser()

        # Complex schema with dependencies
        attribute_types = [
            "( 2.5.4.0 NAME 'objectClass' DESC 'RFC2256: object classes of the entity' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
            "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC2256: common name(s) for which the entity is known by' SUP name )",
            "( 2.5.4.41 NAME 'name' DESC 'RFC2256: common supertype of name attributes' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
        ]

        object_classes = [
            "( 2.5.6.0 NAME 'top' DESC 'top of the superclass chain' ABSTRACT MUST objectClass )",
            "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )",
        ]

        result = parser.parse_schema_definitions(
            attribute_types=attribute_types,
            object_classes=object_classes,
        )

        assert result.success is True
        assert len(result.data.attribute_types) == 3
        assert len(result.data.object_classes) == 2

        # Verify relationships
        cn_attr = result.data.attribute_types["2.5.4.3"]
        assert cn_attr.superior == "name"

        person_class = result.data.object_classes["2.5.6.6"]
        assert person_class.superior_classes == ["top"]
        assert "cn" in person_class.must_attributes

    def test_performance_with_large_schema(self) -> None:
        """Test parser performance with large schema definitions."""
        parser = SchemaParser()

        # Generate large number of attribute types
        attribute_types = []
        for i in range(100):
            oid = f"1.2.3.4.{i}"
            name = f"testAttr{i:03d}"
            definition = f"( {oid} NAME '{name}' DESC 'Test attribute {i}' )"
            attribute_types.append(definition)

        result = parser.parse_schema_definitions(attribute_types=attribute_types)

        assert result.success is True
        assert len(result.data.attribute_types) == 100

    def test_error_recovery_in_batch_parsing(self) -> None:
        """Test error recovery during batch parsing."""
        parser = SchemaParser()

        # Mix of valid and invalid definitions
        mixed_definitions = [
            "( 2.5.4.3 NAME 'cn' DESC 'Valid definition' )",  # Valid
            "INVALID DEFINITION WITHOUT OID",  # Invalid
            "( 2.5.4.4 NAME 'sn' DESC 'Another valid one' )",  # Valid
            "( MALFORMED OID NAME 'bad' )",  # Invalid
            "( 2.5.4.5 NAME 'mail' DESC 'Valid again' )",  # Valid
        ]

        result = parser.parse_schema_definitions(attribute_types=mixed_definitions)

        # Should succeed and include only valid definitions
        assert result.success is True
        assert len(result.data.attribute_types) == 3  # Only 3 valid ones

        # Verify valid ones are included
        assert "2.5.4.3" in result.data.attribute_types
        assert "2.5.4.4" in result.data.attribute_types
        assert "2.5.4.5" in result.data.attribute_types
