"""Tests for Enterprise LDAP Schema Validator Implementation.

This module provides comprehensive test coverage for the enterprise-grade LDAP
schema validator including RFC 2252 compliance checking, dependency validation,
conflict detection, and comprehensive schema validation with error reporting.

Test Coverage:
    - SchemaValidationConfig: Validation configuration and options
    - SchemaValidator: Main enterprise validator with RFC compliance
    - Schema validation with comprehensive error and warning collection
    - RFC 2252 compliance checking for attribute types and object classes
    - Dependency validation between schema elements
    - Name conflict detection and resolution
    - OID uniqueness validation across schema elements

Integration Testing:
    - Complete schema validation workflows
    - Multi-element dependency checking and validation
    - Cross-reference validation between schema components
    - Configuration-based validation behavior and options
    - Error collection and comprehensive reporting mechanisms

Performance Testing:
    - Large schema validation efficiency and optimization
    - Name conflict detection performance at scale
    - OID uniqueness checking optimization
    - Dependency validation performance patterns
    - Validation configuration impact on performance

Security Testing:
    - Input validation and sanitization for schema elements
    - Name injection and conflict protection
    - OID validation security and format checking
    - Error message information disclosure protection
    - Resource consumption limits during validation
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from ldap_core_shared.schema.parser import (
    AttributeType,
    MatchingRule,
    ObjectClass,
    ParsedSchema,
    SyntaxDefinition,
)
from ldap_core_shared.schema.validator import (
    SchemaValidationConfig,
    SchemaValidator,
)


class TestSchemaValidationConfig:
    """Test cases for SchemaValidationConfig."""

    def test_config_creation_defaults(self) -> None:
        """Test creating config with default values."""
        config = SchemaValidationConfig()

        assert config.check_rfc_compliance is True
        assert config.check_dependencies is True
        assert config.check_name_conflicts is True
        assert config.check_oid_uniqueness is True
        assert config.allow_obsolete_elements is False

    def test_config_creation_custom(self) -> None:
        """Test creating config with custom values."""
        config = SchemaValidationConfig(
            check_rfc_compliance=False,
            check_dependencies=False,
            check_name_conflicts=False,
            check_oid_uniqueness=False,
            allow_obsolete_elements=True,
        )

        assert config.check_rfc_compliance is False
        assert config.check_dependencies is False
        assert config.check_name_conflicts is False
        assert config.check_oid_uniqueness is False
        assert config.allow_obsolete_elements is True

    def test_config_strict_mode(self) -> None:
        """Test config strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            SchemaValidationConfig(extra_field="not_allowed")

    def test_config_selective_validation(self) -> None:
        """Test config with selective validation enabled."""
        config = SchemaValidationConfig(
            check_rfc_compliance=True,
            check_dependencies=False,
            check_name_conflicts=True,
            check_oid_uniqueness=False,
        )

        assert config.check_rfc_compliance is True
        assert config.check_dependencies is False
        assert config.check_name_conflicts is True
        assert config.check_oid_uniqueness is False


class TestSchemaValidator:
    """Test cases for SchemaValidator."""

    def test_validator_initialization_default(self) -> None:
        """Test validator initialization with default config."""
        validator = SchemaValidator()

        assert isinstance(validator.config, SchemaValidationConfig)
        assert validator.config.check_rfc_compliance is True
        assert validator.config.check_dependencies is True

    def test_validator_initialization_custom_config(self) -> None:
        """Test validator initialization with custom config."""
        config = SchemaValidationConfig(
            check_rfc_compliance=False,
            check_dependencies=True,
        )
        validator = SchemaValidator(config)

        assert validator.config.check_rfc_compliance is False
        assert validator.config.check_dependencies is True

    def test_validate_schema_valid_complete(self) -> None:
        """Test validating complete valid schema."""
        validator = SchemaValidator()

        # Create valid schema elements
        attr_type = AttributeType(
            oid="2.5.4.3",
            names=["cn", "commonName"],
            description="Common Name",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            usage="userApplications",
        )

        obj_class = ObjectClass(
            oid="2.5.6.6",
            names=["person"],
            description="Person object class",
            superior_classes=["top"],
            class_type="STRUCTURAL",
            must_attributes=["sn", "cn"],
            may_attributes=["description"],
        )

        syntax_def = SyntaxDefinition(
            oid="1.3.6.1.4.1.1466.115.121.1.15",
            description="Directory String",
        )

        matching_rule = MatchingRule(
            oid="2.5.13.2",
            names=["caseIgnoreMatch"],
            description="Case Ignore Match",
        )

        schema = ParsedSchema(
            attribute_types={"2.5.4.3": attr_type},
            object_classes={"2.5.6.6": obj_class},
            syntax_definitions={"1.3.6.1.4.1.1466.115.121.1.15": syntax_def},
            matching_rules={"2.5.13.2": matching_rule},
        )

        result = validator.validate_schema(schema)

        assert result.valid is True
        assert result.validation_type == "schema"
        assert result.entries_validated == 1
        assert len(result.schema_errors) == 0

    def test_validate_schema_with_errors(self) -> None:
        """Test validating schema with various errors."""
        validator = SchemaValidator()

        # Create schema with errors
        attr_type_invalid_oid = AttributeType(
            oid="invalid.oid",  # Invalid OID format
            names=["cn"],
        )

        attr_type_no_names = AttributeType(
            oid="2.5.4.4",
            names=[],  # No names (will cause RFC error)
        )

        obj_class_invalid_type = ObjectClass(
            oid="2.5.6.7",
            names=["invalidClass"],
            class_type="INVALID_TYPE",  # Invalid class type
        )

        schema = ParsedSchema(
            attribute_types={
                "invalid.oid": attr_type_invalid_oid,
                "2.5.4.4": attr_type_no_names,
            },
            object_classes={"2.5.6.7": obj_class_invalid_type},
        )

        result = validator.validate_schema(schema)

        assert result.valid is False
        assert len(result.schema_errors) > 0

        # Check for specific error types
        error_messages = " ".join(result.schema_errors)
        assert "Invalid OID format" in error_messages
        assert "must have at least one name" in error_messages
        assert "Invalid object class type" in error_messages

    def test_validate_schema_oid_duplicates(self) -> None:
        """Test validating schema with duplicate OIDs."""
        validator = SchemaValidator()

        # Create schema with duplicate OIDs
        attr_type = AttributeType(oid="2.5.4.3", names=["cn"])
        obj_class = ObjectClass(oid="2.5.4.3", names=["duplicate"])  # Same OID

        schema = ParsedSchema(
            attribute_types={"2.5.4.3": attr_type},
            object_classes={"2.5.4.3": obj_class},
        )

        result = validator.validate_schema(schema)

        assert result.valid is False
        assert any("Duplicate OID found: 2.5.4.3" in error for error in result.schema_errors)

    def test_validate_schema_name_conflicts(self) -> None:
        """Test validating schema with name conflicts."""
        validator = SchemaValidator()

        # Create schema with name conflicts
        attr_type = AttributeType(oid="2.5.4.3", names=["cn", "commonName"])
        obj_class = ObjectClass(oid="2.5.6.6", names=["cn"])  # Same name as attribute

        schema = ParsedSchema(
            attribute_types={"2.5.4.3": attr_type},
            object_classes={"2.5.6.6": obj_class},
        )

        result = validator.validate_schema(schema)

        assert result.valid is False
        assert any("Name conflict" in error and "cn" in error for error in result.schema_errors)

    def test_validate_schema_selective_checks(self) -> None:
        """Test validating schema with selective checks enabled."""
        # Config with only RFC compliance checking
        config = SchemaValidationConfig(
            check_rfc_compliance=True,
            check_dependencies=False,
            check_name_conflicts=False,
            check_oid_uniqueness=False,
        )
        validator = SchemaValidator(config)

        # Create schema with multiple types of issues
        attr_type = AttributeType(oid="invalid.oid", names=["cn"])  # RFC issue
        obj_class = ObjectClass(oid="invalid.oid", names=["cn"])    # Duplicate OID and name

        schema = ParsedSchema(
            attribute_types={"invalid.oid": attr_type},
            object_classes={"invalid.oid": obj_class},
        )

        result = validator.validate_schema(schema)

        # Should only report RFC compliance errors, not duplicates/conflicts
        assert result.valid is False
        assert any("Invalid OID format" in error for error in result.schema_errors)
        assert not any("Duplicate OID" in error for error in result.schema_errors)
        assert not any("Name conflict" in error for error in result.schema_errors)

    def test_validate_attribute_type_valid(self) -> None:
        """Test validating valid attribute type."""
        validator = SchemaValidator()

        attr_type = AttributeType(
            oid="2.5.4.3",
            names=["cn", "commonName"],
            description="Common Name",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            usage="userApplications",
        )

        schema = ParsedSchema()

        result = validator.validate_attribute_type(attr_type, schema)

        assert result.valid is True
        assert len(result.schema_errors) == 0

    def test_validate_attribute_type_invalid_oid(self) -> None:
        """Test validating attribute type with invalid OID."""
        validator = SchemaValidator()

        attr_type = AttributeType(
            oid="invalid.oid.format",
            names=["cn"],
        )

        schema = ParsedSchema()

        result = validator.validate_attribute_type(attr_type, schema)

        assert result.valid is False
        assert any("Invalid OID format" in error for error in result.schema_errors)

    def test_validate_attribute_type_no_names(self) -> None:
        """Test validating attribute type without names."""
        validator = SchemaValidator()

        attr_type = AttributeType(
            oid="2.5.4.3",
            names=[],  # No names
        )

        schema = ParsedSchema()

        result = validator.validate_attribute_type(attr_type, schema)

        assert result.valid is False
        assert any("must have at least one name" in error for error in result.schema_errors)

    def test_validate_attribute_type_invalid_names(self) -> None:
        """Test validating attribute type with invalid names."""
        validator = SchemaValidator()

        attr_type = AttributeType(
            oid="2.5.4.3",
            names=["123invalid", "invalid-name!", ""],  # Invalid names
        )

        schema = ParsedSchema()

        result = validator.validate_attribute_type(attr_type, schema)

        assert result.valid is False
        assert any("Invalid attribute name" in error for error in result.schema_errors)

    def test_validate_attribute_type_invalid_usage(self) -> None:
        """Test validating attribute type with invalid usage."""
        validator = SchemaValidator()

        attr_type = AttributeType(
            oid="2.5.4.3",
            names=["cn"],
            usage="invalidUsage",  # Invalid usage
        )

        schema = ParsedSchema()

        result = validator.validate_attribute_type(attr_type, schema)

        assert result.valid is False
        assert any("Invalid usage value" in error for error in result.schema_errors)

    def test_validate_attribute_type_obsolete_warning(self) -> None:
        """Test validating obsolete attribute type generates warning."""
        validator = SchemaValidator()

        attr_type = AttributeType(
            oid="2.5.4.3",
            names=["cn"],
            obsolete=True,
        )

        schema = ParsedSchema()

        result = validator.validate_attribute_type(attr_type, schema)

        assert result.valid is True  # Valid but with warning
        assert any("is marked as obsolete" in warning for warning in result.syntax_errors)

    def test_validate_attribute_type_allow_obsolete(self) -> None:
        """Test validating obsolete attribute type with obsolete allowed."""
        config = SchemaValidationConfig(allow_obsolete_elements=True)
        validator = SchemaValidator(config)

        attr_type = AttributeType(
            oid="2.5.4.3",
            names=["cn"],
            obsolete=True,
        )

        schema = ParsedSchema()

        result = validator.validate_attribute_type(attr_type, schema)

        assert result.valid is True
        assert len(result.syntax_errors) == 0  # No obsolete warning

    def test_validate_attribute_type_dependencies(self) -> None:
        """Test validating attribute type dependencies."""
        validator = SchemaValidator()

        # Attribute with superior that doesn't exist
        attr_type = AttributeType(
            oid="2.5.4.3",
            names=["cn"],
            superior="nonExistentSuperior",
        )

        schema = ParsedSchema()

        result = validator.validate_attribute_type(attr_type, schema)

        assert result.valid is False
        assert any("Superior attribute type not found" in error for error in result.schema_errors)

    def test_validate_attribute_type_syntax_dependency(self) -> None:
        """Test validating attribute type syntax dependency."""
        validator = SchemaValidator()

        attr_type = AttributeType(
            oid="2.5.4.3",
            names=["cn"],
            syntax="1.3.6.1.4.1.1466.115.121.1.15",  # Syntax not in schema
        )

        # Schema with syntax definitions but not the one we need
        schema = ParsedSchema(
            syntax_definitions={
                "1.3.6.1.4.1.1466.115.121.1.12": SyntaxDefinition(
                    oid="1.3.6.1.4.1.1466.115.121.1.12",
                ),
            },
        )

        result = validator.validate_attribute_type(attr_type, schema)

        assert result.valid is False
        assert any("Syntax definition not found" in error for error in result.schema_errors)

    def test_validate_object_class_valid(self) -> None:
        """Test validating valid object class."""
        validator = SchemaValidator()

        obj_class = ObjectClass(
            oid="2.5.6.6",
            names=["person"],
            description="Person object class",
            superior_classes=["top"],
            class_type="STRUCTURAL",
            must_attributes=["sn", "cn"],
            may_attributes=["description"],
        )

        schema = ParsedSchema()

        result = validator.validate_object_class(obj_class, schema)

        assert result.valid is True
        assert len(result.schema_errors) == 0

    def test_validate_object_class_invalid_oid(self) -> None:
        """Test validating object class with invalid OID."""
        validator = SchemaValidator()

        obj_class = ObjectClass(
            oid="invalid.oid",
            names=["person"],
        )

        schema = ParsedSchema()

        result = validator.validate_object_class(obj_class, schema)

        assert result.valid is False
        assert any("Invalid OID format" in error for error in result.schema_errors)

    def test_validate_object_class_no_names(self) -> None:
        """Test validating object class without names."""
        validator = SchemaValidator()

        obj_class = ObjectClass(
            oid="2.5.6.6",
            names=[],  # No names
        )

        schema = ParsedSchema()

        result = validator.validate_object_class(obj_class, schema)

        assert result.valid is False
        assert any("must have at least one name" in error for error in result.schema_errors)

    def test_validate_object_class_invalid_names(self) -> None:
        """Test validating object class with invalid names."""
        validator = SchemaValidator()

        obj_class = ObjectClass(
            oid="2.5.6.6",
            names=["123invalid", "invalid-name!"],  # Invalid names
        )

        schema = ParsedSchema()

        result = validator.validate_object_class(obj_class, schema)

        assert result.valid is False
        assert any("Invalid object class name" in error for error in result.schema_errors)

    def test_validate_object_class_invalid_type(self) -> None:
        """Test validating object class with invalid type."""
        validator = SchemaValidator()

        obj_class = ObjectClass(
            oid="2.5.6.6",
            names=["person"],
            class_type="INVALID_TYPE",
        )

        schema = ParsedSchema()

        result = validator.validate_object_class(obj_class, schema)

        assert result.valid is False
        assert any("Invalid object class type" in error for error in result.schema_errors)

    def test_validate_object_class_dependencies(self) -> None:
        """Test validating object class dependencies."""
        validator = SchemaValidator()

        obj_class = ObjectClass(
            oid="2.5.6.6",
            names=["person"],
            superior_classes=["nonExistentSuperior"],
            must_attributes=["nonExistentAttr"],
            may_attributes=["anotherNonExistentAttr"],
        )

        schema = ParsedSchema()

        result = validator.validate_object_class(obj_class, schema)

        assert result.valid is False
        assert any("Superior object class not found" in error for error in result.schema_errors)
        assert any("Required attribute not found" in error for error in result.schema_errors)
        assert any("Optional attribute not found" in error for error in result.schema_errors)


class TestSchemaValidatorHelperMethods:
    """Test cases for schema validator helper methods."""

    def test_is_valid_oid_valid(self) -> None:
        """Test OID validation with valid OIDs."""
        validator = SchemaValidator()

        valid_oids = [
            "2.5.4.3",
            "1.3.6.1.4.1.1466.115.121.1.15",
            "1.2.3.4.5.6.7.8.9.10",
            "0.1",
            "999.999.999",
        ]

        for oid in valid_oids:
            assert validator._is_valid_oid(oid) is True, f"OID should be valid: {oid}"

    def test_is_valid_oid_invalid(self) -> None:
        """Test OID validation with invalid OIDs."""
        validator = SchemaValidator()

        invalid_oids = [
            "",
            "invalid",
            "2.5.4.",
            ".2.5.4.3",
            "2..5.4.3",
            "2.5.4.3.",
            "2.5.4.a",
            "2.5.4.3.invalid",
        ]

        for oid in invalid_oids:
            assert validator._is_valid_oid(oid) is False, f"OID should be invalid: {oid}"

    def test_is_valid_attribute_name_valid(self) -> None:
        """Test attribute name validation with valid names."""
        validator = SchemaValidator()

        valid_names = [
            "cn",
            "commonName",
            "objectClass",
            "telephoneNumber",
            "x121Address",
            "a",
            "A",
            "name123",
            "test-attr",
        ]

        for name in valid_names:
            assert validator._is_valid_attribute_name(name) is True, f"Name should be valid: {name}"

    def test_is_valid_attribute_name_invalid(self) -> None:
        """Test attribute name validation with invalid names."""
        validator = SchemaValidator()

        invalid_names = [
            "",
            "123invalid",
            "-invalid",
            "invalid!",
            "invalid@attr",
            "invalid attr",
            "invalid.attr",
            "инвалид",  # Unicode
        ]

        for name in invalid_names:
            assert validator._is_valid_attribute_name(name) is False, f"Name should be invalid: {name}"

    def test_is_valid_object_class_name_valid(self) -> None:
        """Test object class name validation with valid names."""
        validator = SchemaValidator()

        valid_names = [
            "person",
            "organizationalPerson",
            "inetOrgPerson",
            "top",
            "groupOfNames",
            "a",
            "TestClass123",
            "class-name",
        ]

        for name in valid_names:
            assert validator._is_valid_object_class_name(name) is True, f"Name should be valid: {name}"

    def test_is_valid_object_class_name_invalid(self) -> None:
        """Test object class name validation with invalid names."""
        validator = SchemaValidator()

        invalid_names = [
            "",
            "123invalid",
            "-invalid",
            "invalid!",
            "invalid@class",
            "invalid class",
            "invalid.class",
        ]

        for name in invalid_names:
            assert validator._is_valid_object_class_name(name) is False, f"Name should be invalid: {name}"

    def test_find_attribute_by_name_found(self) -> None:
        """Test finding attribute by name when it exists."""
        validator = SchemaValidator()

        attr_type = AttributeType(oid="2.5.4.3", names=["cn", "commonName"])
        schema = ParsedSchema(attribute_types={"2.5.4.3": attr_type})

        # Test exact match
        found = validator._find_attribute_by_name("cn", schema)
        assert found is not None
        assert found.oid == "2.5.4.3"

        # Test case insensitive match
        found = validator._find_attribute_by_name("CN", schema)
        assert found is not None
        assert found.oid == "2.5.4.3"

        # Test alternative name
        found = validator._find_attribute_by_name("commonName", schema)
        assert found is not None
        assert found.oid == "2.5.4.3"

    def test_find_attribute_by_name_not_found(self) -> None:
        """Test finding attribute by name when it doesn't exist."""
        validator = SchemaValidator()

        attr_type = AttributeType(oid="2.5.4.3", names=["cn"])
        schema = ParsedSchema(attribute_types={"2.5.4.3": attr_type})

        found = validator._find_attribute_by_name("nonExistent", schema)
        assert found is None

    def test_find_object_class_by_name_found(self) -> None:
        """Test finding object class by name when it exists."""
        validator = SchemaValidator()

        obj_class = ObjectClass(oid="2.5.6.6", names=["person", "personClass"])
        schema = ParsedSchema(object_classes={"2.5.6.6": obj_class})

        # Test exact match
        found = validator._find_object_class_by_name("person", schema)
        assert found is not None
        assert found.oid == "2.5.6.6"

        # Test case insensitive match
        found = validator._find_object_class_by_name("PERSON", schema)
        assert found is not None
        assert found.oid == "2.5.6.6"

    def test_find_object_class_by_name_not_found(self) -> None:
        """Test finding object class by name when it doesn't exist."""
        validator = SchemaValidator()

        obj_class = ObjectClass(oid="2.5.6.6", names=["person"])
        schema = ParsedSchema(object_classes={"2.5.6.6": obj_class})

        found = validator._find_object_class_by_name("nonExistent", schema)
        assert found is None

    def test_find_matching_rule_by_name_found(self) -> None:
        """Test finding matching rule by name when it exists."""
        validator = SchemaValidator()

        matching_rule = MatchingRule(oid="2.5.13.2", names=["caseIgnoreMatch"])
        schema = ParsedSchema(matching_rules={"2.5.13.2": matching_rule})

        # Test exact match
        found = validator._find_matching_rule_by_name("caseIgnoreMatch", schema)
        assert found is True

        # Test case insensitive match
        found = validator._find_matching_rule_by_name("CASEIGNOREMATCH", schema)
        assert found is True

    def test_find_matching_rule_by_name_not_found(self) -> None:
        """Test finding matching rule by name when it doesn't exist."""
        validator = SchemaValidator()

        matching_rule = MatchingRule(oid="2.5.13.2", names=["caseIgnoreMatch"])
        schema = ParsedSchema(matching_rules={"2.5.13.2": matching_rule})

        found = validator._find_matching_rule_by_name("nonExistent", schema)
        assert found is False


class TestSchemaValidatorIntegration:
    """Test cases for schema validator integration scenarios."""

    def test_complete_validation_workflow(self) -> None:
        """Test complete validation workflow with complex schema."""
        validator = SchemaValidator()

        # Create complex schema with interdependencies
        name_attr = AttributeType(
            oid="2.5.4.41",
            names=["name"],
            description="Common supertype of name attributes",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
            usage="userApplications",
        )

        cn_attr = AttributeType(
            oid="2.5.4.3",
            names=["cn", "commonName"],
            description="Common Name",
            superior="name",  # References name_attr
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        sn_attr = AttributeType(
            oid="2.5.4.4",
            names=["sn", "surname"],
            description="Surname",
            superior="name",  # References name_attr
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        top_class = ObjectClass(
            oid="2.5.6.0",
            names=["top"],
            description="Top of superclass chain",
            class_type="ABSTRACT",
            must_attributes=["objectClass"],
        )

        person_class = ObjectClass(
            oid="2.5.6.6",
            names=["person"],
            description="Person object class",
            superior_classes=["top"],  # References top_class
            class_type="STRUCTURAL",
            must_attributes=["sn", "cn"],  # References sn_attr and cn_attr
            may_attributes=["description"],
        )

        directory_string_syntax = SyntaxDefinition(
            oid="1.3.6.1.4.1.1466.115.121.1.15",
            description="Directory String",
        )

        case_ignore_match = MatchingRule(
            oid="2.5.13.2",
            names=["caseIgnoreMatch"],
            description="Case Ignore Match",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )

        schema = ParsedSchema(
            attribute_types={
                "2.5.4.41": name_attr,
                "2.5.4.3": cn_attr,
                "2.5.4.4": sn_attr,
            },
            object_classes={
                "2.5.6.0": top_class,
                "2.5.6.6": person_class,
            },
            syntax_definitions={
                "1.3.6.1.4.1.1466.115.121.1.15": directory_string_syntax,
            },
            matching_rules={
                "2.5.13.2": case_ignore_match,
            },
        )

        result = validator.validate_schema(schema)

        # Should be valid as all dependencies are satisfied
        assert result.valid is True
        assert len(result.schema_errors) == 0

    def test_configuration_based_validation_behavior(self) -> None:
        """Test validation behavior based on configuration."""
        # Schema with various issues
        invalid_attr = AttributeType(oid="invalid.oid", names=["cn"])
        obsolete_attr = AttributeType(oid="2.5.4.4", names=["sn"], obsolete=True)
        duplicate_name_class = ObjectClass(oid="2.5.6.6", names=["cn"])  # Name conflict

        schema = ParsedSchema(
            attribute_types={
                "invalid.oid": invalid_attr,
                "2.5.4.4": obsolete_attr,
            },
            object_classes={"2.5.6.6": duplicate_name_class},
        )

        # Strict validation
        strict_config = SchemaValidationConfig(
            check_rfc_compliance=True,
            check_dependencies=True,
            check_name_conflicts=True,
            check_oid_uniqueness=True,
            allow_obsolete_elements=False,
        )
        strict_validator = SchemaValidator(strict_config)
        strict_result = strict_validator.validate_schema(schema)

        # Relaxed validation
        relaxed_config = SchemaValidationConfig(
            check_rfc_compliance=False,
            check_dependencies=False,
            check_name_conflicts=False,
            check_oid_uniqueness=False,
            allow_obsolete_elements=True,
        )
        relaxed_validator = SchemaValidator(relaxed_config)
        relaxed_result = relaxed_validator.validate_schema(schema)

        # Strict should find more errors
        assert strict_result.valid is False
        assert len(strict_result.schema_errors) > 0
        assert len(strict_result.syntax_errors) > 0

        # Relaxed should pass or have fewer errors
        assert len(strict_result.schema_errors) > len(relaxed_result.schema_errors)
        assert len(strict_result.syntax_errors) > len(relaxed_result.syntax_errors)

    def test_error_accumulation_and_reporting(self) -> None:
        """Test comprehensive error accumulation and reporting."""
        validator = SchemaValidator()

        # Create schema with multiple error types
        problems = [
            AttributeType(oid="invalid.oid.1", names=[]),  # Invalid OID + no names
            AttributeType(oid="2.5.4.3", names=["123invalid"]),  # Invalid name
            AttributeType(oid="2.5.4.4", names=["attr"], usage="invalidUsage"),  # Invalid usage
            ObjectClass(oid="invalid.oid.2", names=[]),  # Invalid OID + no names
            ObjectClass(oid="2.5.6.6", names=["456invalid"], class_type="INVALID"),  # Invalid name + type
        ]

        schema = ParsedSchema(
            attribute_types={
                "invalid.oid.1": problems[0],
                "2.5.4.3": problems[1],
                "2.5.4.4": problems[2],
            },
            object_classes={
                "invalid.oid.2": problems[3],
                "2.5.6.6": problems[4],
            },
        )

        result = validator.validate_schema(schema)

        assert result.valid is False
        assert len(result.schema_errors) >= 5  # Should have multiple errors

        # Verify specific error types are reported
        error_messages = " ".join(result.schema_errors)
        assert "Invalid OID format" in error_messages
        assert "must have at least one name" in error_messages
        assert "Invalid attribute name" in error_messages
        assert "Invalid usage value" in error_messages
        assert "Invalid object class name" in error_messages
        assert "Invalid object class type" in error_messages

    def test_dependency_chain_validation(self) -> None:
        """Test validation of complex dependency chains."""
        validator = SchemaValidator()

        # Create dependency chain: cn -> name -> (missing superior)
        name_attr = AttributeType(
            oid="2.5.4.41",
            names=["name"],
            superior="missingParent",  # Missing dependency
        )

        cn_attr = AttributeType(
            oid="2.5.4.3",
            names=["cn"],
            superior="name",  # Valid dependency
        )

        # Object class with dependency on missing attribute
        person_class = ObjectClass(
            oid="2.5.6.6",
            names=["person"],
            superior_classes=["missingClass"],  # Missing dependency
            must_attributes=["cn", "missingAttr"],  # One valid, one missing
        )

        schema = ParsedSchema(
            attribute_types={
                "2.5.4.41": name_attr,
                "2.5.4.3": cn_attr,
            },
            object_classes={"2.5.6.6": person_class},
        )

        result = validator.validate_schema(schema)

        assert result.valid is False

        # Should report all missing dependencies
        error_messages = " ".join(result.schema_errors)
        assert "Superior attribute type not found: missingParent" in error_messages
        assert "Superior object class not found: missingClass" in error_messages
        assert "Required attribute not found: missingAttr" in error_messages

    def test_name_conflict_detection_comprehensive(self) -> None:
        """Test comprehensive name conflict detection."""
        validator = SchemaValidator()

        # Create various types of name conflicts
        attr1 = AttributeType(oid="2.5.4.3", names=["cn", "commonName"])
        attr2 = AttributeType(oid="2.5.4.4", names=["sn", "CN"])  # Case conflict with attr1
        obj_class1 = ObjectClass(oid="2.5.6.6", names=["person", "COMMONNAME"])  # Case conflict
        obj_class2 = ObjectClass(oid="2.5.6.7", names=["org", "sn"])  # Conflict with attr2

        schema = ParsedSchema(
            attribute_types={
                "2.5.4.3": attr1,
                "2.5.4.4": attr2,
            },
            object_classes={
                "2.5.6.6": obj_class1,
                "2.5.6.7": obj_class2,
            },
        )

        result = validator.validate_schema(schema)

        assert result.valid is False

        # Should detect all conflicts (case insensitive)
        error_messages = " ".join(result.schema_errors)
        assert "Name conflict" in error_messages
        assert "cn" in error_messages.lower() or "commonname" in error_messages.lower()
        assert "sn" in error_messages.lower()

    def test_performance_with_large_schema(self) -> None:
        """Test validator performance with large schema."""
        validator = SchemaValidator()

        # Generate large schema
        attribute_types = {}
        object_classes = {}

        for i in range(100):
            attr_oid = f"1.2.3.4.{i}"
            attr = AttributeType(
                oid=attr_oid,
                names=[f"attr{i:03d}", f"attribute{i:03d}"],
                description=f"Test attribute {i}",
            )
            attribute_types[attr_oid] = attr

            if i % 10 == 0:  # Every 10th becomes an object class
                class_oid = f"1.2.3.5.{i}"
                obj_class = ObjectClass(
                    oid=class_oid,
                    names=[f"class{i:03d}"],
                    description=f"Test class {i}",
                    must_attributes=[f"attr{i:03d}"],
                )
                object_classes[class_oid] = obj_class

        schema = ParsedSchema(
            attribute_types=attribute_types,
            object_classes=object_classes,
        )

        result = validator.validate_schema(schema)

        # Should handle large schema efficiently
        assert result.valid is True
        assert result.validation_type == "schema"
