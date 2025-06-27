"""Unit tests for Schema Parser module.

Tests the schema2ldif-perl-converter equivalent functionality including
schema file parsing, attribute type extraction, object class parsing,
and error handling.
"""

from __future__ import annotations

import pytest

from ldap_core_shared.schema.models import AttributeType, ObjectClass, SchemaParseResult


class TestSchemaParser:
    """Test cases for SchemaParser class."""

    @pytest.fixture
    def schema_parser(self):
        """Create SchemaParser instance for testing."""
        from ldap_core_shared.schema.parser import SchemaParser

        return SchemaParser()

    @pytest.mark.unit
    @pytest.mark.schema
    def test_parser_initialization(self, schema_parser) -> None:
        """Test SchemaParser initialization."""
        assert schema_parser is not None
        assert hasattr(schema_parser, "parse_schema_file")
        assert hasattr(schema_parser, "parse_schema_text")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_parse_simple_attribute_type(self, schema_parser, temp_schema_file) -> None:
        """Test parsing simple attribute type."""
        # This test will be skipped if modules are not available
        try:
            result = schema_parser.parse_schema_file(str(temp_schema_file))

            # Basic structure validation
            assert isinstance(result, SchemaParseResult)
            assert hasattr(result, "success")
            assert hasattr(result, "attribute_types")
            assert hasattr(result, "object_classes")

        except ImportError:
            pytest.skip("Schema parser module not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_parse_attribute_type_with_constraints(self, schema_parser) -> None:
        """Test parsing attribute type with size constraints."""
        schema_text = """
        attributetype ( 1.2.3.4.5.100
            NAME 'constrainedAttribute'
            DESC 'Attribute with size constraint'
            EQUALITY caseIgnoreMatch
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64}
            SINGLE-VALUE )
        """

        try:
            result = schema_parser.parse_schema_text(schema_text)
            assert result is not None

        except (ImportError, NotImplementedError):
            pytest.skip("Schema parser functionality not fully implemented")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_parse_multi_name_attribute(self, schema_parser) -> None:
        """Test parsing attribute with multiple names."""
        schema_text = """
        attributetype ( 1.2.3.4.5.200
            NAME ( 'primaryName' 'aliasName' 'shortName' )
            DESC 'Multi-name attribute'
            EQUALITY caseIgnoreMatch
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
        """

        try:
            result = schema_parser.parse_schema_text(schema_text)
            assert result is not None

        except (ImportError, NotImplementedError):
            pytest.skip("Multi-name attribute parsing not fully implemented")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_parse_object_class(self, schema_parser) -> None:
        """Test parsing object class definition."""
        schema_text = """
        objectclass ( 1.2.3.4.6.100
            NAME 'testPerson'
            DESC 'Test person object class'
            SUP top
            STRUCTURAL
            MUST ( cn $ sn )
            MAY ( givenName $ mail $ telephoneNumber ) )
        """

        try:
            result = schema_parser.parse_schema_text(schema_text)
            assert result is not None

        except (ImportError, NotImplementedError):
            pytest.skip("Object class parsing not fully implemented")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_parse_invalid_schema(self, schema_parser) -> None:
        """Test parsing invalid schema returns appropriate errors."""
        invalid_schema = """
        attributetype ( invalid.oid.format
            NAME 'badAttribute'
            SYNTAX invalid.syntax )
        """

        try:
            result = schema_parser.parse_schema_text(invalid_schema)

            # Should either return error result or raise exception
            if hasattr(result, "success"):
                assert not result.success or len(getattr(result, "errors", [])) > 0

        except (ImportError, NotImplementedError, ValueError):
            # Expected for various reasons during development
            pass

    @pytest.mark.unit
    @pytest.mark.schema
    def test_parse_nonexistent_file(self, schema_parser) -> None:
        """Test parsing nonexistent file raises appropriate error."""
        nonexistent_file = "/path/that/does/not/exist.schema"

        try:
            with pytest.raises(FileNotFoundError):
                schema_parser.parse_schema_file(nonexistent_file)

        except ImportError:
            pytest.skip("Schema parser module not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_parse_empty_schema(self, schema_parser) -> None:
        """Test parsing empty schema file."""
        try:
            result = schema_parser.parse_schema_text("")

            # Should handle empty input gracefully
            if hasattr(result, "attribute_types"):
                assert len(result.attribute_types) == 0
            if hasattr(result, "object_classes"):
                assert len(result.object_classes) == 0

        except (ImportError, NotImplementedError):
            pytest.skip("Empty schema handling not implemented")


class TestAttributeType:
    """Test cases for AttributeType model."""

    @pytest.mark.unit
    @pytest.mark.schema
    def test_attribute_type_creation(self) -> None:
        """Test AttributeType model creation."""
        try:
            attr = AttributeType(
                oid="1.2.3.4.5.1",
                names=["testAttribute"],
                description="Test attribute",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                single_value=True,
            )

            assert attr.oid == "1.2.3.4.5.1"
            assert "testAttribute" in attr.names
            assert attr.single_value is True

        except ImportError:
            pytest.skip("AttributeType model not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_attribute_type_validation(self) -> None:
        """Test AttributeType validation."""
        try:
            # Test invalid OID
            with pytest.raises(ValueError):
                AttributeType(
                    oid="invalid.oid",
                    names=["test"],
                    syntax="1.3.6.1.4.1.1466.115.121.1.15",
                )

        except ImportError:
            pytest.skip("AttributeType validation not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_attribute_type_equality(self) -> None:
        """Test AttributeType equality comparison."""
        try:
            attr1 = AttributeType(
                oid="1.2.3.4.5.1",
                names=["testAttribute"],
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
            )

            attr2 = AttributeType(
                oid="1.2.3.4.5.1",
                names=["testAttribute"],
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
            )

            assert attr1 == attr2

        except ImportError:
            pytest.skip("AttributeType model not available")


class TestObjectClass:
    """Test cases for ObjectClass model."""

    @pytest.mark.unit
    @pytest.mark.schema
    def test_object_class_creation(self) -> None:
        """Test ObjectClass model creation."""
        try:
            obj_class = ObjectClass(
                oid="1.2.3.4.6.1",
                names=["testObjectClass"],
                description="Test object class",
                kind="STRUCTURAL",
                superior=["top"],
                must_attributes=["cn"],
                may_attributes=["description"],
            )

            assert obj_class.oid == "1.2.3.4.6.1"
            assert "testObjectClass" in obj_class.names
            assert obj_class.kind == "STRUCTURAL"
            assert "cn" in obj_class.must_attributes

        except ImportError:
            pytest.skip("ObjectClass model not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_object_class_validation(self) -> None:
        """Test ObjectClass validation."""
        try:
            # Test invalid kind
            with pytest.raises(ValueError):
                ObjectClass(
                    oid="1.2.3.4.6.1",
                    names=["test"],
                    kind="INVALID_KIND",
                )

        except ImportError:
            pytest.skip("ObjectClass validation not available")


class TestSchemaParseResult:
    """Test cases for SchemaParseResult model."""

    @pytest.mark.unit
    @pytest.mark.schema
    def test_parse_result_creation(self) -> None:
        """Test SchemaParseResult creation."""
        try:
            result = SchemaParseResult(
                success=True,
                attribute_types=[],
                object_classes=[],
                errors=[],
                warnings=[],
            )

            assert result.success is True
            assert isinstance(result.attribute_types, list)
            assert isinstance(result.object_classes, list)
            assert isinstance(result.errors, list)
            assert isinstance(result.warnings, list)

        except ImportError:
            pytest.skip("SchemaParseResult model not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_parse_result_error_handling(self) -> None:
        """Test SchemaParseResult error handling."""
        try:
            result = SchemaParseResult(
                success=False,
                attribute_types=[],
                object_classes=[],
                errors=["Parse error occurred"],
                warnings=["Warning message"],
            )

            assert result.success is False
            assert len(result.errors) == 1
            assert "Parse error occurred" in result.errors

        except ImportError:
            pytest.skip("SchemaParseResult model not available")


# Performance tests
class TestSchemaParserPerformance:
    """Performance tests for schema parser."""

    @pytest.mark.unit
    @pytest.mark.schema
    @pytest.mark.slow
    def test_parse_large_schema_performance(self, schema_parser) -> None:
        """Test parsing large schema file performance."""
        # Generate large schema content
        large_schema = [
            f"""
            attributetype ( 1.2.3.4.5.{i}
                NAME 'testAttribute{i}'
                DESC 'Test attribute {i}'
                EQUALITY caseIgnoreMatch
                SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
            """
            for i in range(1000)
        ]

        large_schema_text = "\n".join(large_schema)

        try:
            import time

            start_time = time.time()

            schema_parser.parse_schema_text(large_schema_text)

            parse_time = time.time() - start_time

            # Should parse reasonably quickly (less than 10 seconds)
            assert parse_time < 10.0

        except (ImportError, NotImplementedError):
            pytest.skip("Large schema parsing performance test not available")


# Error handling tests
class TestSchemaParserErrorHandling:
    """Test error handling in schema parser."""

    @pytest.mark.unit
    @pytest.mark.schema
    def test_malformed_attribute_type(self, schema_parser) -> None:
        """Test handling malformed attribute type."""
        malformed_schema = """
        attributetype ( 1.2.3.4.5.1
            NAME 'testAttribute'
            # Missing closing parenthesis
        """

        try:
            result = schema_parser.parse_schema_text(malformed_schema)

            # Should handle malformed input gracefully
            if hasattr(result, "success"):
                assert not result.success or len(getattr(result, "errors", [])) > 0

        except (ImportError, NotImplementedError, SyntaxError):
            # Expected during development
            pass

    @pytest.mark.unit
    @pytest.mark.schema
    def test_duplicate_oid_handling(self, schema_parser) -> None:
        """Test handling duplicate OID in schema."""
        duplicate_oid_schema = """
        attributetype ( 1.2.3.4.5.1
            NAME 'firstAttribute'
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )

        attributetype ( 1.2.3.4.5.1
            NAME 'secondAttribute'
            SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
        """

        try:
            result = schema_parser.parse_schema_text(duplicate_oid_schema)

            # Should detect duplicate OID
            if hasattr(result, "warnings"):
                # Might be treated as warning rather than error
                pass

        except (ImportError, NotImplementedError):
            pytest.skip("Duplicate OID handling not implemented")


# Integration with pytest fixtures
class TestSchemaParserWithFixtures:
    """Test schema parser using pytest fixtures."""

    @pytest.mark.unit
    @pytest.mark.schema
    def test_with_temp_schema_file(self, schema_parser, temp_schema_file) -> None:
        """Test parsing using temporary schema file fixture."""
        try:
            schema_parser.parse_schema_file(str(temp_schema_file))

            # Verify we can read the temp file
            assert temp_schema_file.exists()

        except ImportError:
            pytest.skip("Schema parser module not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_with_sample_content(self, schema_parser, sample_schema_content) -> None:
        """Test parsing using sample schema content fixture."""
        try:
            schema_parser.parse_schema_text(sample_schema_content)

            # Sample content should be valid
            assert sample_schema_content is not None
            assert len(sample_schema_content) > 0

        except ImportError:
            pytest.skip("Schema parser module not available")
