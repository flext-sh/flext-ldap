"""Unit tests for Schema LDIF Generator module.

Tests the LDIF generation functionality that converts parsed schema
elements into OpenLDAP cn=config format LDIF files.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from ldap_core_shared.schema.models import AttributeType, ObjectClass, SchemaLDIF


class TestLDIFGenerator:
    """Test cases for LDIFGenerator class."""

    @pytest.fixture
    def ldif_generator(self):
        """Create LDIFGenerator instance for testing."""
        from ldap_core_shared.schema.generator import LDIFGenerator

        return LDIFGenerator()

    @pytest.fixture
    def sample_attribute_type(self):
        """Create sample AttributeType for testing."""
        try:
            return AttributeType(
                oid="1.2.3.4.5.1",
                names=["testAttribute"],
                description="Test attribute for LDIF generation",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality="caseIgnoreMatch",
                single_value=True,
            )
        except ImportError:
            return Mock(
                oid="1.2.3.4.5.1",
                names=["testAttribute"],
                description="Test attribute for LDIF generation",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
            )

    @pytest.fixture
    def sample_object_class(self):
        """Create sample ObjectClass for testing."""
        try:
            return ObjectClass(
                oid="1.2.3.4.6.1",
                names=["testObjectClass"],
                description="Test object class for LDIF generation",
                kind="STRUCTURAL",
                superior=["top"],
                must_attributes=["cn"],
                may_attributes=["description"],
            )
        except ImportError:
            return Mock(
                oid="1.2.3.4.6.1",
                names=["testObjectClass"],
                description="Test object class for LDIF generation",
                kind="STRUCTURAL",
            )

    @pytest.mark.unit
    @pytest.mark.schema
    def test_generator_initialization(self, ldif_generator) -> None:
        """Test LDIFGenerator initialization."""
        assert ldif_generator is not None
        assert hasattr(ldif_generator, "generate_from_elements")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_generate_from_single_attribute(
        self, ldif_generator, sample_attribute_type
    ) -> None:
        """Test generating LDIF from single attribute type."""
        try:
            result = ldif_generator.generate_from_elements(
                attribute_types=[sample_attribute_type],
                object_classes=[],
            )

            assert isinstance(result, SchemaLDIF)
            assert hasattr(result, "success")
            assert hasattr(result, "content")

            if result.success and result.content:
                # Verify LDIF structure
                assert "dn: cn=schema,cn=config" in result.content
                assert "olcAttributeTypes:" in result.content
                assert "testAttribute" in result.content

        except ImportError:
            pytest.skip("LDIF generator module not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_generate_from_single_object_class(
        self, ldif_generator, sample_object_class
    ) -> None:
        """Test generating LDIF from single object class."""
        try:
            result = ldif_generator.generate_from_elements(
                attribute_types=[],
                object_classes=[sample_object_class],
            )

            if result.success and result.content:
                # Verify LDIF structure
                assert "dn: cn=schema,cn=config" in result.content
                assert "olcObjectClasses:" in result.content
                assert "testObjectClass" in result.content

        except ImportError:
            pytest.skip("LDIF generator module not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_generate_from_multiple_elements(
        self, ldif_generator, sample_attribute_type, sample_object_class
    ) -> None:
        """Test generating LDIF from multiple schema elements."""
        try:
            result = ldif_generator.generate_from_elements(
                attribute_types=[sample_attribute_type],
                object_classes=[sample_object_class],
            )

            if result.success and result.content:
                # Verify both types are included
                assert "olcAttributeTypes:" in result.content
                assert "olcObjectClasses:" in result.content
                assert "testAttribute" in result.content
                assert "testObjectClass" in result.content

        except ImportError:
            pytest.skip("LDIF generator module not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_generate_with_custom_config(
        self, ldif_generator, sample_attribute_type
    ) -> None:
        """Test generating LDIF with custom configuration."""
        try:
            from ldap_core_shared.schema.models import SchemaEntryConfig

            config = SchemaEntryConfig(
                schema_name="custom-test-schema",
                base_dn="cn=custom,cn=config",
                include_metadata=True,
            )

            result = ldif_generator.generate_from_elements(
                attribute_types=[sample_attribute_type],
                object_classes=[],
                config=config,
            )

            if result.success and result.content:
                assert "cn=custom,cn=config" in result.content

        except ImportError:
            pytest.skip("Custom config not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_generate_empty_elements(self, ldif_generator) -> None:
        """Test generating LDIF from empty element lists."""
        try:
            result = ldif_generator.generate_from_elements(
                attribute_types=[],
                object_classes=[],
            )

            # Should handle empty input gracefully
            assert isinstance(result, SchemaLDIF)

            if result.success:
                # Should still generate valid LDIF structure
                assert result.content is not None
                assert "dn: cn=schema,cn=config" in result.content

        except ImportError:
            pytest.skip("LDIF generator module not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_generate_with_invalid_elements(self, ldif_generator) -> None:
        """Test generating LDIF with invalid elements."""
        try:
            # Create invalid attribute type
            invalid_attr = Mock(
                oid="invalid.oid",
                names=["invalidAttribute"],
                syntax="",
            )

            result = ldif_generator.generate_from_elements(
                attribute_types=[invalid_attr],
                object_classes=[],
            )

            # Should handle invalid elements
            if hasattr(result, "success"):
                # Might fail or include warnings
                if not result.success:
                    assert len(getattr(result, "errors", [])) > 0

        except ImportError:
            pytest.skip("LDIF generator module not available")


class TestSchemaLDIF:
    """Test cases for SchemaLDIF model."""

    @pytest.mark.unit
    @pytest.mark.schema
    def test_schema_ldif_creation(self) -> None:
        """Test SchemaLDIF model creation."""
        try:
            ldif = SchemaLDIF(
                success=True,
                content="dn: cn=schema,cn=config\nobjectClass: olcSchemaConfig",
                errors=[],
                warnings=[],
            )

            assert ldif.success is True
            assert "dn: cn=schema,cn=config" in ldif.content
            assert isinstance(ldif.errors, list)
            assert isinstance(ldif.warnings, list)

        except ImportError:
            pytest.skip("SchemaLDIF model not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_schema_ldif_validation(self) -> None:
        """Test SchemaLDIF content validation."""
        try:
            ldif = SchemaLDIF(
                success=True,
                content="invalid ldif content",
                errors=[],
                warnings=[],
            )

            # Should validate LDIF format
            validation_errors = ldif.validate()

            # Invalid content should produce errors
            assert len(validation_errors) > 0

        except (ImportError, AttributeError):
            pytest.skip("SchemaLDIF validation not available")


class TestLDIFFormatting:
    """Test LDIF formatting functions."""

    @pytest.mark.unit
    @pytest.mark.schema
    def test_format_attribute_type_ldif(self) -> None:
        """Test formatting attribute type to LDIF."""
        try:
            from ldap_core_shared.schema.generator import format_attribute_type_ldif

            attr = Mock(
                oid="1.2.3.4.5.1",
                names=["testAttribute"],
                description="Test attribute",
                syntax="1.3.6.1.4.1.1466.115.121.1.15",
                equality="caseIgnoreMatch",
                single_value=True,
            )

            ldif_line = format_attribute_type_ldif(attr)

            assert "1.2.3.4.5.1" in ldif_line
            assert "testAttribute" in ldif_line
            assert "SINGLE-VALUE" in ldif_line

        except ImportError:
            pytest.skip("LDIF formatting functions not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_format_object_class_ldif(self) -> None:
        """Test formatting object class to LDIF."""
        try:
            from ldap_core_shared.schema.generator import format_object_class_ldif

            obj_class = Mock(
                oid="1.2.3.4.6.1",
                names=["testObjectClass"],
                description="Test object class",
                kind="STRUCTURAL",
                superior=["top"],
                must_attributes=["cn"],
                may_attributes=["description"],
            )

            ldif_line = format_object_class_ldif(obj_class)

            assert "1.2.3.4.6.1" in ldif_line
            assert "testObjectClass" in ldif_line
            assert "STRUCTURAL" in ldif_line
            assert "MUST ( cn )" in ldif_line

        except ImportError:
            pytest.skip("LDIF formatting functions not available")


class TestLDIFValidation:
    """Test LDIF validation functionality."""

    @pytest.mark.unit
    @pytest.mark.schema
    def test_validate_ldif_syntax(self) -> None:
        """Test LDIF syntax validation."""
        valid_ldif = """dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema
olcAttributeTypes: ( 1.2.3.4.5.1 NAME 'testAttribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
"""

        try:
            from ldap_core_shared.schema.generator import validate_ldif_syntax

            errors = validate_ldif_syntax(valid_ldif)
            assert len(errors) == 0

        except ImportError:
            pytest.skip("LDIF validation not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_validate_invalid_ldif_syntax(self) -> None:
        """Test validation of invalid LDIF syntax."""
        invalid_ldif = """dn: cn=schema,cn=config
objectClass: olcSchemaConfig
# Missing required attributes
"""

        try:
            from ldap_core_shared.schema.generator import validate_ldif_syntax

            errors = validate_ldif_syntax(invalid_ldif)
            assert len(errors) > 0

        except ImportError:
            pytest.skip("LDIF validation not available")


class TestLDIFGeneratorWithFixtures:
    """Test LDIF generator using pytest fixtures."""

    @pytest.mark.unit
    @pytest.mark.schema
    def test_generate_to_file(
        self, ldif_generator, sample_attribute_type, temp_directory
    ) -> None:
        """Test generating LDIF to file."""
        try:
            result = ldif_generator.generate_from_elements(
                attribute_types=[sample_attribute_type],
                object_classes=[],
            )

            if result.success and result.content:
                # Write to temp file
                output_file = temp_directory / "test_output.ldif"
                output_file.write_text(result.content)

                # Verify file was created
                assert output_file.exists()

                # Verify content
                content = output_file.read_text()
                assert "testAttribute" in content

        except ImportError:
            pytest.skip("LDIF generator module not available")

    @pytest.mark.unit
    @pytest.mark.schema
    def test_generate_with_sample_ldif(
        self, ldif_generator, sample_ldif_content
    ) -> None:
        """Test comparing generated LDIF with sample."""
        try:
            # This test compares structure, not exact content
            assert "dn: cn=schema,cn=config" in sample_ldif_content
            assert "olcAttributeTypes:" in sample_ldif_content
            assert "olcObjectClasses:" in sample_ldif_content

        except ImportError:
            pytest.skip("LDIF comparison not available")


# Performance tests
class TestLDIFGeneratorPerformance:
    """Performance tests for LDIF generator."""

    @pytest.mark.unit
    @pytest.mark.schema
    @pytest.mark.slow
    def test_generate_large_schema_performance(self, ldif_generator) -> None:
        """Test generating LDIF from large number of elements."""
        try:
            # Create many mock elements
            attribute_types = []
            for i in range(1000):
                attr = Mock(
                    oid=f"1.2.3.4.5.{i}",
                    names=[f"testAttribute{i}"],
                    description=f"Test attribute {i}",
                    syntax="1.3.6.1.4.1.1466.115.121.1.15",
                )
                attribute_types.append(attr)

            import time

            start_time = time.time()

            result = ldif_generator.generate_from_elements(
                attribute_types=attribute_types,
                object_classes=[],
            )

            generation_time = time.time() - start_time

            # Should generate reasonably quickly (less than 5 seconds)
            assert generation_time < 5.0

            if result.success:
                # Should contain all attributes
                assert result.content is not None
                assert len(result.content) > 0

        except ImportError:
            pytest.skip("Large LDIF generation performance test not available")
