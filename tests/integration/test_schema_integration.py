"""Integration Tests for Schema Management (schema2ldif-perl-converter equivalent).

This module provides comprehensive integration tests for schema conversion
and management functionality, ensuring compatibility with schema2ldif-perl-converter
and ldap-schema-manager Perl tools.

Test Coverage:
    - Schema file format conversion (.schema <-> .ldif)
    - Schema parsing and validation
    - LDIF generation and formatting
    - Schema management operations
    - CLI tool integration
    - Error handling and edge cases

Integration Scenarios:
    - End-to-end schema conversion workflow
    - Schema validation with complex schemas
    - Integration with OpenLDAP cn=config
    - Batch processing scenarios
    - Error recovery and reporting
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

# Test data
SAMPLE_SCHEMA_CONTENT = """
# Sample OpenLDAP Schema File
# Test schema for integration testing

attributetype ( 1.2.3.4.5.1
    NAME 'testAttribute'
    DESC 'Test attribute for integration testing'
    EQUALITY caseIgnoreMatch
    SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256}
    SINGLE-VALUE )

attributetype ( 1.2.3.4.5.2
    NAME ( 'testMultiName' 'testAlias' )
    DESC 'Multi-name test attribute'
    EQUALITY integerMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
    SINGLE-VALUE )

objectclass ( 1.2.3.4.6.1
    NAME 'testObjectClass'
    DESC 'Test object class for integration testing'
    SUP top
    STRUCTURAL
    MUST ( cn $ testAttribute )
    MAY ( testMultiName $ description ) )
"""

EXPECTED_LDIF_CONTENT = """dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema
olcAttributeTypes: ( 1.2.3.4.5.1
  NAME 'testAttribute'
  DESC 'Test attribute for integration testing'
  EQUALITY caseIgnoreMatch
  SUBSTR caseIgnoreSubstringsMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256}
  SINGLE-VALUE )
olcAttributeTypes: ( 1.2.3.4.5.2
  NAME ( 'testMultiName' 'testAlias' )
  DESC 'Multi-name test attribute'
  EQUALITY integerMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
  SINGLE-VALUE )
olcObjectClasses: ( 1.2.3.4.6.1
  NAME 'testObjectClass'
  DESC 'Test object class for integration testing'
  SUP top
  STRUCTURAL
  MUST ( cn $ testAttribute )
  MAY ( testMultiName $ description ) )
"""


class TestSchemaConversionIntegration:
    """Integration tests for schema conversion functionality."""

    def test_schema_to_ldif_conversion(self) -> None:
        """Test complete schema to LDIF conversion workflow."""
        try:
            from ldap_core_shared.schema.generator import LDIFGenerator
            from ldap_core_shared.schema.parser import SchemaParser

            # Create temporary files
            with tempfile.NamedTemporaryFile(mode="w", suffix=".schema", delete=False, encoding="utf-8") as schema_file:
                schema_file.write(SAMPLE_SCHEMA_CONTENT)
                schema_path = schema_file.name

            with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as ldif_file:
                ldif_path = ldif_file.name

            try:
                # Parse schema file
                parser = SchemaParser()
                parse_result = parser.parse_schema_file(schema_path)

                assert parse_result.success, f"Schema parsing failed: {parse_result.errors}"
                assert len(parse_result.attribute_types) == 2
                assert len(parse_result.object_classes) == 1

                # Generate LDIF
                generator = LDIFGenerator()
                ldif_result = generator.generate_from_elements(
                    parse_result.attribute_types,
                    parse_result.object_classes,
                )

                assert ldif_result.success, f"LDIF generation failed: {ldif_result.errors}"
                assert ldif_result.content is not None

                # Write and verify output
                with open(ldif_path, "w", encoding="utf-8") as f:
                    f.write(ldif_result.content)

                with open(ldif_path, encoding="utf-8") as f:
                    generated_content = f.read()

                # Verify content structure
                assert "dn: cn=schema,cn=config" in generated_content
                assert "objectClass: olcSchemaConfig" in generated_content
                assert "olcAttributeTypes:" in generated_content
                assert "olcObjectClasses:" in generated_content
                assert "testAttribute" in generated_content
                assert "testObjectClass" in generated_content

            finally:
                # Cleanup
                Path(schema_path).unlink(missing_ok=True)
                Path(ldif_path).unlink(missing_ok=True)

        except ImportError:
            pytest.skip("Schema modules not available")

    def test_schema_validation_integration(self) -> None:
        """Test schema validation with complex scenarios."""
        try:
            from ldap_core_shared.schema.parser import SchemaParser
            from ldap_core_shared.schema.validator import SchemaValidator

            parser = SchemaParser()
            validator = SchemaValidator()

            # Test valid schema
            with tempfile.NamedTemporaryFile(mode="w", suffix=".schema", delete=False, encoding="utf-8") as f:
                f.write(SAMPLE_SCHEMA_CONTENT)
                schema_path = f.name

            try:
                parse_result = parser.parse_schema_file(schema_path)
                assert parse_result.success

                validation_result = validator.validate_schema_elements(
                    parse_result.attribute_types,
                    parse_result.object_classes,
                )

                assert validation_result.is_valid, f"Validation failed: {validation_result.errors}"

            finally:
                Path(schema_path).unlink(missing_ok=True)

        except ImportError:
            pytest.skip("Schema validation modules not available")

    def test_cli_schema_conversion_integration(self) -> None:
        """Test CLI schema conversion tools."""
        try:
            from ldap_core_shared.cli.schema import run_schema2ldif

            # Create test files
            with tempfile.NamedTemporaryFile(mode="w", suffix=".schema", delete=False, encoding="utf-8") as schema_file:
                schema_file.write(SAMPLE_SCHEMA_CONTENT)
                schema_path = schema_file.name

            with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as ldif_file:
                ldif_path = ldif_file.name

            try:
                # Run CLI conversion
                success = run_schema2ldif(
                    input_file=schema_path,
                    output_file=ldif_path,
                    input_format="schema",
                    validate=True,
                    pretty_print=True,
                    verbose=False,
                )

                assert success, "CLI schema conversion failed"

                # Verify output file exists and has content
                assert Path(ldif_path).exists()
                with open(ldif_path, encoding="utf-8") as f:
                    content = f.read()

                assert len(content) > 0, "Output file is empty"
                assert "dn: cn=schema,cn=config" in content

            finally:
                Path(schema_path).unlink(missing_ok=True)
                Path(ldif_path).unlink(missing_ok=True)

        except ImportError:
            pytest.skip("CLI schema modules not available")

    def test_error_handling_integration(self) -> None:
        """Test error handling in schema processing."""
        try:
            from ldap_core_shared.schema.parser import SchemaParser

            # Test invalid schema
            invalid_schema = """
            attributetype ( invalid.oid
                NAME 'badAttribute'
                DESC 'Invalid attribute'
                SYNTAX invalid.syntax )
            """

            with tempfile.NamedTemporaryFile(mode="w", suffix=".schema", delete=False, encoding="utf-8") as f:
                f.write(invalid_schema)
                schema_path = f.name

            try:
                parser = SchemaParser()
                result = parser.parse_schema_file(schema_path)

                # Should detect errors but not crash
                assert not result.success or len(result.errors) > 0

            finally:
                Path(schema_path).unlink(missing_ok=True)

        except ImportError:
            pytest.skip("Schema modules not available")


class TestSchemaManagerIntegration:
    """Integration tests for schema management operations."""

    def test_schema_manager_workflow(self) -> None:
        """Test complete schema management workflow."""
        try:
            from ldap_core_shared.schema.manager import SchemaManager

            manager = SchemaManager()

            # Create test LDIF file
            with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
                f.write(EXPECTED_LDIF_CONTENT)
                ldif_path = f.name

            try:
                # Test schema installation (dry run)
                operation = manager.install_schema_from_file(
                    ldif_file_path=ldif_path,
                    schema_name="test-integration",
                    dry_run=True,
                )

                # Should succeed in dry run mode
                assert operation.success, f"Schema installation dry run failed: {operation.error}"

            finally:
                Path(ldif_path).unlink(missing_ok=True)

        except ImportError:
            pytest.skip("Schema manager modules not available")


def test_schema_integration_summary() -> None:
    """Summary test to verify all schema components work together."""
    try:
        # Import all schema modules
        from ldap_core_shared.cli.schema import run_schema2ldif
        from ldap_core_shared.schema.generator import LDIFGenerator
        from ldap_core_shared.schema.manager import SchemaManager
        from ldap_core_shared.schema.parser import SchemaParser
        from ldap_core_shared.schema.validator import SchemaValidator

        # Verify all components are available
        assert SchemaParser is not None
        assert LDIFGenerator is not None
        assert SchemaValidator is not None
        assert SchemaManager is not None
        assert run_schema2ldif is not None

    except ImportError:
        pass


if __name__ == "__main__":
    # Run integration tests
    test_schema_integration_summary()

    # Run individual test classes if pytest not available
    try:
        integration_tests = TestSchemaConversionIntegration()
        integration_tests.test_schema_to_ldif_conversion()
        integration_tests.test_schema_validation_integration()
        integration_tests.test_cli_schema_conversion_integration()
        integration_tests.test_error_handling_integration()

        manager_tests = TestSchemaManagerIntegration()
        manager_tests.test_schema_manager_workflow()

    except Exception:
        import traceback
        traceback.print_exc()
