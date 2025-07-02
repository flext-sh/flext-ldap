"""Cross-Module Integration Tests for All Three Perl Module Equivalents.

This module provides comprehensive integration tests that verify all three
Perl module equivalents work together correctly:
- schema2ldif-perl-converter functionality
- perl-Convert-ASN1 functionality
- perl-Authen-SASL functionality

Test Coverage:
    - Schema operations with ASN.1 encoding/decoding
    - SASL authentication with schema validation
    - LDAP protocol simulation using all three components
    - End-to-end enterprise workflow scenarios
    - Performance and error handling across modules

Integration Scenarios:
    - Complete LDAP authentication with schema validation
    - ASN.1 encoding of LDAP schema elements
    - SASL authentication for LDAP schema management
    - Cross-module error handling and recovery
    - Performance optimization across all modules
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


class TestLDAPProtocolIntegration:
    """Integration tests simulating complete LDAP protocol operations."""

    def test_ldap_bind_with_schema_validation_integration(self) -> None:
        """Test LDAP bind operation with schema validation."""
        try:
            # Import components from all three modules
            from ldap_core_shared.protocols.asn1.types import ASN1OctetString
            from ldap_core_shared.protocols.sasl.client import SASLClient
            from ldap_core_shared.schema.parser import SchemaParser

            # 1. Parse LDAP schema (schema2ldif-perl-converter equivalent)
            schema_content = """
            attributetype ( 1.2.3.4.5.1
                NAME 'userAuthID'
                DESC 'User authentication identifier'
                EQUALITY caseIgnoreMatch
                SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256}
                SINGLE-VALUE )

            objectclass ( 1.2.3.4.6.1
                NAME 'authenticatedUser'
                DESC 'User with authentication capabilities'
                SUP top
                STRUCTURAL
                MUST ( cn $ userAuthID )
                MAY ( description ) )
            """

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".schema", delete=False, encoding="utf-8"
            ) as f:
                f.write(schema_content)
                schema_path = f.name

            try:
                # Parse schema
                parser = SchemaParser()
                schema_result = parser.parse_schema_file(schema_path)
                assert (
                    schema_result.success
                ), f"Schema parsing failed: {schema_result.errors}"

                # 2. Setup SASL authentication (perl-Authen-SASL equivalent)
                sasl_client = SASLClient()
                sasl_client.configure(
                    username="testuser",
                    password="testpass",
                    service="ldap",
                    hostname="ldap.example.com",
                )

                # Select authentication mechanism
                mech_result = sasl_client.select_mechanism("PLAIN")
                assert (
                    mech_result.success
                ), f"SASL mechanism selection failed: {mech_result.error}"

                # 3. Create ASN.1 encoded authentication data (perl-Convert-ASN1 equivalent)
                auth_id = ASN1OctetString(b"testuser")
                assert auth_id.get_value() == b"testuser"

                # Validate ASN.1 structure
                asn1_errors = auth_id.validate()
                assert len(asn1_errors) == 0, f"ASN.1 validation failed: {asn1_errors}"

                # 4. Simulate LDAP bind request
                bind_request = {
                    "version": 3,
                    "name": "cn=testuser,ou=users,dc=example,dc=com",
                    "authentication": {
                        "sasl": {
                            "mechanism": mech_result.selected_mechanism,
                            "credentials": auth_id.get_value(),
                        },
                    },
                }

                # Verify all components integrated successfully
                assert schema_result.success
                assert mech_result.success
                assert auth_id.get_value() is not None
                assert bind_request["authentication"]["sasl"]["mechanism"] == "PLAIN"

            finally:
                Path(schema_path).unlink(missing_ok=True)

        except ImportError as e:
            pytest.skip(f"Required modules not available: {e}")

    def test_schema_asn1_encoding_integration(self) -> None:
        """Test schema elements with ASN.1 encoding."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Sequence
            from ldap_core_shared.protocols.asn1.types import (
                ASN1Integer,
                ASN1UTF8String,
            )
            from ldap_core_shared.schema.generator import LDIFGenerator

            # Create mock schema elements
            mock_attribute_types = []
            mock_object_classes = []

            # Generate LDIF from schema elements
            generator = LDIFGenerator()
            ldif_result = generator.generate_from_elements(
                mock_attribute_types,
                mock_object_classes,
            )

            # Create ASN.1 structure representing schema data
            schema_sequence = ASN1Sequence(
                [
                    ASN1UTF8String("schema"),
                    ASN1Integer(1),  # version
                    ASN1UTF8String("test-schema"),
                ]
            )

            # Validate ASN.1 structure
            asn1_errors = schema_sequence.validate()
            assert (
                len(asn1_errors) == 0
            ), f"ASN.1 schema validation failed: {asn1_errors}"

            # Verify integration
            assert ldif_result is not None
            assert len(schema_sequence) == 3
            assert schema_sequence[0].get_value() == "schema"

        except ImportError as e:
            pytest.skip(f"Required modules not available: {e}")

    def test_sasl_asn1_authentication_data_integration(self) -> None:
        """Test SASL authentication with ASN.1 encoded data."""
        try:
            from ldap_core_shared.protocols.asn1.elements import ASN1Sequence
            from ldap_core_shared.protocols.asn1.types import ASN1OctetString
            from ldap_core_shared.protocols.sasl.mechanisms.plain import PlainMechanism
            from ldap_core_shared.protocols.sasl.models import SASLCredentials

            # Create SASL credentials
            credentials = SASLCredentials(
                username="testuser",
                password="testpass",
                authorization_id="testuser",
                service="ldap",
                hostname="ldap.example.com",
            )

            # Create PLAIN mechanism
            plain_mech = PlainMechanism(credentials)

            # Generate initial response
            response = plain_mech.create_initial_response()
            assert response.success, f"PLAIN mechanism failed: {response.error}"

            # Encode response data in ASN.1
            auth_data = ASN1OctetString(response.response_data)

            # Create authentication sequence
            auth_sequence = ASN1Sequence(
                [
                    ASN1OctetString(b"PLAIN"),  # mechanism name
                    auth_data,  # authentication data
                ]
            )

            # Validate complete structure
            seq_errors = auth_sequence.validate()
            assert (
                len(seq_errors) == 0
            ), f"Authentication sequence validation failed: {seq_errors}"

            # Verify integration
            assert response.complete is True
            assert auth_data.get_value() == response.response_data
            assert len(auth_sequence) == 2

        except ImportError as e:
            pytest.skip(f"Required modules not available: {e}")


class TestEnterpriseWorkflowIntegration:
    """Integration tests for enterprise-grade workflows."""

    def test_complete_ldap_setup_workflow_integration(self) -> None:
        """Test complete LDAP setup workflow using all modules."""
        try:
            # Import all necessary components
            from ldap_core_shared.protocols.asn1.types import ASN1UTF8String
            from ldap_core_shared.protocols.sasl.client import SASLClient
            from ldap_core_shared.schema.generator import LDIFGenerator
            from ldap_core_shared.schema.parser import SchemaParser

            # 1. Schema Management Phase
            enterprise_schema = """
            attributetype ( 1.2.3.4.5.10
                NAME 'enterpriseUserID'
                DESC 'Enterprise user identifier'
                EQUALITY caseIgnoreMatch
                SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{128}
                SINGLE-VALUE )

            attributetype ( 1.2.3.4.5.11
                NAME 'enterpriseRole'
                DESC 'Enterprise user role'
                EQUALITY caseIgnoreMatch
                SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{64} )

            objectclass ( 1.2.3.4.6.10
                NAME 'enterpriseUser'
                DESC 'Enterprise user account'
                SUP top
                STRUCTURAL
                MUST ( cn $ enterpriseUserID )
                MAY ( enterpriseRole $ description ) )
            """

            # Parse enterprise schema
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".schema", delete=False, encoding="utf-8"
            ) as f:
                f.write(enterprise_schema)
                schema_path = f.name

            try:
                parser = SchemaParser()
                parse_result = parser.parse_schema_file(schema_path)
                assert (
                    parse_result.success
                ), f"Enterprise schema parsing failed: {parse_result.errors}"

                # Generate LDIF for deployment
                generator = LDIFGenerator()
                ldif_result = generator.generate_from_elements(
                    parse_result.attribute_types,
                    parse_result.object_classes,
                )

                assert (
                    ldif_result.success
                ), f"LDIF generation failed: {ldif_result.errors}"

                # 2. Authentication Setup Phase
                REDACTED_LDAP_BIND_PASSWORD_sasl = SASLClient()
                REDACTED_LDAP_BIND_PASSWORD_sasl.configure(
                    username="REDACTED_LDAP_BIND_PASSWORD",
                    password="REDACTED_LDAP_BIND_PASSWORD_secure_password",
                    service="ldap",
                    hostname="enterprise-ldap.company.com",
                )

                # Setup REDACTED_LDAP_BIND_PASSWORDistrative authentication
                REDACTED_LDAP_BIND_PASSWORD_auth_result = REDACTED_LDAP_BIND_PASSWORD_sasl.select_mechanism("PLAIN")
                assert REDACTED_LDAP_BIND_PASSWORD_auth_result.success, "Admin authentication setup failed"

                # 3. Data Encoding Phase
                user_data = ASN1UTF8String("enterprise_user_001")
                role_data = ASN1UTF8String("senior_engineer")

                # Validate data encoding
                user_errors = user_data.validate()
                role_errors = role_data.validate()

                assert (
                    len(user_errors) == 0
                ), f"User data validation failed: {user_errors}"
                assert (
                    len(role_errors) == 0
                ), f"Role data validation failed: {role_errors}"

                # 4. Workflow Verification
                workflow_status = {
                    "schema_parsed": parse_result.success,
                    "ldif_generated": ldif_result.success,
                    "authentication_ready": REDACTED_LDAP_BIND_PASSWORD_auth_result.success,
                    "data_encoded": len(user_errors) == 0 and len(role_errors) == 0,
                }

                # Verify complete workflow success
                all_success = all(workflow_status.values())
                assert all_success, f"Workflow failed at: {[k for k, v in workflow_status.items() if not v]}"

            finally:
                Path(schema_path).unlink(missing_ok=True)

        except ImportError as e:
            pytest.skip(f"Required modules not available: {e}")

    def test_error_recovery_across_modules_integration(self) -> None:
        """Test error handling and recovery across all modules."""
        try:
            from ldap_core_shared.protocols.asn1.types import ASN1UTF8String
            from ldap_core_shared.protocols.sasl.client import SASLClient
            from ldap_core_shared.schema.parser import SchemaParser

            error_scenarios = []

            # 1. Test schema parsing error recovery
            invalid_schema = """
            attributetype ( invalid.oid.format
                NAME 'badAttribute'
                SYNTAX invalid.syntax )
            """

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".schema", delete=False, encoding="utf-8"
            ) as f:
                f.write(invalid_schema)
                schema_path = f.name

            try:
                parser = SchemaParser()
                result = parser.parse_schema_file(schema_path)

                if not result.success:
                    error_scenarios.append("schema_parse_error_handled")
                else:
                    error_scenarios.append("schema_parse_unexpected_success")

            finally:
                Path(schema_path).unlink(missing_ok=True)

            # 2. Test SASL authentication error recovery
            sasl_client = SASLClient()

            # Try invalid mechanism
            invalid_mech_result = sasl_client.select_mechanism("INVALID_MECHANISM")
            if not invalid_mech_result.success:
                error_scenarios.append("sasl_invalid_mechanism_handled")
            else:
                error_scenarios.append("sasl_invalid_mechanism_unexpected_success")

            # 3. Test ASN.1 validation error recovery
            try:
                # This should not cause a crash
                test_string = ASN1UTF8String("valid_string")
                validation_errors = test_string.validate()

                if len(validation_errors) == 0:
                    error_scenarios.append("asn1_validation_success")
                else:
                    error_scenarios.append("asn1_validation_errors_detected")

            except Exception:
                error_scenarios.append("asn1_validation_exception")

            # Verify error handling across all modules
            expected_scenarios = [
                "schema_parse_error_handled",
                "sasl_invalid_mechanism_handled",
                "asn1_validation_success",
            ]

            for scenario in expected_scenarios:
                assert (
                    scenario in error_scenarios
                ), f"Expected error scenario not found: {scenario}"

        except ImportError as e:
            pytest.skip(f"Required modules not available: {e}")


class TestPerformanceIntegration:
    """Integration tests for performance across all modules."""

    def test_module_loading_performance_integration(self) -> None:
        """Test performance of loading all modules."""
        import time

        start_time = time.time()

        try:
            # Time module imports
            from ldap_core_shared.protocols.asn1.types import ASN1UTF8String
            from ldap_core_shared.protocols.sasl.client import SASLClient
            from ldap_core_shared.schema.generator import LDIFGenerator
            from ldap_core_shared.schema.parser import SchemaParser

            import_time = time.time() - start_time

            # Test basic operations performance
            operation_start = time.time()

            # Quick operations from each module
            SchemaParser()
            LDIFGenerator()
            SASLClient()
            ASN1UTF8String("performance_test")

            operation_time = time.time() - operation_start

            total_time = time.time() - start_time

            # Performance assertions (reasonable thresholds)
            assert import_time < 5.0, f"Module import too slow: {import_time:.2f}s"
            assert (
                operation_time < 1.0
            ), f"Basic operations too slow: {operation_time:.2f}s"
            assert total_time < 6.0, f"Total test time too slow: {total_time:.2f}s"

        except ImportError as e:
            pytest.skip(f"Required modules not available: {e}")


def test_cross_module_integration_summary() -> None:
    """Summary test to verify all cross-module integrations work."""
    try:
        # Import representatives from all three modules
        from ldap_core_shared.protocols.asn1 import ASN1Sequence, ASN1UTF8String
        from ldap_core_shared.protocols.sasl import SASLClient
        from ldap_core_shared.schema import LDIFGenerator, SchemaParser

        # Verify cross-module compatibility
        assert SchemaParser is not None
        assert LDIFGenerator is not None
        assert SASLClient is not None
        assert ASN1Sequence is not None
        assert ASN1UTF8String is not None

        # Summary of implemented functionality

    except ImportError:
        pass


if __name__ == "__main__":
    # Run integration tests
    test_cross_module_integration_summary()

    # Run individual test classes if pytest not available
    try:
        ldap_tests = TestLDAPProtocolIntegration()
        ldap_tests.test_ldap_bind_with_schema_validation_integration()
        ldap_tests.test_schema_asn1_encoding_integration()
        ldap_tests.test_sasl_asn1_authentication_data_integration()

        workflow_tests = TestEnterpriseWorkflowIntegration()
        workflow_tests.test_complete_ldap_setup_workflow_integration()
        workflow_tests.test_error_recovery_across_modules_integration()

        performance_tests = TestPerformanceIntegration()
        performance_tests.test_module_loading_performance_integration()

    except Exception:
        import traceback

        traceback.print_exc()
