"""Integration Tests for LDAP Core Shared.

This package provides integration tests for all three Perl module equivalents:
- schema2ldif-perl-converter functionality
- perl-Convert-ASN1 functionality
- perl-Authen-SASL functionality

The integration tests verify that all components work together correctly
and provide the same functionality as the original Perl modules.

Test Categories:
    - Schema conversion and management integration
    - ASN.1 encoding/decoding integration
    - SASL authentication flow integration
    - Cross-module integration scenarios
    - CLI tool integration tests
    - Enterprise workflow simulations

Test Files:
    - test_schema_integration.py: Schema conversion and management tests
    - test_asn1_integration.py: ASN.1 encoding/decoding tests
    - test_sasl_integration.py: SASL authentication flow tests
    - test_cross_module_integration.py: Complete workflow integration tests

Usage:
    python -m pytest tests/integration/
    python -m pytest tests/integration/test_schema_integration.py
    python -m pytest tests/integration/test_asn1_integration.py
    python -m pytest tests/integration/test_sasl_integration.py
    python -m pytest tests/integration/test_cross_module_integration.py

    # Run specific test categories
    python -m pytest tests/integration/ -k "schema"
    python -m pytest tests/integration/ -k "asn1"
    python -m pytest tests/integration/ -k "sasl"
    python -m pytest tests/integration/ -k "cross_module"
"""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "LDAP Core Shared Team"

# Test configuration
TEST_DATA_DIR = "tests/data"
TEMP_TEST_DIR = "/tmp/ldap-core-shared-tests"

# Export test utilities
__all__ = [
    "TEMP_TEST_DIR",
    "TEST_DATA_DIR",
]
