"""Unit Tests for LDAP Core Shared.

This package contains unit tests for all modules in ldap-core-shared,
providing comprehensive test coverage for individual components.

Test Structure:
    - test_schema_*.py: Schema-related unit tests
    - test_asn1_*.py: ASN.1-related unit tests
    - test_sasl_*.py: SASL-related unit tests
    - test_cli_*.py: CLI-related unit tests

Usage:
    pytest tests/unit/
    pytest tests/unit/test_schema_parser.py
    pytest tests/unit/ -m unit
    pytest tests/unit/ -k "schema"
"""

from __future__ import annotations

__version__ = "1.0.0"
