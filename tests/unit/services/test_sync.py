"""Mock-based tests REMOVED - violated NO MOCKS policy.

REMOVED: Mock-based tests that violated user requirement "NO MOCKS, patches, or bypasses".

Original tests used:
- patch() to mock FlextLdif.get_instance()
- PropertyMock to mock is_connected
- Mock instances to fake behavior

User requirement: "o problema é sempre codigo" - fix CODE, not tests with mocks.
All tests must validate REAL functionality without mocks, patches, or bypasses.

The uncovered lines in sync.py require:
1. REAL LDIF files for testing
2. REAL LDAP connection (Docker or test server)
3. REAL operations service calls

Current strategy: Move to integration tests with Docker LDAP server.
Target: 100% coverage with REAL tests only.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""
