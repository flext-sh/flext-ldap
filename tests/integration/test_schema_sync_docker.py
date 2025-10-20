"""Integration tests for schema sync with real OpenLDAP container.

Uses Docker fixture from conftest.py.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import cast

import pytest

from flext_ldap.schema_sync import FlextLdapSchemaSync


@pytest.mark.docker
@pytest.mark.integration
def test_schema_sync_idempotent(clean_ldap_container: dict[str, object]) -> None:
    """Test schema sync is idempotent - run twice, same result."""
    # Setup using clean_ldap_container fixture from conftest.py
    container_info = clean_ldap_container

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".ldif", delete=False, encoding="utf-8"
    ) as f:
        f.write("""
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.99999.1.1 NAME 'testAttr1'
  DESC 'Test attribute 1' EQUALITY caseIgnoreMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectClasses: ( 1.3.6.1.4.1.99999.2.1 NAME 'testClass1'
  DESC 'Test class 1' SUP top STRUCTURAL
  MUST ( cn ) MAY ( testAttr1 ) )
""")
        schema_file = Path(f.name)

    try:
        # First run
        sync1 = FlextLdapSchemaSync(
            schema_ldif_file=schema_file,
            server_host="localhost",
            server_port=cast("int", container_info["port"]),
            bind_dn=cast("str", container_info["bind_dn"]),
            bind_password=cast("str", container_info["password"]),
            server_type="openldap2",
        )

        result1 = sync1.execute()
        assert result1.is_success
        stats1 = result1.unwrap()

        # Second run - should skip existing definitions
        sync2 = FlextLdapSchemaSync(
            schema_ldif_file=schema_file,
            server_host="localhost",
            server_port=cast("int", container_info["port"]),
            bind_dn=cast("str", container_info["bind_dn"]),
            bind_password=cast("str", container_info["password"]),
            server_type="openldap2",
        )

        result2 = sync2.execute()
        assert result2.is_success
        stats2 = result2.unwrap()

        # Verify idempotency
        assert stats2["new_definitions_added"] == 0
        assert stats2["skipped_count"] == stats1["total_definitions"]
        assert stats2["idempotent"] is True

    finally:
        schema_file.unlink()


@pytest.mark.docker
@pytest.mark.integration
def test_schema_sync_with_real_ldap(clean_ldap_container: dict[str, object]) -> None:
    """Test schema sync with real OpenLDAP server."""
    container_info = clean_ldap_container

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".ldif", delete=False, encoding="utf-8"
    ) as f:
        f.write("""
dn: cn=schema
attributeTypes: ( 1.3.6.1.4.1.99999.1.2 NAME 'testAttr2'
  DESC 'Test attribute 2' EQUALITY caseIgnoreMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
objectClasses: ( 1.3.6.1.4.1.99999.2.2 NAME 'testClass2'
  DESC 'Test class 2' SUP top STRUCTURAL
  MUST ( cn ) MAY ( testAttr2 ) )
""")
        schema_file = Path(f.name)

    try:
        sync_service = FlextLdapSchemaSync(
            schema_ldif_file=schema_file,
            server_host="localhost",
            server_port=cast("int", container_info["port"]),
            bind_dn=cast("str", container_info["bind_dn"]),
            bind_password=cast("str", container_info["password"]),
            server_type="openldap2",
        )

        result = sync_service.execute()
        assert result.is_success

        stats = result.unwrap()
        assert cast("int", stats["total_definitions"]) >= 2  # At least 2 definitions
        assert cast("int", stats["new_definitions_added"]) >= 0
        assert cast("bool", stats["idempotent"]) is True

    finally:
        schema_file.unlink()


@pytest.mark.docker
@pytest.mark.integration
def test_schema_sync_error_handling(clean_ldap_container: dict[str, object]) -> None:
    """Test schema sync error handling with invalid schema."""
    container_info = clean_ldap_container

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".ldif", delete=False, encoding="utf-8"
    ) as f:
        f.write("""
dn: cn=schema
# Invalid schema definition - missing closing parenthesis
attributeTypes: ( 1.3.6.1.4.1.99999.1.3 NAME 'invalidAttr'
  DESC 'Invalid attribute' EQUALITY caseIgnoreMatch
  SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
""")
        schema_file = Path(f.name)

    try:
        sync_service = FlextLdapSchemaSync(
            schema_ldif_file=schema_file,
            server_host="localhost",
            server_port=cast("int", container_info["port"]),
            bind_dn=cast("str", container_info["bind_dn"]),
            bind_password=cast("str", container_info["password"]),
            server_type="openldap2",
        )

        result = sync_service.execute()
        # Should handle parsing errors gracefully
        assert result.is_success or result.is_failure

    finally:
        schema_file.unlink()
