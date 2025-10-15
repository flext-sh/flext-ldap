#!/usr/bin/env python3
"""LDIF Operations Example - flext-ldap API.

This example demonstrates LDIF import/export functionality:
- Import entries from LDIF files (import_from_ldif)
- Export entries to LDIF files (export_to_ldif)
- FlextLdif integration and entry conversion
- Entry adapter pattern for ldap3 ↔ FlextLdif conversion
- Working with FlextLdif.Entry models
- Entry format conversion between LDAP servers
- Server type detection from entry attributes
- Entry normalization for target servers
- Entry validation for server compatibility
- Server-specific attribute information

Uses ONLY api.py (FlextLdap) as the primary interface.
Demonstrates entry_adapter.py (FlextLdapEntryAdapter) functionality.

Requirements:
    - flext-ldif must be installed: pip install flext-ldif

Environment Variables:
    LDAP_SERVER_URI: LDAP server URI (default: ldap://localhost:389)
    LDAP_BIND_DN: Bind DN (default: cn=admin,dc=example,dc=com)
    LDAP_BIND_PASSWORD: Bind password (default: admin)
    LDAP_BASE_DN: Base DN (default: dc=example,dc=com)

Example:
    python examples/04_ldif_operations.py

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
from pathlib import Path
from typing import Final

from flext_core import FlextCore
from flext_ldif import FlextLdifModels
from pydantic import SecretStr

from flext_ldap.api import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels

logger: FlextCore.Logger = FlextCore.Logger(__name__)

LDAP_URI: Final[str] = os.getenv("LDAP_SERVER_URI", "ldap://localhost:3390")
BIND_DN: Final[str] = os.getenv("LDAP_BIND_DN", "cn=admin,dc=example,dc=com")
BIND_PASSWORD: Final[SecretStr] = SecretStr(os.getenv("LDAP_BIND_PASSWORD", "admin"))
BASE_DN: Final[str] = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")


def setup_api() -> FlextLdap | None:
    """Setup and connect FlextLdap API.

    Returns:
        Connected FlextLdap instance or None if connection failed.

    """
    FlextLdapConfig(
        ldap_server_uri=LDAP_URI,
        ldap_bind_dn=BIND_DN,
        ldap_bind_password=BIND_PASSWORD,
        ldap_base_dn=BASE_DN,
    )
    api = FlextLdap()

    # Use context manager for automatic connection/disconnection
    try:
        with api:
            return api
    except Exception:
        logger.exception("Connection failed")
        return None


def create_sample_ldif_file() -> Path:
    """Create a sample LDIF file for testing.

    Returns:
        Path to the created LDIF file.

    """
    logger.info("=== Creating Sample LDIF File ===")

    # Create temporary LDIF file
    temp_dir = tempfile.gettempdir()
    ldif_path = Path(temp_dir) / "sample_users.ldif"

    # Sample LDIF content
    ldif_content = f"""# Sample LDIF file for flext-ldap testing
# Created by flext-ldap examples

dn: ou=users,{BASE_DN}
objectClass: organizationalUnit
ou: users
description: User accounts

dn: cn=john.doe,ou=users,{BASE_DN}
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: john.doe
sn: Doe
givenName: John
mail: john.doe@example.com
uid: john.doe
description: Sample user from LDIF import

dn: cn=jane.smith,ou=users,{BASE_DN}
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: jane.smith
sn: Smith
givenName: Jane
mail: jane.smith@example.com
uid: jane.smith
description: Another sample user from LDIF import
"""

    # Write LDIF file
    ldif_path.write_text(ldif_content, encoding="utf-8")
    logger.info(f"✅ Sample LDIF file created: {ldif_path}")
    logger.info("   Entries: 3 (1 OU + 2 users)")

    return ldif_path


def demonstrate_ldif_import(
    api: FlextLdap, ldif_path: Path
) -> list[FlextLdapModels.Entry] | None:
    """Demonstrate importing entries from LDIF file.

    Args:
        api: Connected FlextLdap instance
        ldif_path: Path to LDIF file

    Returns:
        List of imported entries or None if import failed.

    """
    logger.info("\n=== LDIF Import Operations ===")

    logger.info(f"Importing entries from: {ldif_path}")

    # Import entries from LDIF
    result: FlextCore.Result[list[FlextLdapModels.Entry]] = api.import_from_ldif(
        ldif_path
    )

    if result.is_failure:
        logger.error(f"❌ LDIF import failed: {result.error}")
        return None

    entries = result.unwrap()
    logger.info(f"✅ Imported {len(entries)} entries from LDIF")

    # Display imported entries
    for i, entry in enumerate(entries, 1):
        logger.info(f"   {i}. DN: {entry.dn}")
        logger.info(f"      Attributes: {list(entry.attributes.keys())}")

        # Show object classes
        object_classes = entry.attributes.get("objectClass", [])
        if object_classes:
            logger.info(f"      Object Classes: {object_classes}")

    return entries


def demonstrate_ldif_export(api: FlextLdap) -> Path | None:
    """Demonstrate exporting entries to LDIF file.

    Args:
        api: Connected FlextLdap instance

    Returns:
        Path to exported LDIF file or None if export failed.

    """
    logger.info("\n=== LDIF Export Operations ===")

    # Search for entries to export
    logger.info("Searching for entries to export...")
    search_request = FlextLdapModels.SearchRequest.create(
        base_dn=BASE_DN,
        filter_str="(objectClass=person)",
        attributes=["cn", "sn", "mail", "uid", "objectClass"],
    )
    search_result = api.search(search_request)

    if search_result.is_failure:
        logger.error(f"❌ Search failed: {search_result.error}")
        return None

    entries = search_result.unwrap()
    if not entries:
        logger.warning("⚠️  No entries found to export")
        return None

    logger.info(f"Found {len(entries)} entries to export")

    # Create export file path
    temp_dir = tempfile.gettempdir()
    export_path = Path(temp_dir) / "exported_users.ldif"

    # Export entries to LDIF
    logger.info(f"Exporting to: {export_path}")
    export_result: FlextCore.Result[bool] = api.export_to_ldif(entries, export_path)

    if export_result.is_failure:
        logger.error(f"❌ LDIF export failed: {export_result.error}")
        return None

    logger.info(f"✅ Exported {len(entries)} entries to LDIF")
    logger.info(f"   File size: {export_path.stat().st_size} bytes")

    # Show first few lines of exported file
    logger.info("   First 10 lines of exported LDIF:")
    with export_path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if i > 10:
                break
            logger.info(f"      {line.rstrip()}")

    return export_path


def demonstrate_entry_conversion() -> None:
    """Demonstrate FlextLdap.Entry model usage (no connection needed)."""
    logger.info("\n=== Entry Model Conversion ===")

    # Create Entry model manually
    logger.info("Creating FlextLdapModels.Entry manually:")
    entry = FlextLdapModels.Entry(
        dn="cn=test.user,ou=users,dc=example,dc=com",
        attributes={
            "objectClass": ["person", "organizationalPerson", "inetOrgPerson"],
            "cn": ["test.user"],
            "sn": ["User"],
            "givenName": ["Test"],
            "mail": ["test.user@example.com"],
            "uid": ["test.user"],
        },
    )

    logger.info("✅ Entry created:")
    logger.info(f"   DN: {entry.dn}")
    logger.info(f"   Attributes: {list(entry.attributes.keys())}")

    # Access specific attributes
    logger.info("\nAccessing attributes:")
    cn = entry.attributes.get("cn", ["N/A"])[0]
    mail = entry.attributes.get("mail", ["N/A"])[0]
    object_classes = entry.attributes.get("objectClass", [])

    logger.info(f"   CN: {cn}")
    logger.info(f"   Mail: {mail}")
    logger.info(f"   Object Classes: {', '.join(object_classes)}")


def demonstrate_ldif_round_trip(api: FlextLdap) -> None:
    """Demonstrate complete LDIF round-trip (import → modify → export).

    Args:
        api: Connected FlextLdap instance

    """
    logger.info("\n=== LDIF Round-Trip Operations ===")

    # Step 1: Create and import from LDIF
    logger.info("Step 1: Creating sample LDIF file...")
    ldif_path = create_sample_ldif_file()

    logger.info("Step 2: Importing entries from LDIF...")
    entries = demonstrate_ldif_import(api, ldif_path)

    if not entries:
        logger.error("Round-trip aborted: Import failed")
        return

    # Step 3: Modify entries (simulate processing)
    logger.info("Step 3: Modifying imported entries...")
    for entry in entries:
        # Add a processed marker
        entry.attributes["description"] = [f"Processed by flext-ldap at {Path.cwd()}"]

    logger.info(f"✅ Modified {len(entries)} entries")

    # Step 4: Export modified entries
    logger.info("Step 4: Exporting modified entries...")
    temp_dir = tempfile.gettempdir()
    output_path = Path(temp_dir) / "round_trip_output.ldif"

    export_result = api.export_to_ldif(entries, output_path)

    if export_result.is_success:
        logger.info("✅ Round-trip completed successfully!")
        logger.info(f"   Output file: {output_path}")
        logger.info(f"   File size: {output_path.stat().st_size} bytes")
    else:
        logger.error(f"❌ Export failed: {export_result.error}")

    # Cleanup
    try:
        ldif_path.unlink()
        logger.info(f"Cleaned up temporary file: {ldif_path}")
    except Exception as e:
        logger.warning(f"Failed to cleanup {ldif_path}: {e}")


def demonstrate_ldif_availability(api: FlextLdap) -> bool:
    """Check if FlextLdif is available.

    Args:
        api: FlextLdap instance

    Returns:
        True if FlextLdif is available, False otherwise.

    """
    logger.info("\n=== FlextLdif Availability Check ===")

    # Check if ldif property is available
    ldif_instance = api.ldif

    if ldif_instance is None:
        logger.error("❌ FlextLdif not available")
        logger.error("   Install with: pip install flext-ldif")
        return False

    logger.info("✅ FlextLdif is available and initialized")
    return True


def demonstrate_entry_adapter_conversion(api: FlextLdap) -> None:
    """Demonstrate entry adapter format conversion between servers.

    Args:
        api: FlextLdap instance

    """
    logger.info("\n=== Entry Adapter Format Conversion ===")

    logger.info("\n1. Creating sample entry with server-specific attributes:")

    # Create entry with OpenLDAP 2.x specific attributes
    openldap_entry: FlextLdifModels.Entry = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=config,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "objectClass": FlextLdifModels.AttributeValues(
                    values=["olcGlobal", "top"]
                ),
                "olcAccess": FlextLdifModels.AttributeValues(
                    values=["to * by * read"]
                ),  # OpenLDAP 2.x ACL format
                "olcLogLevel": FlextLdifModels.AttributeValues(values=["stats"]),
            }
        ),
        version=1,
    )

    logger.info("   ✅ OpenLDAP 2.x entry created")
    logger.info(
        f"      Attributes: {list(openldap_entry.attributes.attributes.keys())}"
    )

    logger.info("\n2. Converting to Oracle OUD format:")

    # Convert LDIF entry to LDAP entry first
    ldap_entry = FlextLdapModels.Entry.from_ldif(openldap_entry)

    # Use entry adapter to convert between server formats
    result = api.convert_entry_between_servers(
        entry=ldap_entry,
        source_server_type="openldap2",
        target_server_type="oud",
    )

    if result.is_success:
        oud_entry = result.unwrap()
        logger.info("   ✅ Conversion successful")
        logger.info(f"      Target attributes: {list(oud_entry.attributes.keys())}")
        logger.info("      Note: Server-specific attributes adapted")
    else:
        logger.warning(f"   ⚠️  Conversion: {result.error}")


def demonstrate_entry_server_detection(api: FlextLdap) -> None:
    """Demonstrate server type detection from entry attributes.

    Args:
        api: FlextLdap instance

    """
    logger.info("\n=== Entry Server Type Detection ===")

    # Test entries with server-specific attributes
    test_cases: list[dict[str, str | FlextLdifModels.Entry]] = [
        {
            "name": "OpenLDAP 2.x entry",
            "entry": FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=config"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["olcGlobal"]
                        ),
                        "olcAccess": FlextLdifModels.AttributeValues(
                            values=["to * by * read"]
                        ),
                    }
                ),
                version=1,
            ),
            "expected": "openldap2",
        },
        {
            "name": "Oracle OID entry",
            "entry": FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                        "orclaci": FlextLdifModels.AttributeValues(
                            values=["access to entry by * (read)"]
                        ),
                    }
                ),
                version="1",
                created_at=None,
                updated_at=None,
            ),
            "expected": "oid",
        },
        {
            "name": "389 DS entry",
            "entry": FlextLdifModels.Entry(
                dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
                attributes=FlextLdifModels.LdifAttributes(
                    attributes={
                        "objectClass": FlextLdifModels.AttributeValues(
                            values=["person"]
                        ),
                        "aci": FlextLdifModels.AttributeValues(
                            values=['(targetattr="*")(version 3.0; acl "test";)']
                        ),
                    }
                ),
                version="1",
                created_at=None,
                updated_at=None,
            ),
            "expected": "389ds",
        },
    ]

    logger.info("\n1. Detecting server types from entries:")

    for test_case in test_cases:
        logger.info(f"\n   Testing: {test_case['name']}")

        entry = test_case["entry"]
        if isinstance(entry, str):
            logger.warning(f"   ⚠️  Skipping string entry: {entry}")
            continue
        # entry is now guaranteed to be FlextLdifModels.Entry
        # Convert to LDAP entry for server type detection
        ldap_entry = FlextLdapModels.Entry.from_ldif(entry)
        result = api.detect_entry_server_type(ldap_entry)

        if result.is_success:
            detected = result.unwrap()
            logger.info(f"   ✅ Detected: {detected}")
            if detected == test_case["expected"]:
                logger.info("      Matches expected server type")
            else:
                logger.info(f"      Expected: {test_case['expected']}")
        else:
            logger.warning(f"   ⚠️  Detection failed: {result.error}")


def demonstrate_entry_normalization(api: FlextLdap) -> None:
    """Demonstrate entry normalization for target servers.

    Args:
        api: FlextLdap instance

    """
    logger.info("\n=== Entry Normalization for Servers ===")
    logger.info("\n1. Creating entry with mixed attributes:")

    # Create entry that might need normalization
    mixed_entry: FlextLdifModels.Entry = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(
            value="cn=user,ou=users,dc=example,dc=com"
        ),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "objectClass": FlextLdifModels.AttributeValues(
                    values=["person", "inetOrgPerson"]
                ),
                "cn": FlextLdifModels.AttributeValues(values=["user"]),
                "sn": FlextLdifModels.AttributeValues(values=["User"]),
                "mail": FlextLdifModels.AttributeValues(values=["user@example.com"]),
                # Some attributes might need normalization
                "userPassword": FlextLdifModels.AttributeValues(
                    values=["{SSHA}encryptedpassword"]
                ),
            }
        ),
        version=1,
    )

    logger.info("   ✅ Entry created with attributes:")
    logger.info(f"      {list(mixed_entry.attributes.attributes.keys())}")

    logger.info("\n2. Normalizing for current server:")
    # Convert LDIF entry to LDAP entry for normalization
    ldap_entry = FlextLdapModels.Entry.from_ldif(mixed_entry)
    result = api.normalize_entry_for_server(ldap_entry)

    if result.is_success:
        normalized = result.unwrap()
        logger.info("   ✅ Normalization successful")
        logger.info(f"      Normalized DN: {normalized.dn}")
        logger.info(f"      Attributes: {list(normalized.attributes.keys())}")
        logger.info("      Entry is ready for LDAP operations")
    else:
        logger.warning(f"   ⚠️  Normalization: {result.error}")


def demonstrate_entry_validation(api: FlextLdap) -> None:
    """Demonstrate entry validation for target servers.

    Args:
        api: FlextLdap instance

    """
    logger.info("\n=== Entry Validation for Servers ===")
    logger.info("\n1. Validating compatible entry:")

    # Create valid entry
    valid_entry: FlextLdifModels.Entry = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=valid,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "objectClass": FlextLdifModels.AttributeValues(
                    values=["person", "top"]
                ),
                "cn": FlextLdifModels.AttributeValues(values=["valid"]),
                "sn": FlextLdifModels.AttributeValues(values=["User"]),
            }
        ),
        version=1,
    )

    # Convert LDIF entry to LDAP entry for validation
    ldap_entry = FlextLdapModels.Entry.from_ldif(valid_entry)
    result = api.validate_entry_for_server(ldap_entry)

    if result.is_success:
        is_valid = result.unwrap()
        if is_valid:
            logger.info("   ✅ Entry is valid for current server")
        else:
            logger.warning("   ⚠️  Entry validation failed (incompatible)")
    else:
        logger.warning(f"   ⚠️  Validation error: {result.error}")

    logger.info("\n2. Validating entry with server-specific attributes:")

    # Create entry with potentially incompatible attributes
    specific_entry: FlextLdifModels.Entry = FlextLdifModels.Entry(
        dn=FlextLdifModels.DistinguishedName(value="cn=specific,dc=example,dc=com"),
        attributes=FlextLdifModels.LdifAttributes(
            attributes={
                "objectClass": FlextLdifModels.AttributeValues(values=["person"]),
                "cn": FlextLdifModels.AttributeValues(values=["specific"]),
                "sn": FlextLdifModels.AttributeValues(values=["User"]),
                "olcAccess": FlextLdifModels.AttributeValues(
                    values=["to * by * read"]
                ),  # OpenLDAP-specific
            }
        ),
        version=1,
    )

    # Convert LDIF entry to LDAP entry for validation
    ldap_entry = FlextLdapModels.Entry.from_ldif(specific_entry)
    result = api.validate_entry_for_server(ldap_entry)

    if result.is_success:
        is_valid = result.unwrap()
        if is_valid:
            logger.info("   ✅ Entry compatible with current server")
        else:
            logger.info("   INFO Entry may contain server-specific attributes")
    else:
        logger.info(f"   INFO Validation note: {result.error}")


def demonstrate_server_specific_attributes(api: FlextLdap) -> None:
    """Demonstrate server-specific attribute information.

    Args:
        api: FlextLdap instance

    """
    logger.info("\n=== Server-Specific Attributes ===")

    logger.info("\n1. Getting server-specific attributes:")

    result = api.get_server_specific_attributes()

    if result.is_success:
        attributes = result.unwrap()
        logger.info("   ✅ Server-specific attributes retrieved:")

        # Display attribute information - ServerAttributes is a Pydantic model
        attrs_dict = (
            attributes.model_dump()
            if hasattr(attributes, "model_dump")
            else dict(attributes)
        )
        attr_items = list(attrs_dict.items())[:5]  # Show first 5

        for key, value in attr_items:
            if isinstance(value, list):
                logger.info(f"      • {key}: {len(value)} items")
            else:
                logger.info(f"      • {key}: {value}")

        if len(attrs_dict) > 5:
            logger.info(f"      ... and {len(attrs_dict) - 5} more")

    else:
        logger.warning(f"   ⚠️  Failed to get attributes: {result.error}")


def main() -> int:
    """Run LDIF operations demonstration.

    Returns:
        Exit code (0 for success, 1 for failure).

    """
    logger.info("=" * 60)
    logger.info("FLEXT-LDAP LDIF Operations Example")
    logger.info("=" * 60)
    logger.info(f"Server: {LDAP_URI}")
    logger.info(f"Base DN: {BASE_DN}")
    logger.info("=" * 60)

    try:
        # Entry model demonstration (no connection needed)
        demonstrate_entry_conversion()

        # Connect to LDAP server
        api = setup_api()
        if not api:
            logger.error("Cannot proceed without connection")
            return 1

        try:
            # Check FlextLdif availability
            if not demonstrate_ldif_availability(api):
                logger.warning("FlextLdif not available - skipping LDIF operations")
                logger.info("Install flext-ldif to enable LDIF functionality:")
                logger.info("   pip install flext-ldif")
                return 0

            # LDIF operations demonstrations
            ldif_path = create_sample_ldif_file()
            demonstrate_ldif_import(api, ldif_path)
            demonstrate_ldif_export(api)
            demonstrate_ldif_round_trip(api)

            # Entry adapter demonstrations
            demonstrate_entry_adapter_conversion(api)
            demonstrate_entry_server_detection(api)
            demonstrate_entry_normalization(api)
            demonstrate_entry_validation(api)
            demonstrate_server_specific_attributes(api)

            # Cleanup
            with contextlib.suppress(Exception):
                ldif_path.unlink()

            logger.info(f"\n{'=' * 60}")
            logger.info("✅ All LDIF operations completed successfully!")
            logger.info("=" * 60)

            logger.info("\nEntry Adapter Features Demonstrated:")
            logger.info("  • Format conversion between LDAP servers")
            logger.info("  • Server type detection from entry attributes")
            logger.info("  • Entry normalization for target servers")
            logger.info("  • Entry validation for server compatibility")
            logger.info("  • Server-specific attribute information")

        finally:
            # Always disconnect
            if api.is_connected():
                api.unbind()
                logger.info("Disconnected from LDAP server")

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
