#!/usr/bin/env python3
"""Load test data into LDAP server using flext-ldap API.

This script demonstrates:
1. Bulk data loading using flext-ldap
2. Error handling and retry logic
3. Connection management
4. Progress tracking
"""

import sys
from pathlib import Path

from flext_core import (
    FlextLogger,
)
from pydantic import SecretStr

from flext_ldap import FlextLdap, FlextLdapConfig

logger = FlextLogger(__name__)


def parse_ldif_file(
    ldif_path: Path,
) -> list[tuple[str, dict[str, str | list[str]]]]:
    """Parse LDIF file into list of (dn, attributes) tuples."""
    entries: list[tuple[str, dict[str, str | list[str]]]] = []
    current_dn: str | None = None
    current_attrs: dict[str, str | list[str]] = {}

    with Path(ldif_path).open(encoding="utf-8") as f:
        for line in f:
            stripped_line = line.rstrip()

            # Skip empty lines and comments
            if not stripped_line or stripped_line.startswith("#"):
                if current_dn and current_attrs:
                    entries.append((current_dn, current_attrs))
                    current_dn = None
                    current_attrs = {}
                continue

            # Parse DN
            if stripped_line.startswith("dn:"):
                if current_dn and current_attrs:
                    entries.append((current_dn, current_attrs))
                current_dn = stripped_line.split(":", 1)[1].strip()
                current_attrs = {}
                continue

            # Parse attribute: value
            if ":" in stripped_line and current_dn:
                attr, value = stripped_line.split(":", 1)
                attr = attr.strip()
                value = value.strip()

                # Handle multi-valued attributes
                if attr in current_attrs:
                    existing_value = current_attrs[attr]
                    if isinstance(existing_value, list):
                        existing_value.append(value)
                    else:
                        current_attrs[attr] = [existing_value, value]
                else:
                    current_attrs[attr] = value

        # Add last entry
        if current_dn and current_attrs:
            entries.append((current_dn, current_attrs))

    return entries


def load_test_data_openldap() -> bool:
    """Load test data into OpenLDAP using flext-ldap API."""
    logger.info("=" * 80)
    logger.info("LOADING TEST DATA INTO OPENLDAP USING FLEXT-LDAP API")
    logger.info("=" * 80)

    # Parse LDIF file
    ldif_path = Path("test_data_openldap.ldif")
    if not ldif_path.exists():
        logger.error(f"LDIF file not found: {ldif_path}")
        return False

    logger.info(f"Parsing LDIF file: {ldif_path}")
    entries = parse_ldif_file(ldif_path)
    logger.info(f"Parsed {len(entries)} entries from LDIF")

    # Create flext-ldap API instance

    FlextLdapConfig(
        ldap_server_uri="ldap://localhost:3390",
        ldap_bind_dn="cn=admin,dc=flext,dc=local",
        ldap_bind_password=SecretStr("admin123"),
        ldap_base_dn="dc=flext,dc=local",
    )

    api = FlextLdap()

    # Connect to server using context manager
    logger.info("Connecting to OpenLDAP server...")
    try:
        with api:
            logger.info("✅ Connected successfully")

            # Load entries
            success_count = 0
            failure_count = 0
            skipped_count = 0

            logger.info(f"Loading {len(entries)} entries...")
            logger.info("-" * 80)

            for i, (dn, attributes) in enumerate(entries, 1):
                # Skip base DN (already exists)
                if dn == "dc=flext,dc=local":
                    skipped_count += 1
                    continue

                # Show progress every 50 entries
                if i % 50 == 0:
                    logger.info(f"Progress: {i}/{len(entries)} entries processed...")

                # Add entry using flext-ldap
                add_result = api.client.add_entry(dn=dn, attributes=attributes)

                if add_result.is_success:
                    success_count += 1
                else:
                    # Check if entry already exists (code 68)
                    error_msg = str(add_result.error)
                    if "Already exists" in error_msg or "68" in error_msg:
                        skipped_count += 1
                    else:
                        failure_count += 1
                        if failure_count <= 10:  # Only log first 10 failures
                            logger.warning(f"Failed to add {dn}: {add_result.error}")

    except Exception:
        logger.exception("Failed to connect")
        return False

    # Summary
    logger.info("-" * 80)
    logger.info("LOAD SUMMARY:")
    logger.info(f"  Total entries: {len(entries)}")
    logger.info(f"  ✅ Successfully added: {success_count}")
    logger.info(f"  ⏭️  Skipped (already exists): {skipped_count}")
    logger.info(f"  ❌ Failed: {failure_count}")
    logger.info("=" * 80)

    return failure_count == 0


def main() -> int:
    """Main entry point."""
    try:
        success = load_test_data_openldap()
        return 0 if success else 1
    except Exception:
        logger.exception("Unexpected error")
        return 1


if __name__ == "__main__":
    sys.exit(main())
