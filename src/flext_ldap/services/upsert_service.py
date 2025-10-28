"""Generic UPSERT service for intelligent entry creation/update operations.

Provides a reusable, production-grade UPSERT (Create or Update) implementation
that handles the complexity of determining whether to ADD new attributes or
REPLACE existing ones based on actual current entry state.

Usage:
    from flext_ldap import FlextLdap, FlextLdapUpsertService

    client = FlextLdap()
    upsert_service = FlextLdapUpsertService()
    result = upsert_service.upsert_entry(
        ldap_client=client,
        dn="cn=user,ou=users,dc=example,dc=com",
        new_attributes={
            "mail": ["user@example.com"],
            "telephoneNumber": ["555-1234"],
            "cn": ["User Name"],
        }
    )

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextResult, FlextService

from flext_ldap.api import FlextLdap
from flext_ldap.constants import FlextLdapConstants


class FlextLdapUpsertService(FlextService[dict[str, object]]):
    """Generic UPSERT service for intelligent entry operations.

    Implements production-grade UPSERT logic that:
    - Searches for existing entry to get actual attributes
    - Intelligently decides ADD vs REPLACE based on facts
    - Executes modifications without unnecessary retries
    - Handles errors immediately without fallback attempts

    This service should be used by applications that need to create or
    update LDAP entries efficiently and reliably.

    Example:
        service = FlextLdapUpsertService()
        result = service.upsert_entry(
            ldap_client=client,
            dn="cn=john,ou=users,dc=corp,dc=com",
            new_attributes={
                "mail": ["john@corp.com"],
                "displayName": ["John Smith"],
                "objectClass": ["inetOrgPerson", "person"],
            }
        )
        if result.is_success:
            print(f"Entry upserted: {result.unwrap()}")

    """

    def __init__(self) -> None:
        """Initialize UPSERT service."""
        super().__init__()

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute method required by FlextService base class."""
        return FlextResult[dict[str, object]].ok({})

    def upsert_entry(
        self,
        ldap_client: FlextLdap,
        dn: str,
        new_attributes: dict[str, list[str] | str],
        skip_attributes: set[str] | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Intelligently create or update LDAP entry.

        Strategy:
        1. Attempt ADD (entry creation) - fastest path for new entries
        2. If fails with "already exists", search for existing attributes
        3. Compare current vs new attributes to decide ADD vs REPLACE
        4. Execute MODIFY operations based on actual differences
        5. Return errors immediately (no retries)

        Args:
            ldap_client: Connected FlextLdap instance
            dn: Distinguished name of entry to upsert
            new_attributes: New/updated attributes (dict or list format)
            skip_attributes: Optional set of attribute names to skip (operational, RDN)

        Returns:
            FlextResult containing dict with:
            - "upserted": bool - True if entry created/updated
            - "added": int - Number of attributes added
            - "replaced": int - Number of attributes replaced
            - "unchanged": int - Number of attributes unchanged

        Example:
            >>> result = service.upsert_entry(
            ...     client,
            ...     "cn=user,ou=users,dc=example,dc=com",
            ...     {"mail": ["user@example.com"], "cn": ["User"]},
            ... )
            >>> if result.is_success:
            ...     stats = result.unwrap()
            ...     print(f"Added: {stats['added']}, Replaced: {stats['replaced']}")

        """
        if skip_attributes is None:
            skip_attributes = self._get_default_skip_attributes()

        # Normalize new_attributes to list format
        normalized_new: dict[str, list[str]] = {}
        for attr, value in new_attributes.items():
            if isinstance(value, list):
                normalized_new[attr] = value
            else:
                normalized_new[attr] = [value]

        # Step 1: Try ADD first (most efficient for new entries)
        self.logger.debug("Attempting ADD", extra={"dn": dn})
        add_result = ldap_client.client.add_entry(dn=dn, attributes=new_attributes)

        # Entry created successfully
        if add_result.is_success:
            self.logger.debug(
                "Entry created via ADD",
                extra={"dn": dn, "attribute_count": len(normalized_new)},
            )
            return FlextResult[dict[str, object]].ok({
                "upserted": True,
                "added": len(normalized_new),
                "replaced": 0,
                "unchanged": 0,
            })

        # Step 2: Check if failure is because entry already exists
        error_msg = str(add_result.error).lower()
        is_already_exists = any(
            pattern in error_msg
            for pattern in ["entryalreadyexists", "already exists", "code 68"]
        )

        if not is_already_exists:
            # Real error - not a "already exists" error
            self.logger.error(
                "ADD failed with non-existence error",
                extra={"dn": dn, "error": str(add_result.error)},
            )
            return FlextResult[dict[str, object]].fail(str(add_result.error))

        # Step 3: Entry exists - search for current attributes
        self.logger.debug("Entry exists, fetching current attributes", extra={"dn": dn})
        search_result = ldap_client.search(
            base_dn=dn,
            search_filter="(objectClass=*)",
            bulk=False,
        )

        if search_result.is_failure:
            self.logger.error(
                "Failed to fetch existing entry",
                extra={"dn": dn, "error": str(search_result.error)},
            )
            return FlextResult[dict[str, object]].fail(
                f"Failed to fetch existing entry: {search_result.error}"
            )

        search_response = search_result.unwrap()
        if not search_response:
            self.logger.error(
                "Entry reported as exists but not found in search",
                extra={"dn": dn},
            )
            return FlextResult[dict[str, object]].fail(
                f"Entry {dn} not found in search despite ADD indicating existence"
            )

        # Extract Entry from search response (search() returns list[Entry] | Entry | None)
        # Handle three cases: None, single Entry, list of Entry objects
        if isinstance(search_response, list):
            if not search_response:
                self.logger.error(
                    "Entry not found in search entries",
                    extra={"dn": dn},
                )
                return FlextResult[dict[str, object]].fail(
                    f"Entry {dn} not found in search entries despite ADD indicating existence"
                )
            existing_entry = search_response[0]
        else:
            # Single Entry returned directly from search
            existing_entry = search_response

        # Extract current attributes from existing entry
        existing_attrs: dict[str, list[str]] = {}
        for attr_name, attr_obj in existing_entry.attributes.items():
            if attr_obj:
                if hasattr(attr_obj, "values"):
                    existing_attrs[attr_name.lower()] = [
                        str(v) for v in attr_obj.values
                    ]
                else:
                    existing_attrs[attr_name.lower()] = [str(attr_obj)]

        # Step 4: Determine ADD vs REPLACE based on actual attributes
        to_add: dict[str, list[str]] = {}
        to_replace: dict[str, list[str]] = {}
        unchanged_count = 0

        for attr, new_values in normalized_new.items():
            # Skip operational and RDN attributes
            if attr.lower() in skip_attributes:
                continue

            attr_lower = attr.lower()
            if attr_lower not in existing_attrs:
                # Attribute doesn't exist - ADD
                to_add[attr] = new_values
            else:
                # Attribute exists - check if values differ
                existing_values = existing_attrs[attr_lower]
                if set(new_values) == set(existing_values):
                    # Values are identical - no change needed
                    unchanged_count += 1
                else:
                    # Values differ - REPLACE
                    to_replace[attr] = new_values

        # Step 5: Skip MODIFY if no changes detected
        if not to_add and not to_replace:
            self.logger.debug(
                "Entry already has identical attributes, skipping MODIFY",
                extra={"dn": dn, "unchanged_count": unchanged_count},
            )
            return FlextResult[dict[str, object]].ok({
                "upserted": True,
                "added": 0,
                "replaced": 0,
                "unchanged": unchanged_count,
            })

        # Step 6: Execute MODIFY operations (no retries)
        self.logger.debug(
            "Preparing MODIFY",
            extra={
                "dn": dn,
                "to_add_count": len(to_add),
                "to_replace_count": len(to_replace),
            },
        )

        added_count = 0
        replaced_count = 0

        # Execute ADD modifications
        if to_add:
            add_changes = cast("dict[str, str | list[str]]", to_add)
            self.logger.debug(
                "Executing MODIFY ADD",
                extra={"dn": dn, "attributes": list(to_add.keys())},
            )
            add_result = ldap_client.modify(
                dn=dn,
                changes=add_changes,
                operation=FlextLdapConstants.ModifyOperation.ADD,
            )
            if add_result.is_failure:
                # No retry - ADD should work since we verified attributes don't exist
                self.logger.error(
                    "MODIFY ADD failed",
                    extra={"dn": dn, "error": str(add_result.error)},
                )
                return FlextResult[dict[str, object]].fail(str(add_result.error))
            added_count = len(to_add)
            self.logger.debug(
                "MODIFY ADD successful",
                extra={"dn": dn, "added_count": added_count},
            )

        # Execute REPLACE modifications
        if to_replace:
            replace_changes = cast("dict[str, str | list[str]]", to_replace)
            self.logger.debug(
                "Executing MODIFY REPLACE",
                extra={"dn": dn, "attributes": list(to_replace.keys())},
            )
            replace_result = ldap_client.modify(
                dn=dn,
                changes=replace_changes,
                operation=FlextLdapConstants.ModifyOperation.REPLACE,
            )
            if replace_result.is_failure:
                self.logger.error(
                    "MODIFY REPLACE failed",
                    extra={"dn": dn, "error": str(replace_result.error)},
                )
                return FlextResult[dict[str, object]].fail(str(replace_result.error))
            replaced_count = len(to_replace)
            self.logger.debug(
                "MODIFY REPLACE successful",
                extra={"dn": dn, "replaced_count": replaced_count},
            )

        self.logger.info(
            "Entry upserted successfully",
            extra={"dn": dn, "added": added_count, "replaced": replaced_count},
        )

        return FlextResult[dict[str, object]].ok({
            "upserted": True,
            "added": added_count,
            "replaced": replaced_count,
            "unchanged": unchanged_count,
        })

    @staticmethod
    def _get_default_skip_attributes() -> set[str]:
        """Get default set of attributes to skip during UPSERT.

        Returns attributes that should never be modified:
        - Operational attributes (managed by server)
        - RDN attributes (cannot be modified via MODIFY)
        - Structural attributes (objectClass cannot be modified)

        Returns:
            Set of lowercase attribute names to skip

        """
        return {
            # Operational attributes
            "createtimestamp",
            "modifytimestamp",
            "creatorsname",
            "modifiersname",
            "entryuuid",
            "entrycsn",
            "structuralobjectclass",
            "hassubordinates",
            "subschemasubentry",
            # Common RDN attributes (check these, they're often RDNs)
            "cn",
            "uid",
            "ou",
            # Structural attributes (cannot be modified)
            "objectclass",
        }
