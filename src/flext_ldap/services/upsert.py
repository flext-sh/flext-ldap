"""Generic UPSERT service for intelligent entry creation/update operations.

Provides a reusable, production-grade UPSERT (Create or Update) implementation
that handles the complexity of determining whether to ADD new attributes or
REPLACE existing ones based on actual current entry state.

Usage:
    from flext_ldap import FlextLdapClients, FlextLdapUpsertService

    client = FlextLdapClients(config=config)
    client.connect()
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

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.clients import FlextLdapClients


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
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [FlextLdapConstants.ObjectClasses.INET_ORG_PERSON, FlextLdapConstants.ObjectClasses.PERSON],
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

    def _normalize_attributes(
        self,
        attributes: dict[str, list[str] | str],
    ) -> dict[str, list[str]]:
        """Normalize attributes to list format."""
        normalized: dict[str, list[str]] = {}
        for attr, value in attributes.items():
            if isinstance(value, list):
                normalized[attr] = value
            else:
                normalized[attr] = [value]
        return normalized

    def _extract_entry_from_search(
        self,
        search_response: FlextLdifModels.Entry | list[FlextLdifModels.Entry] | list[tuple[str, FlextLdifModels.Entry]] | None,
        dn: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Extract Entry object from various search response formats."""
        if not search_response:
            return FlextResult[FlextLdifModels.Entry].fail(
                f"Entry {dn} not found in search despite ADD indicating existence",
            )

        if isinstance(search_response, list):
            if not search_response:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Entry {dn} not found in search entries despite ADD indicating existence",
                )
            search_result_item = search_response[0]
            expected_tuple_length = 2
            entry_index = 1
            if (
                isinstance(search_result_item, tuple)
                and len(search_result_item) == expected_tuple_length
            ):
                entry: FlextLdifModels.Entry = search_result_item[entry_index]  # type: ignore[assignment]
                return FlextResult[FlextLdifModels.Entry].ok(entry)
            # Direct Entry object from list
            if isinstance(search_result_item, FlextLdifModels.Entry):
                return FlextResult[FlextLdifModels.Entry].ok(search_result_item)
            return FlextResult[FlextLdifModels.Entry].fail(f"Unexpected search result format for {dn}")

        return FlextResult[FlextLdifModels.Entry].ok(search_response)

    def _extract_existing_attributes(
        self,
        entry: FlextLdifModels.Entry,
    ) -> dict[str, list[str]]:
        """Extract current attributes from existing entry."""
        existing_attrs: dict[str, list[str]] = {}
        for attr_name, attr_obj in entry.attributes.items():
            if attr_obj:
                if hasattr(attr_obj, "values"):
                    existing_attrs[attr_name.lower()] = [str(v) for v in attr_obj.values]
                else:
                    existing_attrs[attr_name.lower()] = [str(attr_obj)]
        return existing_attrs

    def _compute_attribute_changes(
        self,
        normalized_new: dict[str, list[str]],
        existing_attrs: dict[str, list[str]],
        skip_attributes: set[str],
    ) -> tuple[dict[str, list[str]], dict[str, list[str]], int]:
        """Determine which attributes to ADD, REPLACE, or leave unchanged."""
        to_add: dict[str, list[str]] = {}
        to_replace: dict[str, list[str]] = {}
        unchanged_count = 0

        for attr, new_values in normalized_new.items():
            if attr.lower() in skip_attributes:
                continue

            attr_lower = attr.lower()
            if attr_lower not in existing_attrs:
                to_add[attr] = new_values
            else:
                existing_values = existing_attrs[attr_lower]
                if set(new_values) == set(existing_values):
                    unchanged_count += 1
                else:
                    to_replace[attr] = new_values

        return to_add, to_replace, unchanged_count

    def _execute_add_modifications(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
        to_add: dict[str, list[str]],
    ) -> FlextResult[int]:
        """Execute MODIFY ADD operations."""
        if not to_add:
            return FlextResult[int].ok(0)

        add_changes_dict = {
            attr: [(FlextLdapConstants.ModifyOperation.ADD, values)]
            for attr, values in to_add.items()
        }
        add_changes = FlextLdapModels.EntryChanges(**add_changes_dict)
        self.logger.debug(
            "Executing MODIFY ADD",
            extra={"dn": dn, "attributes": list(to_add.keys())},
        )

        add_result = ldap_client.modify_entry(dn=dn, changes=add_changes)
        if add_result.is_failure:
            self.logger.error(
                "MODIFY ADD failed",
                extra={"dn": dn, "error": str(add_result.error)},
            )
            return FlextResult[int].fail(str(add_result.error))

        added_count = len(to_add)
        self.logger.debug(
            "MODIFY ADD successful",
            extra={"dn": dn, "added_count": added_count},
        )
        return FlextResult[int].ok(added_count)

    def _execute_replace_modifications(
        self,
        ldap_client: FlextLdapClients,
        dn: str,
        to_replace: dict[str, list[str]],
    ) -> FlextResult[int]:
        """Execute MODIFY REPLACE operations."""
        if not to_replace:
            return FlextResult[int].ok(0)

        replace_changes_dict = {
            attr: [(FlextLdapConstants.ModifyOperation.REPLACE, values)]
            for attr, values in to_replace.items()
        }
        replace_changes = FlextLdapModels.EntryChanges(**replace_changes_dict)
        self.logger.debug(
            "Executing MODIFY REPLACE",
            extra={"dn": dn, "attributes": list(to_replace.keys())},
        )

        replace_result = ldap_client.modify_entry(dn=dn, changes=replace_changes)
        if replace_result.is_failure:
            self.logger.error(
                "MODIFY REPLACE failed",
                extra={"dn": dn, "error": str(replace_result.error)},
            )
            return FlextResult[int].fail(str(replace_result.error))

        replaced_count = len(to_replace)
        self.logger.debug(
            "MODIFY REPLACE successful",
            extra={"dn": dn, "replaced_count": replaced_count},
        )
        return FlextResult[int].ok(replaced_count)

    def upsert_entry(
        self,
        ldap_client: FlextLdapClients,
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
            ldap_client: Connected FlextLdapClients instance
            dn: Distinguished name of entry to upsert
            new_attributes: New/updated attributes (dict or list format)
            skip_attributes: Optional set of attribute names to skip (operational, RDN)

        Returns:
            FlextResult containing dict with:
            - "{FlextLdapConstants.StatusKeys.UPSERTED}": bool - True if entry created/updated
            - "{FlextLdapConstants.StatusKeys.ADDED}": int - Number of attributes added
            - "{FlextLdapConstants.StatusKeys.REPLACED}": int - Number of attributes replaced
            - "{FlextLdapConstants.StatusKeys.UNCHANGED}": int - Number of attributes unchanged

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

        # Step 1: Normalize attributes
        normalized_new = self._normalize_attributes(new_attributes)

        # Step 2: Try ADD first (most efficient for new entries)
        self.logger.debug("Attempting ADD", extra={"dn": dn})
        add_result = ldap_client.add_entry(dn=dn, attributes=new_attributes)

        if add_result.is_success:
            self.logger.debug(
                "Entry created via ADD",
                extra={
                    "dn": dn,
                    FlextLdapConstants.StatusKeys.ATTRIBUTE_COUNT: len(normalized_new),
                },
            )
            return FlextResult[dict[str, object]].ok({
                FlextLdapConstants.StatusKeys.UPSERTED: True,
                FlextLdapConstants.StatusKeys.ADDED: len(normalized_new),
                FlextLdapConstants.StatusKeys.REPLACED: 0,
                FlextLdapConstants.StatusKeys.UNCHANGED: 0,
            })

        # Step 3: Check if failure is because entry already exists
        error_msg = str(add_result.error).lower()
        is_already_exists = any(
            pattern in error_msg
            for pattern in [
                FlextLdapConstants.ErrorPatterns.ENTRY_ALREADY_EXISTS,
                FlextLdapConstants.ErrorPatterns.ALREADY_EXISTS,
                FlextLdapConstants.ErrorPatterns.CODE_68,
            ]
        )

        if not is_already_exists:
            self.logger.error(
                "ADD failed with non-existence error",
                extra={"dn": dn, "error": str(add_result.error)},
            )
            return FlextResult[dict[str, object]].fail(str(add_result.error))

        # Step 4: Entry exists - fetch and extract existing entry
        self.logger.debug("Entry exists, fetching current attributes", extra={"dn": dn})
        search_result = ldap_client.search(
            base_dn=dn,
            filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
            single=True,
        )

        if search_result.is_failure:
            self.logger.error(
                "Failed to fetch existing entry",
                extra={"dn": dn, "error": str(search_result.error)},
            )
            return FlextResult[dict[str, object]].fail(
                f"Failed to fetch existing entry: {search_result.error}",
            )

        entry_result = self._extract_entry_from_search(search_result.unwrap(), dn)
        if entry_result.is_failure:
            self.logger.error(
                "Failed to extract entry from search",
                extra={"dn": dn, "error": str(entry_result.error)},
            )
            return FlextResult[dict[str, object]].fail(str(entry_result.error))

        existing_entry = entry_result.unwrap()
        existing_attrs = self._extract_existing_attributes(existing_entry)

        # Step 5: Compute changes (ADD vs REPLACE)
        to_add, to_replace, unchanged_count = self._compute_attribute_changes(
            normalized_new,
            existing_attrs,
            skip_attributes,
        )

        # Skip MODIFY if no changes detected
        if not to_add and not to_replace:
            self.logger.debug(
                "Entry already has identical attributes, skipping MODIFY",
                extra={"dn": dn, "unchanged_count": unchanged_count},
            )
            return FlextResult[dict[str, object]].ok({
                FlextLdapConstants.StatusKeys.UPSERTED: True,
                FlextLdapConstants.StatusKeys.ADDED: 0,
                FlextLdapConstants.StatusKeys.REPLACED: 0,
                FlextLdapConstants.StatusKeys.UNCHANGED: unchanged_count,
            })

        # Step 6: Execute modifications
        self.logger.debug(
            "Preparing MODIFY",
            extra={
                "dn": dn,
                "to_add_count": len(to_add),
                "to_replace_count": len(to_replace),
            },
        )

        add_count_result = self._execute_add_modifications(ldap_client, dn, to_add)
        if add_count_result.is_failure:
            return FlextResult[dict[str, object]].fail(str(add_count_result.error))

        replace_count_result = self._execute_replace_modifications(ldap_client, dn, to_replace)
        if replace_count_result.is_failure:
            return FlextResult[dict[str, object]].fail(str(replace_count_result.error))

        added_count = add_count_result.unwrap()
        replaced_count = replace_count_result.unwrap()

        self.logger.info(
            "Entry upserted successfully",
            extra={
                "dn": dn,
                FlextLdapConstants.StatusKeys.ADDED: added_count,
                FlextLdapConstants.StatusKeys.REPLACED: replaced_count,
            },
        )

        return FlextResult[dict[str, object]].ok({
            FlextLdapConstants.StatusKeys.UPSERTED: True,
            FlextLdapConstants.StatusKeys.ADDED: added_count,
            FlextLdapConstants.StatusKeys.REPLACED: replaced_count,
            FlextLdapConstants.StatusKeys.UNCHANGED: unchanged_count,
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
