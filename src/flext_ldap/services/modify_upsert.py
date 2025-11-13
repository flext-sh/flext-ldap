r"""Generic MODIFY UPSERT service for idempotent schema and attribute operations.

Provides production-grade MODIFY UPSERT operations that:
- SEARCH for existing entry to check current state
- FILTER out values that already exist (idempotency)
- MODIFY ADD/DELETE only new or removed values
- Handles errors gracefully with detailed statistics
- Works for schema modifications, ACL attributes, and any multi-valued attribute

This service is the foundation for idempotent operations across the FLEXT ecosystem,
used by data migration tools (client-a-oud-mig), ACL management, and other LDAP operations.

Usage:
    from flext_ldap.services.modify_upsert import FlextLdapModifyUpsertService

    service = FlextLdapModifyUpsertService()

    # Idempotent schema modification (skip existing attributeTypes/objectClasses)
    result = service.modify_upsert_schema(
        ldap_client=client,
        dn="cn=schema",
        attribute_types=["( 2.16.840.1.113894.1.1.321 NAME 'orclDASIsMandatory' ... )"],
        object_classes=["( 2.16.840.1.113894.1.2.9 NAME 'orclcontainerOC' ... )"],
    )

    # Idempotent attribute modification (skip existing values)
    result = service.modify_upsert_attribute(
        ldap_client=client,
        dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        attribute_name="aci",
        values_to_add=["(targetattr=*)(version 3.0; acl \\"Default\\"; allow(all) userdn=\\"ldap:///anyone\\";)"],
    )

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Union

if TYPE_CHECKING:
    from flext_ldap.api import FlextLdap

from flext_core import FlextResult, FlextService
from flext_ldif import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.clients import FlextLdapClients

# Import for OUD schema conversion (only used conditionally)
try:
    from flext_ldif.servers.oud import FlextLdifServersOud
except ImportError:
    FlextLdifServersOud = None


class FlextLdapModifyUpsertService(FlextService[dict[str, object]]):
    """Generic MODIFY UPSERT service for idempotent LDAP operations.

    Provides idempotent MODIFY operations that intelligently:
    - SEARCH existing entry to understand current state
    - FILTER operations based on what's already present
    - MODIFY ADD/DELETE only what's needed
    - Return detailed statistics about what was done

    This service handles:
    - Schema modifications (attributeTypes, objectClasses)
    - ACL attribute modifications (aci, orclaci)
    - Generic attribute modifications (any multi-valued attribute)

    Example:
        service = FlextLdapModifyUpsertService()

        # Add schema elements (skip if already exist)
        result = service.modify_upsert_schema(
            ldap_client=client,
            dn="cn=schema",
            attribute_types=["(...definition...)"],
        )
        if result.is_success:
            stats = result.unwrap()
            print(f"Added: {stats['added']}, Skipped: {stats['skipped']}")

    """

    def __init__(self) -> None:
        """Initialize MODIFY UPSERT service."""
        super().__init__()

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute method required by FlextService base class."""
        return FlextResult[dict[str, object]].ok({})

    def _get_client(self, ldap_client: Union[FlextLdap, FlextLdapClients]) -> FlextLdapClients:
        """Get FlextLdapClients instance from either FlextLdap or FlextLdapClients."""
        return ldap_client if isinstance(ldap_client, FlextLdapClients) else ldap_client.client

    def _extract_existing_values(self, entry: FlextLdifModels.Entry | None, attribute_name: str) -> set[str]:
        """Extract existing attribute values from an entry."""
        existing_values: set[str] = set()
        if entry and entry.attributes:
            existing_list = entry.attributes.get(attribute_name, [])
            if isinstance(existing_list, list):
                existing_values = set(existing_list)
            elif existing_list:
                existing_values = {str(existing_list)}
        return existing_values

    def _search_existing_entry(
        self, client: FlextLdapClients, dn: str, attributes: list[str]
    ) -> FlextLdifModels.Entry | None:
        """Search for existing entry and return it if found."""
        search_result = client.search(
            FlextLdapModels.SearchRequest(
                base_dn=dn,
                filter_str="(objectClass=*)",
                scope="base",
                attributes=attributes,
            )
        )

        if search_result.is_success:
            entries = search_result.unwrap()
            if entries:
                return entries[0] if isinstance(entries, list) else entries
        return None

    def _filter_new_values(self, new_values: list[str], existing_values: set[str]) -> tuple[list[str], int]:
        """Filter new values that don't already exist, return filtered list and skipped count."""
        filtered_values: list[str] = []
        skipped_count = 0

        for value in new_values:
            if value not in existing_values:
                filtered_values.append(value)
            else:
                skipped_count += 1

        return filtered_values, skipped_count

    def _convert_oud_schema_definitions(
        self,
        attribute_types: list[str] | None,
        object_classes: list[str] | None
    ) -> tuple[list[str] | None, list[str] | None]:
        """Convert schema definitions for OUD compatibility."""
        if not attribute_types and not object_classes:
            return attribute_types, object_classes

        if FlextLdifServersOud is None:
            msg = "FlextLdifServersOud not available"
            raise ImportError(msg)

        oud_quirks = FlextLdifServersOud()

        converted_attr_types = None
        if attribute_types:
            converted_attr_types = [
                oud_quirks.convert_schema_definition_for_ldap(attr, "attribute")
                for attr in attribute_types
            ]

        converted_obj_classes = None
        if object_classes:
            converted_obj_classes = [
                oud_quirks.convert_schema_definition_for_ldap(oc, "objectclass")
                for oc in object_classes
            ]

        return converted_attr_types, converted_obj_classes

    def modify_upsert_schema(
        self,
        ldap_client: Union[FlextLdap, FlextLdapClients],
        dn: str = "cn=schema",
        attribute_types: list[str] | None = None,
        object_classes: list[str] | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Idempotently ADD schema elements via MODIFY.

        Searches existing schema entry, filters out duplicates, and adds only new
        attributeTypes and objectClasses. Handles schema errors gracefully.

        ⚠️  IMPORTANT: Oracle Unified Directory (OUD) does NOT support schema
        modifications via LDAP. For OUD, schema extensions must be done through
        custom schema files placed in OUD_ORACLE_HOME/config/schema/ directory.

        Args:
            ldap_client: Connected FlextLdap or FlextLdapClients instance
            dn: Distinguished name of schema entry (default: "cn=schema")
            attribute_types: List of attributeType definitions to add
            object_classes: List of objectClass definitions to add

        Returns:
            FlextResult with statistics:
                {
                    "added": int,        # Number of definitions added
                    "skipped": int,      # Number of duplicates skipped
                    "failed": int,       # Number of failed operations
                    "details": str,      # Additional info (errors, etc)
                    "server_type": str,  # Detected server type
                    "oud_warning": str,  # Warning if OUD detected
                }

        Example:
            result = service.modify_upsert_schema(
                ldap_client=client,
                attribute_types=["( 2.16... NAME 'newAttr' ... )"],
                object_classes=["( 1.3... NAME 'newClass' ... )"],
            )

        """
        try:
            client = self._get_client(ldap_client)
            server_type = getattr(client, '_detected_server_type', 'unknown')
            is_oud = server_type == 'oud'

            # Convert definitions for OUD if needed
            if is_oud:
                attribute_types, object_classes = self._convert_oud_schema_definitions(
                    attribute_types, object_classes
                )

            # Search existing schema entry
            existing_entry = self._search_existing_entry(
                client, dn, ["attributeTypes", "objectClasses", "+"]
            )

            # Extract and filter values
            existing_attr_types = self._extract_existing_values(existing_entry, "attributeTypes")
            existing_obj_classes = self._extract_existing_values(existing_entry, "objectClasses")

            new_attr_types, skipped_attr = self._filter_new_values(
                attribute_types or [], existing_attr_types
            )
            new_obj_classes, skipped_obj = self._filter_new_values(
                object_classes or [], existing_obj_classes
            )
            skipped_count = skipped_attr + skipped_obj

            # Build and execute operations
            operations = {}
            if new_attr_types:
                operations["attributeTypes"] = new_attr_types
            if new_obj_classes:
                operations["objectClasses"] = new_obj_classes

            added_count = 0
            failed_count = 0
            error_details = []

            if operations:
                modify_result = client.modify_entry(dn, FlextLdapModels.EntryChanges(**operations))
                total_new = len(new_attr_types) + len(new_obj_classes)
                if modify_result.is_success:
                    added_count = total_new
                else:
                    failed_count = total_new
                    error_details.append(f"MODIFY failed: {modify_result.error}")

            # Return statistics
            return FlextResult[dict[str, object]].ok(
                {
                    "added": added_count,
                    "skipped": skipped_count,
                    "failed": failed_count,
                    "details": "; ".join(error_details) if error_details else "OK",
                    "server_type": server_type,
                    "oud_warning": "OUD detected - schema modifications via LDAP not supported" if is_oud else None,
                }
            )

        except Exception as e:
            return FlextResult[dict[str, object]].fail(f"Schema MODIFY UPSERT failed: {e!s}")

    def _build_operations_for_attribute(
        self,
        attribute_name: str,
        values_to_add: list[str],
        values_to_delete: list[str]
    ) -> tuple[dict[str, Any], int, int]:
        """Build operations dict for attribute modification, return operations, added_count, deleted_count."""
        operations: dict[str, Any] = {}
        added_count = 0
        deleted_count = 0

        # Build ADD operations
        if values_to_add:
            operations[attribute_name] = [(FlextLdapConstants.ModifyOperation.ADD, values_to_add)]
            added_count = len(values_to_add)

        # Build DELETE operations
        if values_to_delete:
            if attribute_name in operations:
                operations[attribute_name].append((FlextLdapConstants.ModifyOperation.DELETE, values_to_delete))
            else:
                operations[attribute_name] = [(FlextLdapConstants.ModifyOperation.DELETE, values_to_delete)]
            deleted_count = len(values_to_delete)

        return operations, added_count, deleted_count

    def modify_upsert_attribute(
        self,
        ldap_client: Union[FlextLdap, FlextLdapClients],
        dn: str,
        attribute_name: str,
        values_to_add: list[str] | None = None,
        values_to_delete: list[str] | None = None,
    ) -> FlextResult[dict[str, object]]:
        r"""Idempotently MODIFY attribute values (ADD/DELETE).

        Searches existing entry, filters values, and executes only necessary
        modifications. Useful for ACL attributes (aci, orclaci) and any
        multi-valued attributes.

        Args:
            ldap_client: Connected FlextLdap or FlextLdapClients instance
            dn: Distinguished name to modify
            attribute_name: Attribute to modify (e.g., "aci", "orclaci", "mail")
            values_to_add: List of values to add (skip if already exist)
            values_to_delete: List of values to delete (skip if don't exist)

        Returns:
            FlextResult with statistics:
                {
                    "added": int,        # Number of values added
                    "deleted": int,      # Number of values deleted
                    "skipped": int,      # Number of redundant operations
                    "modified": bool,    # True if any MODIFY executed
                }

        Example:
            result = service.modify_upsert_attribute(
                ldap_client=client,
                dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                attribute_name="aci",
                values_to_add=["(targetattr=*)(version 3.0; acl \\"rule1\\"; allow(all) userdn=\\"ldap:///anyone\\";)"],
            )

        """
        # Railway Pattern: Initialize tracking
        added_count = 0
        deleted_count = 0
        skipped_count = 0

        try:
            client = self._get_client(ldap_client)

            # Search existing entry
            existing_entry = self._search_existing_entry(
                client, dn, [attribute_name, "+"]
            )

            # Extract existing values
            existing_values = self._extract_existing_values(existing_entry, attribute_name)

            # Filter values to add/delete
            values_to_add_filtered: list[str] = []
            values_to_delete_filtered: list[str] = []

            if values_to_add:
                values_to_add_filtered, skipped_add = self._filter_new_values(values_to_add, existing_values)
                skipped_count += skipped_add

            # Filter values to delete (skip if don't exist)
            if values_to_delete:
                for value in values_to_delete:
                    if value in existing_values:
                        values_to_delete_filtered.append(value)
                    else:
                        skipped_count += 1

            # Build operations and execute modify if needed
            operations, added_count, deleted_count = self._build_operations_for_attribute(
                attribute_name, values_to_add_filtered, values_to_delete_filtered
            )

            modified = False
            if operations:
                modify_result = client.modify_entry(dn, FlextLdapModels.EntryChanges(**operations))
                if modify_result.is_success:
                    modified = True
                else:
                    return FlextResult[dict[str, object]].fail(
                        f"MODIFY failed for {dn}.{attribute_name}: {modify_result.error}"
                    )

            # Return statistics
            return FlextResult[dict[str, object]].ok(
                {
                    "added": added_count,
                    "deleted": deleted_count,
                    "skipped": skipped_count,
                    "modified": modified,
                }
            )

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Attribute MODIFY UPSERT failed for {dn}.{attribute_name}: {e!s}"
            )
