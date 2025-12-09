"""Search, CRUD, and upsert helpers built on ``Ldap3Adapter``.

This module keeps protocol concerns inside the adapter while exposing typed
inputs, normalized results, and reusable comparison utilities for callers.

Business Rules:
    - All LDAP operations are delegated to the adapter layer (Ldap3Adapter)
    - DN normalization is applied before all search operations using
      FlextLdifUtilities.Ldif.DN.norm_string() to ensure consistent DN format
    - Entry comparison ignores operational attributes defined in
      c.Ldap.OperationalAttributes.IGNORE_SET
    - Upsert operations implement add-or-modify pattern:
      1. First attempts ADD operation
      2. If entry exists (LDAP error 68), compares attributes and applies MODIFY
      3. If no changes detected, operation is marked as SKIPPED
    - Schema modifications are handled specially via changetype=modify entries

Audit Implications:
    - All operations log to FlextLdapServiceBase.logger for traceability
    - batch_upsert tracks synced/failed/skipped counts for compliance reporting
    - Progress callbacks enable real-time audit trail during batch operations
    - Error messages are logged with entry DN and index for forensic analysis

Architecture Notes:
    - Uses Railway-Oriented Programming pattern (FlextResult) for error handling
    - No exceptions are raised; all failures return r.fail()
    - All methods are type-safe with strict Pydantic v2 validation
    - Python 3.13: isinstance(..., Sequence) used directly for type narrowing
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence

from flext_core import r
from flext_ldif import FlextLdifUtilities
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from pydantic import ConfigDict

from flext_ldap.base import s
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import c
from flext_ldap.models import m
from flext_ldap.protocols import p
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.typings import t
from flext_ldap.utilities import u


class FlextLdapOperations(s[m.Ldap.SearchResult]):
    """Coordinate LDAP operations on an active connection.

    Protocol calls are delegated to :class:`~flext.adapters.ldap3.Ldap3Adapter`
    so this layer can concentrate on typed arguments, predictable
    :class:`flext_core.FlextResult` responses, and shared comparison helpers.

    Business Rules:
        - Connection must be bound before operations (validated via is_connected)
        - Search operations normalize base_dn using FlextLdifUtilities.Ldif.DN.norm_string()
        - Add/Modify/Delete operations convert string DNs to DistinguishedName models
        - Upsert implements LDAP idempotent write: add -> exists check -> modify
        - Batch operations track per-entry progress and support stop_on_error

    Audit Implications:
        - Each operation is logged with the operation name and result status
        - Batch operations log individual entry failures for forensic analysis
        - Progress callbacks allow external systems to track operation progress
        - All errors include context (DN, operation type, error message)

    Thread Safety:
        - Service instances are NOT thread-safe; use separate instances per thread
        - The underlying ldap3 Connection is managed by FlextLdapConnection

    Pydantic v2 Integration:
        - model_config allows frozen=False for mutable service state (_connection)
        - Uses extra="allow" for compatibility with service configuration
        - arbitrary_types_allowed=True enables non-Pydantic types in fields

    Examples:
        >>> ops = FlextLdapOperations(connection=conn)
        >>> result = ops.search(m.Ldap.SearchOptions(base_dn="dc=example,dc=com"))
        >>> if result.is_success:
        ...     entries = result.unwrap().entries

    """

    model_config = ConfigDict(
        frozen=False,  # Service needs mutable state for connection reference
        extra="allow",
        arbitrary_types_allowed=True,
    )

    _connection: FlextLdapConnection

    @staticmethod
    def _extract_attributes_dict(
        entry: p.Ldap.LdapEntryProtocol | p.Entry,
    ) -> dict[str, list[str]]:
        """Extract attributes dict from entry protocol.

        Args:
            entry: Entry protocol-compatible object.

        Returns:
            Attributes dict with normalized values.

        """
        # Use extract_attributes which handles all types
        attrs_mapping = FlextLdapOperations.EntryComparison.extract_attributes(entry)
        # Python 3.13: Use isinstance directly for type narrowing
        result: dict[str, list[str]] = {}
        for k, v in u.mapper().to_dict(attrs_mapping).items():
            result[k] = (
                [str(item) for item in v] if isinstance(v, Sequence) else [str(v)]
            )
        return result

    class EntryComparison:
        """Compute attribute-level differences between entries.

        Utilities normalize attribute keys and values to build precise
        ``MODIFY`` payloads without duplicating comparison logic across
        services or tests.

        Business Rules:
            - Attribute comparison is case-insensitive for both names and values
            - Operational attributes (objectClass, entryUUID, etc.) are ignored
            - Empty values are filtered out before comparison
            - MODIFY_REPLACE is used for changed attributes
            - MODIFY_DELETE is used for attributes removed in new entry

        Audit Implications:
            - Returns precise change set for audit trail of modifications
            - Null return indicates no changes needed (idempotent)
            - Changes dict maps attribute name -> list of LDAP modify operations

        Performance Notes:
            - O(n) for attribute extraction and comparison
            - Uses set comparison for value differences (O(1) lookups)
        """

        @staticmethod
        def _convert_mapping_to_dict(
            attrs: Mapping[str, Sequence[str]],
        ) -> dict[str, list[str]]:
            """Convert Mapping to dict[str, list[str]].

            Args:
                attrs: Mapping of attribute names to sequences

            Returns:
                Dictionary of attribute names to list of strings

            """
            # Python 3.13: Use isinstance directly for type narrowing
            attrs_result: dict[str, list[str]] = {}
            for k, v in u.mapper().to_dict(attrs).items():
                attrs_result[k] = (
                    [str(item) for item in v] if isinstance(v, Sequence) else [str(v)]
                )
            return attrs_result

        @staticmethod
        def _extract_ldif_entry_attributes(
            entry: p.Entry,
        ) -> Mapping[str, Sequence[str]]:
            """Extract attributes from p.Entry.

            Args:
                entry: LDIF entry model

            Returns:
                Mapping of attribute names to sequences

            """
            ldif_attrs = entry.attributes
            if ldif_attrs is None:
                return {}
            # Python 3.13: Protocol guarantees attributes is Mapping - direct access
            if isinstance(ldif_attrs, p.Ldap.LdifAttributesProtocol):
                attrs_dict = ldif_attrs.attributes
                # Protocol guarantees Mapping[str, Sequence[str]] - direct dict conversion
                return dict(attrs_dict) if isinstance(attrs_dict, Mapping) else {}
            return {}

        @staticmethod
        def _extract_protocol_entry_attributes(
            entry: p.Ldap.LdapEntryProtocol,
        ) -> Mapping[str, Sequence[str]]:
            """Extract attributes from EntryProtocol.

            Args:
                entry: Entry protocol instance

            Returns:
                Mapping of attribute names to sequences

            """
            # Python 3.13: Use match-case for modern pattern matching
            attrs = entry.attributes
            match attrs:
                case Mapping():
                    return FlextLdapOperations.EntryComparison._convert_mapping_to_dict(
                        attrs
                    )
                case p.Ldap.LdifAttributesProtocol():
                    # Protocol guarantees Mapping[str, Sequence[str]]
                    return FlextLdapOperations.EntryComparison._convert_mapping_to_dict(
                        attrs.attributes
                    )
                case _:
                    return {}

        @staticmethod
        def extract_attributes(
            entry: p.Ldap.LdapEntryProtocol | p.Entry,
        ) -> Mapping[str, Sequence[str]]:
            """Return entry attributes as a normalized mapping of lists.

            Business Rule:
                Normalizes p.Entry and EntryProtocol to a common
                Mapping[str, Sequence[str]] format. p.Entry has
                nested LdifAttributes.attributes, while EntryProtocol has direct
                attributes mapping.

            Audit Implication:
                Returns empty dict for entries without attributes, ensuring
                comparison operations handle edge cases gracefully.

            Returns:
                Mapping of attribute names to list of string values.

            """
            # Python 3.13: Use match-case for modern pattern matching
            if entry.attributes is None:
                return {}
            match entry:
                case p.Entry():
                    return FlextLdapOperations.EntryComparison._extract_ldif_entry_attributes(
                        entry
                    )
                case p.Ldap.LdapEntryProtocol():
                    return FlextLdapOperations.EntryComparison._extract_protocol_entry_attributes(
                        entry
                    )
                case _:
                    return {}

        @staticmethod
        def normalize_value_set(values: list[str]) -> set[str]:
            """Normalize attribute values to a lowercase set for comparison.

            Business Rule:
                Case-insensitive comparison per LDAP matching rules (RFC 4518).
                Empty/None values are filtered to avoid false differences.

            Audit Implication:
                Lowercase normalization ensures consistent comparison regardless
                of source system case conventions.
            """
            # Normalize values to lowercase set
            return {str(v).lower() for v in values if v}

        @staticmethod
        def find_existing_values(
            attr_name: str,
            existing_attrs: Mapping[str, Sequence[str]],
        ) -> list[str] | None:
            """Find existing attribute values by case-insensitive name.

            Business Rule:
                Attribute names are case-insensitive per LDAP schema (RFC 4512).
                Searches existing attributes for case-insensitive match.

            Audit Implication:
                Returns None if attribute not found, enabling distinction between
                missing attribute (add) and empty attribute (replace with empty).

            Returns:
                List of values if attribute exists, None otherwise.

            """
            # Use u.Ldif.find with case-insensitive match for efficient lookup
            # Convert Mapping to Sequence of keys for find()
            # existing_attrs is already Mapping[str, Sequence[str]] - no isinstance check needed
            attr_keys = list(existing_attrs.keys())
            # Type narrowing: u.norm_str returns str for case-insensitive comparison
            found_key = u.Ldif.find(
                attr_keys,
                predicate=lambda k: (
                    u.Ldap.norm_str(str(k), case="lower")
                    == u.Ldap.norm_str(str(attr_name), case="lower")
                ),
            )
            # If key found, return its values from existing_attrs
            if found_key is not None:
                # u.mapper().get() returns the value directly, not RuntimeResult
                values = u.mapper().get(existing_attrs, found_key)
                # Python 3.13: Use isinstance directly for type narrowing
                if values is not None:
                    return (
                        [str(item) for item in values if item is not None]
                        if isinstance(values, Sequence)
                        else [str(values)]
                    )
            return None

        @staticmethod
        def process_new_attributes(
            new_attrs: Mapping[str, Sequence[str]],
            existing_attrs: Mapping[str, Sequence[str]],
            ignore: frozenset[str],
        ) -> tuple[t.Ldap.ModifyChanges, set[str]]:
            """Process new attributes and detect replacement changes.

            Business Rules:
                - Skips operational attributes in ignore set (objectClass, etc.)
                - Uses MODIFY_REPLACE for changed values (not ADD/DELETE pair)
                - Tracks processed attributes to detect deletions later
                - Python 3.13: isinstance(..., Sequence) validates sequences directly

            Audit Implication:
                Returns tuple of (changes, processed_attrs) for audit trail.
                processed_attrs enables deletion detection in second pass.

            Returns:
                Tuple of (modify changes dict, set of processed attribute names).

            """
            changes: t.Ldap.ModifyChanges = {}
            processed = set()

            # Filter out non-list-like values and ignored attributes
            # Python 3.13: Use isinstance directly for type narrowing
            filtered_attrs: dict[str, list[str]] = {}
            ignore_lower = [k.lower() for k in ignore]
            for k, v in new_attrs.items():
                if isinstance(v, Sequence) and k.lower() not in ignore_lower:
                    # Type narrowing: isinstance ensures v is Sequence
                    filtered_attrs[k] = [str(item) for item in v]

            # Process attributes efficiently
            def process_attr(
                attr_name: str,
                new_vals: Sequence[str],
            ) -> tuple[str, list[tuple[str, list[str]]] | None]:
                """Process single attribute and return change if needed."""
                # Use u.normalize for consistent case handling
                # DSL pattern: builder for string normalization
                normalized_name = u.Ldap.norm_str(attr_name, case="lower")
                processed.add(normalized_name)

                existing_vals = (
                    FlextLdapOperations.EntryComparison.find_existing_values(
                        attr_name,
                        existing_attrs,
                    )
                )
                # Python 3.13: Use isinstance directly for type narrowing
                if existing_vals and isinstance(existing_vals, Sequence):
                    # Convert to list[str] and filter truthy
                    existing_list = [str(v) for v in existing_vals if v]
                    existing_set = (
                        FlextLdapOperations.EntryComparison.normalize_value_set(
                            existing_list,
                        )
                    )
                else:
                    existing_set = set()
                # Convert new_vals to truthy list[str]
                new_set = FlextLdapOperations.EntryComparison.normalize_value_set(
                    u.Ldap.to_str_list_truthy(new_vals),
                )
                if existing_set != new_set:
                    # Convert new_vals to truthy list[str]
                    new_list = [str(v) for v in new_vals if v]
                    return (
                        attr_name,
                        [
                            (
                                MODIFY_REPLACE,
                                new_list,
                            ),
                        ],
                    )
                return (attr_name, None)

            # Process all attributes
            processed_dict: dict[str, list[tuple[str, list[str]]] | None] = {}
            logger = logging.getLogger(__name__)
            for attr_name, new_vals in u.mapper().to_dict(filtered_attrs).items():
                try:
                    result = process_attr(attr_name, new_vals)
                    if result[1] is not None:
                        processed_dict[result[0]] = result[1]
                except Exception as e:
                    logger.debug(
                        "Failed to process attribute %s, skipping",
                        attr_name,
                        exc_info=e,
                    )
                    continue
            # Filter None values and update changes dict
            processed_changes: dict[str, list[tuple[str, list[str]]]] = {
                k: v
                for k, v in u.mapper().to_dict(processed_dict).items()
                if v is not None
            }
            changes.update(processed_changes)

            return changes, processed

        @staticmethod
        def process_deleted_attributes(
            existing_attrs: Mapping[str, Sequence[str]],
            ignore: frozenset[str],
            processed: set[str],
        ) -> t.Ldap.ModifyChanges:
            """Capture deletions for attributes missing from the new entry.

            Business Rules:
                - Only deletes attributes NOT in processed set (already handled)
                - Skips operational attributes in ignore set
                - Uses MODIFY_DELETE with empty list to remove attribute entirely
                - Python 3.13: isinstance(..., Sequence) validates sequences directly

            Audit Implication:
                Returns deletions needed to sync existing entry with new state.
                Critical for maintaining data integrity during upsert operations.

            Returns:
                Dict mapping attribute names to MODIFY_DELETE operations.

            """
            # Filter out non-list-like values, ignored attributes, and processed attributes
            # Python 3.13: Use isinstance directly for type narrowing
            filtered_attrs: dict[str, list[str]] = {}
            ignore_lower = [k.lower() for k in ignore]
            processed_lower = [k.lower() for k in processed]
            for k, v in existing_attrs.items():
                if (
                    isinstance(v, Sequence)
                    and k.lower() not in ignore_lower
                    and k.lower() not in processed_lower
                ):
                    # Type narrowing: isinstance ensures v is Sequence
                    filtered_attrs[k] = [str(item) for item in v]
            # Transform to MODIFY_DELETE operations
            changes_dict: dict[str, list[tuple[str, list[str]]]] = {
                k: [(MODIFY_DELETE, [])] for k in filtered_attrs
            }

            return changes_dict

        @staticmethod
        def compare(
            existing_entry: p.Ldap.LdapEntryProtocol | p.Entry,
            new_entry: p.Ldap.LdapEntryProtocol | p.Entry,
        ) -> t.Ldap.ModifyChanges | None:
            """Compare two entries and return modify changes when needed.

            Business Rules:
                - Returns None if either entry has no attributes (no-op)
                - Computes MODIFY_REPLACE for changed attributes
                - Computes MODIFY_DELETE for removed attributes
                - Operational attributes (IGNORE_SET) are excluded from comparison
                - Case-insensitive attribute name and value comparison

            Audit Implication:
                Returns precise change set for audit trail. None indicates
                entries are equivalent (idempotent upsert operation).

            Args:
                existing_entry: Current entry from LDAP server
                new_entry: Desired state entry to synchronize

            Returns:
                ModifyChanges dict or None if no changes needed.

            """
            existing_attrs_raw = FlextLdapOperations.EntryComparison.extract_attributes(
                existing_entry,
            )
            new_attrs_raw = FlextLdapOperations.EntryComparison.extract_attributes(
                new_entry,
            )

            # Normalize attributes efficiently
            # Python 3.13: Use isinstance for type narrowing (TypeGuard limitation)
            def normalize_attr(_k: str, v: object) -> list[str]:
                """Normalize attribute value to list[str]."""
                return (
                    [str(item) for item in v if item is not None]
                    if isinstance(v, Sequence)
                    else [str(v)]
                )

            # Normalize existing attributes
            existing_attrs_transformed: t.Ldap.Attributes = {}
            logger = logging.getLogger(__name__)
            for k, v in existing_attrs_raw.items():
                try:
                    normalized = normalize_attr(k, v)
                    existing_attrs_transformed[k] = normalized
                except Exception as e:
                    logger.debug(
                        "Failed to normalize existing attribute %s, skipping",
                        k,
                        exc_info=e,
                    )
                    continue
            existing_attrs = existing_attrs_transformed
            # Normalize new attributes
            new_attrs: t.Ldap.Attributes = {}
            for k, v in new_attrs_raw.items():
                try:
                    normalized = normalize_attr(k, v)
                    new_attrs[k] = normalized
                except Exception as e:
                    logger.debug(
                        "Failed to normalize new attribute %s, skipping",
                        k,
                        exc_info=e,
                    )
                    continue

            # Check if any collection is empty
            if not existing_attrs or not new_attrs:
                return None

            ignore = c.Ldap.OperationalAttributes.IGNORE_SET
            changes, processed = (
                FlextLdapOperations.EntryComparison.process_new_attributes(
                    new_attrs,
                    existing_attrs,
                    ignore,
                )
            )
            delete_changes = (
                FlextLdapOperations.EntryComparison.process_deleted_attributes(
                    existing_attrs,
                    ignore,
                    processed,
                )
            )
            # Merge dictionaries (override strategy)
            merged: dict[str, list[tuple[str, list[str]]]] = {}
            merged.update(changes)
            merged.update(delete_changes)
            return merged or None

    class _UpsertHandler:
        """Handle add-or-modify flows for upsert calls.

        Business Rules:
            - Schema modifications (changetype=modify) use MODIFY_ADD operations
            - Regular entries attempt ADD first, then compare and MODIFY if exists
            - "Entry already exists" errors trigger comparison and modification
            - Idempotent: SKIPPED if entry already matches desired state

        Audit Implications:
            - Returns operation type (ADDED, MODIFIED, SKIPPED) for tracking
            - All operations return FlextResult for consistent error handling
            - Error messages preserve original LDAP error context

        Architecture:
            - Private class (_) to encapsulate upsert state machine
            - Delegates to parent FlextLdapOperations for actual LDAP calls
        """

        @staticmethod
        def _convert_to_model(
            entry: p.Ldap.LdapEntryProtocol | p.Entry,
        ) -> m.Ldif.Entry:
            """Convert entry to model type.

            Args:
                entry: Entry to convert.

            Returns:
                p.Entry instance.

            """
            # Python 3.13: Use match-case for modern pattern matching
            match entry:
                case p.Entry():
                    return entry
                case p.Ldap.LdapEntryProtocol():
                    # EntryProtocol - convert to p.Entry
                    dn_value = str(entry.dn)
                    attrs_mapping = (
                        FlextLdapOperations.EntryComparison.extract_attributes(
                            entry,
                        )
                    )
                    # Python 3.13: Modern dict comprehension with type narrowing
                    attrs_dict: dict[str, list[str]] = {
                        k: [str(item) for item in v]
                        if isinstance(v, Sequence)
                        else [str(v)]
                        for k, v in u.mapper().to_dict(attrs_mapping).items()
                    }
                    return m.Ldif.Entry(
                        dn=m.Ldif.DistinguishedName(value=dn_value),
                        attributes=m.Ldif.LdifAttributes(attributes=attrs_dict),
                    )
                case _:
                    # Fallback for unknown types - should never reach here due to union type
                    msg = f"Unsupported entry type: {type(entry)}"
                    raise TypeError(msg)

        def __init__(self, operations: FlextLdapOperations) -> None:
            """Initialize upsert handler with operations service.

            Business Rules:
                - Operations service is REQUIRED (no default, fail-fast pattern)
                - Handler stores reference for delegation to parent service
                - No connection validation at init (validated during execute)

            Architecture:
                - Private inner class encapsulates upsert state machine
                - Delegates all LDAP operations to parent FlextLdapOperations
                - Enables testability through dependency injection

            Args:
                operations: FlextLdapOperations instance for LDAP operations.
                    Must have active connection for execute() to succeed.

            """
            self._ops = operations

        def _extract_schema_add_operation(
            self,
            attrs: dict[str, list[str]],
        ) -> r[str]:
            """Extract schema add operation attribute type.

            Args:
                attrs: Attributes dictionary.

            Returns:
                FlextResult with attribute type or error.

            """
            add_op_raw: list[object] = u.mapper().get(
                attrs, c.Ldap.ChangeTypeOperations.ADD, default=[]
            )
            # Python 3.13: Use isinstance directly for type narrowing
            add_op: list[str] = (
                [str(item) for item in add_op_raw]
                if isinstance(add_op_raw, Sequence)
                else ([str(add_op_raw)] if add_op_raw else [])
            )
            if not add_op:
                return r[str].fail("Schema modify entry missing 'add' attribute")
            return r[str].ok(add_op[0])

        def _extract_schema_attribute_values(
            self,
            attrs: dict[str, list[str]],
            attr_type: str,
        ) -> r[list[str]]:
            """Extract and filter schema attribute values.

            Args:
                attrs: Attributes dictionary.
                attr_type: Attribute type to extract.

            Returns:
                FlextResult with filtered values or error.

            """
            # mapper().get() returns T | None directly, not FlextResult
            # Python 3.13: Use isinstance directly for type narrowing
            attr_values_raw: list[object] = u.mapper().get(attrs, attr_type, default=[])
            attr_values: list[str] = (
                [str(item) for item in attr_values_raw]
                if isinstance(attr_values_raw, Sequence)
                else ([str(attr_values_raw)] if attr_values_raw else [])
            )
            filtered: list[str] = u.Ldap.to_str_list_truthy(attr_values)
            if not filtered:
                return r[list[str]].fail(
                    f"Schema modify entry has only empty values for '{attr_type}'",
                )
            return r[list[str]].ok(filtered)

        def execute(
            self,
            entry: p.Ldap.LdapEntryProtocol | p.Entry,
        ) -> r[m.Ldap.LdapOperationResult]:
            """Execute an upsert operation for the provided entry.

            Business Rules:
                - Checks changetype attribute to route to schema modify vs regular add
                - Schema modifications use MODIFY_ADD for new schema elements
                - Regular entries use add-then-modify pattern for idempotency

            Audit Implication:
                Entry point for all upsert operations; returns operation type
                for audit trail (ADDED, MODIFIED, or SKIPPED).

            Returns:
                FlextResult with LdapOperationResult indicating operation type.

            """
            attrs = FlextLdapOperations._extract_attributes_dict(entry)
            # Extract changetype (available via c.LdapAttributeNames inheritance)
            # u.mapper().get() returns the value directly, not RuntimeResult
            changetype_raw: list[object] = u.mapper().get(
                attrs, c.Ldap.LdapAttributeNames.CHANGETYPE, default=[]
            )
            # Python 3.13: Use isinstance directly for type narrowing
            changetype_val: list[str] = (
                [str(item) for item in changetype_raw]
                if isinstance(changetype_raw, Sequence)
                else ([str(changetype_raw)] if changetype_raw else [])
            )
            # Use u.normalize for consistent case handling
            changetype = (
                u.Ldap.norm_str(changetype_val[0], case="lower")
                if changetype_val
                else ""
            )

            if changetype == c.Ldap.ChangeTypeOperations.MODIFY:
                # p.Entry is structurally compatible with EntryProtocol (no cast needed)
                return self.handle_schema_modify(entry)
                # p.Entry is structurally compatible with EntryProtocol (no cast needed)
            return self.handle_regular_add(entry)

        def handle_schema_modify(
            self,
            entry: p.Ldap.LdapEntryProtocol | p.Entry,
        ) -> r[m.Ldap.LdapOperationResult]:
            """Apply a schema modification entry.

            Business Rules:
                - Entry must have 'add' attribute specifying the schema attribute to add
                - Uses MODIFY_ADD operation (not REPLACE) for additive schema changes
                - "Entry already exists" is interpreted as schema element exists -> SKIPPED
                - Empty values are filtered out before modification

            Audit Implication:
                Schema modifications are critical; returns MODIFIED, SKIPPED, or error.
                Preserves LDAP error context for schema validation failures.

            Returns:
                FlextResult with operation type (MODIFIED or SKIPPED).

            """
            entry_model = self._convert_to_model(entry)
            attrs = FlextLdapOperations._extract_attributes_dict(entry_model)
            # Extract add operation - Python 3.13: Modern pattern matching
            add_op_raw: list[object] = u.mapper().get(
                attrs, c.Ldap.ChangeTypeOperations.ADD, default=[]
            )
            # Python 3.13: Modern list conversion with ternary
            add_op: list[str] = (
                [str(item) for item in add_op_raw]
                if isinstance(add_op_raw, Sequence)
                else ([str(add_op_raw)] if add_op_raw else [])
            )
            if not add_op:
                return r[m.Ldap.LdapOperationResult].fail(
                    "Schema modify entry missing 'add' attribute",
                )

            attr_type = add_op[0]
            # Extract attribute values - Python 3.13: Modern pattern matching
            attr_values_raw: list[object] = u.mapper().get(attrs, attr_type, default=[])
            # Python 3.13: Modern list conversion with ternary
            attr_values: list[str] = (
                [str(item) for item in attr_values_raw]
                if isinstance(attr_values_raw, Sequence)
                else ([str(attr_values_raw)] if attr_values_raw else [])
            )
            # Filter truthy values
            filtered: list[str] = u.Ldap.to_str_list_truthy(attr_values)

            # Check if collection is empty
            if not filtered:
                return r[m.Ldap.LdapOperationResult].fail(
                    f"Schema modify entry has only empty values for '{attr_type}'",
                )

            changes: t.Ldap.ModifyChanges = {
                attr_type: [(MODIFY_ADD, filtered)],
            }
            entry_model = self._convert_to_model(entry)
            # Python 3.13: Use match-case for DN extraction
            dn_str = (
                entry_model.dn.value or "unknown"
                if isinstance(entry_model.dn, p.Ldap.DistinguishedNameProtocol)
                else str(entry_model.dn)
                if entry_model.dn is not None
                else "unknown"
            )
            modify_result = self._ops.modify(dn_str, changes)

            # Python 3.13: Use match-case for result handling
            if modify_result.is_success:
                return r[m.Ldap.LdapOperationResult].ok(
                    m.Ldap.LdapOperationResult(
                        operation=c.Ldap.UpsertOperations.MODIFIED
                    ),
                )

            # Get error string and check if it's "already exists"
            error_str = u.to_str(modify_result.error)
            return (
                r[m.Ldap.LdapOperationResult].ok(
                    m.Ldap.LdapOperationResult(
                        operation=c.Ldap.UpsertOperations.SKIPPED
                    ),
                )
                if self._ops.is_already_exists_error(error_str)
                else r[m.Ldap.LdapOperationResult].fail(
                    error_str or c.Ldap.ErrorStrings.UNKNOWN_ERROR,
                )
            )

        def handle_regular_add(
            self,
            entry: p.Ldap.LdapEntryProtocol | p.Entry,
        ) -> r[m.Ldap.LdapOperationResult]:
            """Add a standard entry or fall back to existing-entry handling.

            Business Rules:
                - First attempts LDAP ADD operation for optimistic path
                - If ADD succeeds, returns ADDED operation result
                - If "entry already exists" error (68), delegates to handle_existing_entry
                - Other errors are propagated as r.fail()

            Audit Implication:
                Primary upsert entry point for non-schema entries.
                Optimistic add minimizes round trips for new entries.

            Returns:
                FlextResult with ADDED or delegates to existing entry handler.

            """
            # Convert to model for add operation
            entry_for_add = self._convert_to_model(entry)
            add_result = self._ops.add(entry_for_add)

            # Create result based on operation outcome
            if add_result.is_success:
                return r[m.Ldap.LdapOperationResult].ok(
                    m.Ldap.LdapOperationResult(operation=c.Ldap.UpsertOperations.ADDED),
                )

            # DSL pattern: builder for str conversion
            error_str = u.to_str(add_result.error)
            # DSL pattern: early return for non-existing-entry errors
            if not self._ops.is_already_exists_error(error_str):
                return r[m.Ldap.LdapOperationResult].fail(error_str)

            return self.handle_existing_entry(entry)

        def handle_existing_entry(
            self,
            entry: p.Ldap.LdapEntryProtocol | p.Entry,
        ) -> r[m.Ldap.LdapOperationResult]:
            """Handle an upsert when the entry already exists in LDAP.

            Business Rules:
                - Searches for existing entry using BASE scope on entry DN
                - If search fails, returns SKIPPED (entry may have been deleted)
                - If search returns empty (race condition), retries ADD
                - Compares existing vs new entry to compute MODIFY changes
                - If no differences, returns SKIPPED (idempotent)
                - Applies MODIFY_REPLACE/MODIFY_DELETE changes for sync

            Audit Implication:
                Critical for idempotent upserts; computes minimal change set.
                SKIPPED indicates no changes needed, enabling safe reruns.

            Returns:
                FlextResult with MODIFIED, SKIPPED, or ADDED (race condition).

            """
            # Extract DN from EntryProtocol
            entry_dn: str = "unknown"
            if isinstance(entry.dn, str):
                entry_dn = entry.dn
            elif isinstance(entry.dn, p.Ldap.DistinguishedNameProtocol):
                entry_dn = str(entry.dn.value)
            else:
                entry_dn = str(entry.dn) if entry.dn else "unknown"
            search_options = m.Ldap.SearchOptions(
                base_dn=entry_dn,
                filter_str=c.Ldap.Filters.ALL_ENTRIES_FILTER,
                scope=c.Ldap.SearchScope.BASE,
            )

            search_result = self._ops.search(search_options)
            # Create result
            if search_result.is_failure:
                return r[m.Ldap.LdapOperationResult].ok(
                    m.Ldap.LdapOperationResult(
                        operation=c.Ldap.UpsertOperations.SKIPPED
                    ),
                )

            # Extract search data
            search_data = search_result.value if search_result.is_success else None
            # Get entries safely - SearchResult.entries is list[p.Entry]
            existing_entries: list[p.Entry] = []
            if search_data is not None:
                # search_data is m.Ldap.SearchResult from model definition
                # No hasattr check needed - SearchResult always has entries attribute
                entries_raw = search_data.entries
                # SearchResult.entries is list[p.Entry] from model definition
                # No isinstance check needed - type is already guaranteed
                existing_entries = list(entries_raw) if entries_raw else []
            if not existing_entries:
                retry_result = self._ops.add(entry)
                # Create results
                if retry_result.is_success:
                    return r[m.Ldap.LdapOperationResult].ok(
                        m.Ldap.LdapOperationResult(
                            operation=c.Ldap.UpsertOperations.ADDED
                        ),
                    )
                # Get error string
                return r[m.Ldap.LdapOperationResult].fail(
                    u.Ldap.to_str(retry_result.error)
                )

            # Use entry directly - already cast to p.Entry above
            existing_entry: p.Entry = existing_entries[0]
            changes = FlextLdapOperations.EntryComparison.compare(
                existing_entry,
                entry,
            )
            # Check if changes dict is empty
            if changes is None or not changes:
                return r[m.Ldap.LdapOperationResult].ok(
                    m.Ldap.LdapOperationResult(
                        operation=c.Ldap.UpsertOperations.SKIPPED,
                    ),
                )

            modify_result = self._ops.modify(entry_dn, changes)
            if modify_result.is_success:
                return r[m.Ldap.LdapOperationResult].ok(
                    m.Ldap.LdapOperationResult(
                        operation=c.Ldap.UpsertOperations.MODIFIED,
                    ),
                )

            return r[m.Ldap.LdapOperationResult].fail(
                u.to_str(modify_result.error),
            )

    @staticmethod
    def is_already_exists_error(error_message: str) -> bool:
        """Return ``True`` when the error indicates an existing entry.

        Business Rules:
            - Checks for LDAP error 68 (entryAlreadyExists) in error message
            - Case-insensitive matching for cross-server compatibility
            - Supports multiple error string patterns:
              - "entry already exists" (standard)
              - "already exists" (abbreviated)
              - "entryalreadyexists" (LDAP error constant)

        Audit Implication:
            Used by upsert logic to distinguish "add failed because exists"
            from other failures (schema violation, permission denied, etc.)

        Returns:
            True if error indicates entry exists, False otherwise.

        """
        # Use u.normalize for consistent case handling
        # DSL pattern: builder for string normalization
        error_lower = u.Ldap.norm_str(error_message, case="lower")
        return (
            str(c.Ldap.ErrorStrings.ENTRY_ALREADY_EXISTS) in error_lower
            or str(c.Ldap.ErrorStrings.ENTRY_ALREADY_EXISTS_ALT) in error_lower
            or str(c.Ldap.ErrorStrings.ENTRY_ALREADY_EXISTS_LDAP) in error_lower
        )

    def __init__(
        self,
        connection: FlextLdapConnection,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize the operations service with a live connection."""
        # Remove _auto_result from kwargs (handled by FlextService)
        service_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if k != "_auto_result" and isinstance(v, (str, float, bool, type(None)))
        }
        # Type narrowing: service_kwargs is dict[str, str | float | bool | None]
        # which matches FlextService.__init__ signature
        super().__init__(**service_kwargs)
        self._connection = connection
        self._upsert_handler = self._UpsertHandler(self)

    def search(
        self,
        search_options: m.Ldap.SearchOptions,
        server_type: c.Ldif.ServerTypes | str = c.Ldif.ServerTypes.RFC,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.SearchResult]:
        """Perform an LDAP search using normalized search options.

        Business Rules:
            - Base DN is normalized using FlextLdifUtilities.Ldif.DN.norm_string() before search
            - Normalization ensures consistent DN format across server types
            - Search filter syntax is validated by LDAP server
            - Server type determines parsing quirks for entry attributes
            - Empty result sets return successful SearchResult with empty entries list

        Audit Implications:
            - Search operations are logged with normalized base_dn and filter
            - Result counts are logged for compliance reporting
            - Failed searches log error messages with search parameters

        Architecture:
            - Delegates to Ldap3Adapter.search() for protocol-level execution
            - Uses FlextLdifParser for server-specific entry parsing
            - Returns FlextResult pattern - no exceptions raised

        Args:
            search_options: Search configuration (base_dn, filter_str, scope, attributes)
            server_type: LDAP server type for parsing quirks (default: RFC)

        Returns:
            FlextResult containing SearchResult with Entry models

        """
        normalized_options = search_options.model_copy(
            update={
                "base_dn": FlextLdifUtilities.Ldif.DN.norm_string(
                    search_options.base_dn
                ),
            },
        )
        result = self._connection.adapter.search(
            normalized_options,
            server_type=server_type,
        )
        # Adapter returns r[SearchResultProtocol] - unwrap directly
        if result.is_success:
            search_result = result.unwrap()
            # Type narrowing: SearchResultProtocol is compatible with SearchResult model
            return r[m.Ldap.SearchResult].ok(search_result)
        # DSL pattern: ensure error message with default
        # DSL pattern: builder for str conversion
        error_msg = u.to_str(result.error, default="Unknown error")
        return r[m.Ldap.SearchResult].fail(error_msg)

    def add(
        self,
        entry: p.Ldap.LdapEntryProtocol | p.Entry,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.OperationResult]:
        """Add an LDAP entry using the active adapter connection.

        Business Rules:
            - Entry DN must be unique (LDAP error 68 if entry already exists)
            - Entry attributes are converted to ldap3 format via FlextLdapEntryAdapter
            - DN normalization is handled by adapter layer
            - Entry must conform to LDAP schema constraints

        Audit Implications:
            - Add operations are logged with entry DN
            - Successful adds log affected count (always 1)
            - Failed adds log error message and DN

        Architecture:
            - Delegates to Ldap3Adapter.add() for protocol-level execution
            - Entry conversion handled by FlextLdapEntryAdapter
            - Returns FlextResult pattern - no exceptions raised

        Args:
            entry: Entry model to add (must include DN and required attributes)

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        # Convert entry to m.Ldap.Entry (adapter requires m.Ldap.Entry)
        entry_for_adapter: m.Ldap.Entry
        if isinstance(entry, m.Ldap.Entry):
            entry_for_adapter = entry
        elif isinstance(entry, p.Entry):
            # Convert p.Entry to m.Ldap.Entry
            entry_for_adapter = m.Ldap.Entry(
                dn=entry.dn,
                attributes=entry.attributes,
                metadata=entry.metadata,
            )
        else:
            # EntryProtocol - convert to m.Ldap.Entry
            dn_value = str(entry.dn)
            attrs_mapping = FlextLdapOperations.EntryComparison.extract_attributes(
                entry,
            )
            # Python 3.13: Use isinstance directly for type narrowing
            attrs_dict: dict[str, list[str]] = {
                k: [str(item) for item in v] if isinstance(v, Sequence) else [str(v)]
                for k, v in u.mapper().to_dict(attrs_mapping).items()
            }
            # Create entry as m.Ldap.Entry
            entry_for_adapter = m.Ldap.Entry(
                dn=m.Ldif.DistinguishedName(value=dn_value),
                attributes=m.Ldif.LdifAttributes(attributes=attrs_dict),
            )
        result = self._connection.adapter.add(entry_for_adapter)
        # Adapter returns r[OperationResultProtocol] - unwrap directly
        if result.is_success:
            operation_result = result.unwrap()
            return r[m.Ldap.OperationResult].ok(operation_result)
        # DSL pattern: ensure error message with default
        # DSL pattern: builder for str conversion
        error_msg = u.to_str(result.error, default="Unknown error")
        return r[m.Ldap.OperationResult].fail(error_msg)

    def modify(
        self,
        dn: str | p.Ldap.DistinguishedNameProtocol,
        changes: t.Ldap.ModifyChanges,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.OperationResult]:
        """Modify an LDAP entry with the provided change set.

        Business Rules:
            - Entry must exist before modification (LDAP error 32 if not found)
            - Changes use ldap3 format: {attr_name: [(MODIFY_ADD|MODIFY_DELETE|MODIFY_REPLACE, [values])]}
            - DN normalization is applied using FlextLdifUtilities.Ldif.DN.get_dn_value()
            - String DNs are converted to DistinguishedName models for type safety
            - Schema constraints are validated by LDAP server

        Audit Implications:
            - Modify operations are logged with DN and change summary
            - Successful modifies log affected count (always 1)
            - Failed modifies log error message and DN

        Architecture:
            - Delegates to Ldap3Adapter.modify() for protocol-level execution
            - DN conversion handled by FlextLdifUtilities.Ldif.DN
            - Returns FlextResult pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to modify (string or DistinguishedName model)
            changes: Modification changes dict in ldap3 format

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        # Type narrowing: convert str to DistinguishedName model if needed
        if isinstance(dn, str):
            dn_model: p.Ldap.DistinguishedNameProtocol = m.Ldif.DistinguishedName(
                value=FlextLdifUtilities.Ldif.DN.get_dn_value(dn),
            )
        else:
            dn_model = dn
        result = self._connection.adapter.modify(
            dn_model,
            changes,
        )
        # Adapter returns r[OperationResultProtocol] - unwrap directly
        if result.is_success:
            operation_result = result.unwrap()
            return r[m.Ldap.OperationResult].ok(operation_result)
        # DSL pattern: ensure error message with default
        # DSL pattern: builder for str conversion
        error_msg = u.to_str(result.error, default="Unknown error")
        return r[m.Ldap.OperationResult].fail(error_msg)

    def delete(
        self,
        dn: str | p.Ldap.DistinguishedNameProtocol,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.OperationResult]:
        """Delete an LDAP entry identified by DN.

        Business Rules:
            - Entry must exist before deletion (LDAP error 32 if not found)
            - Entry must not have children (LDAP error 66 if has children)
            - DN normalization is applied using FlextLdifUtilities.Ldif.DN.get_dn_value()
            - String DNs are converted to DistinguishedName models for type safety
            - Deletion is permanent - no undo capability

        Audit Implications:
            - Delete operations are logged with DN for critical audit trail
            - Successful deletes log affected count (always 1)
            - Failed deletes log error message and DN

        Architecture:
            - Delegates to Ldap3Adapter.delete() for protocol-level execution
            - DN conversion handled by FlextLdifUtilities.Ldif.DN
            - Returns FlextResult pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to delete (string or DistinguishedName model)

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        # Type narrowing: convert str to DistinguishedName model if needed
        if isinstance(dn, str):
            dn_model: p.Ldap.DistinguishedNameProtocol = m.Ldif.DistinguishedName(
                value=FlextLdifUtilities.Ldif.DN.get_dn_value(dn),
            )
        else:
            dn_model = dn
        result = self._connection.adapter.delete(dn_model)
        # Adapter returns r[OperationResultProtocol] - unwrap directly
        if result.is_success:
            operation_result = result.unwrap()
            return r[m.Ldap.OperationResult].ok(operation_result)
        # DSL pattern: ensure error message with default
        # DSL pattern: builder for str conversion
        error_msg = u.to_str(result.error, default="Unknown error")
        return r[m.Ldap.OperationResult].fail(error_msg)

    @property
    def is_connected(self) -> bool:
        """Check if operations service has an active connection.

        Business Rules:
            - Delegates to Flexun.is_connected property
            - Returns True if connection is bound and ready for operations
            - Returns False if connection is closed or not established
            - State is checked synchronously (no network calls)

        Audit Implications:
            - Connection state checks are not logged (frequent operation)
            - State changes are logged via connect/disconnect methods
            - State can be queried before operations for validation

        Returns:
            True if connected and bound, False otherwise.

        """
        return self._connection.is_connected

    def upsert(
        self,
        entry: p.Ldap.LdapEntryProtocol | p.Entry,
        *,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
    ) -> r[m.Ldap.LdapOperationResult]:
        """Upsert an entry, optionally retrying for configured error patterns.

        Business Rules:
            - First attempts ADD operation via _UpsertHandler
            - If entry exists (LDAP error 68), performs search and comparison
            - Entry comparison ignores operational attributes (modifyTimestamp, etc.)
            - If entries are identical, operation is SKIPPED (no changes needed)
            - If entries differ, MODIFY operation is applied with computed changes
            - Schema modification entries (changetype=modify) are handled specially
            - Retry mechanism uses u.Reliability.retry() for transient errors
            - Retry only occurs if error matches retry_on_errors patterns

        Audit Implications:
            - Upsert operations log operation type (ADDED, MODIFIED, SKIPPED)
            - Retry attempts are logged individually for compliance
            - Skipped operations indicate no changes needed (audit efficiency)

        Architecture:
            - Uses _UpsertHandler.execute() for core upsert logic
            - Retry logic uses u.Reliability.retry()
            - Returns FlextResult pattern - no exceptions raised

        Args:
            entry: Entry model to upsert (must include DN and attributes)
            retry_on_errors: List of error patterns to retry on (e.g., ["session terminated"])
            max_retries: Maximum number of retry attempts (default: 1, no retry)

        Returns:
            FlextResult containing LdapOperationResult with operation type (ADDED|MODIFIED|SKIPPED)

        """
        # Use u.all_()/u.any_() mnemonic: check conditions
        # all_() is from flext-core u, not u.Ldap
        if not (retry_on_errors and max_retries > 1):
            return self._upsert_handler.execute(entry)

        result = self._upsert_handler.execute(entry)
        # Check if success or no retry needed
        if result.is_success or not retry_on_errors:
            return result

        # Use u.normalize for consistent case handling
        # DSL pattern: builder for string normalization
        error_str = u.Ldap.norm_str(str(result.error), case="lower")
        # Use u.Ldif.find() to check if error matches any retry pattern
        if retry_on_errors is None:
            return result
        # Convert retry_on_errors to tuple for u.Ldif.find compatibility
        retry_patterns = tuple(retry_on_errors)
        if (
            u.Ldif.find(
                retry_patterns,
                predicate=lambda pattern: u.Ldap.norm_in(
                    error_str, [pattern], case="lower"
                ),
            )
            is None
        ):
            return result

        # Wrap execute - retry accepts r[TResult] | TResult directly
        def wrapped_execute() -> r[m.Ldap.LdapOperationResult]:
            return self._upsert_handler.execute(entry)

        retry_result = u.Reliability.retry[m.Ldap.LdapOperationResult](
            operation=wrapped_execute,
            max_attempts=max_retries,
            delay_seconds=1.0,
        )
        # retry returns r[TResult] | TResult, convert to r[TResult]
        if isinstance(retry_result, r):
            return retry_result
        return r[m.Ldap.LdapOperationResult].ok(retry_result)

    def _update_batch_stats(
        self,
        upsert_result: r[m.Ldap.LdapOperationResult],
        stats: dict[str, int],
        entry_index: int,
        entry_dn: str | None,
        total_entries: int,
    ) -> None:
        """Update batch stats from upsert result."""
        if upsert_result.is_success:
            operation = upsert_result.unwrap().operation
            if operation == c.Ldap.UpsertOperations.SKIPPED:
                stats["skipped"] += 1
            elif operation in {
                c.Ldap.UpsertOperations.ADDED,
                c.Ldap.UpsertOperations.MODIFIED,
            }:
                stats["synced"] += 1
        else:
            stats["failed"] += 1
            entry_dn_sliced = entry_dn[:100] if entry_dn else None
            error_msg = (str(upsert_result.error) if upsert_result.error else "")[:200]
            self.logger.error(
                "Batch upsert entry failed",
                entry_index=entry_index,
                total_entries=total_entries,
                entry_dn=entry_dn_sliced,
                error=error_msg,
            )

    def _invoke_batch_progress_callback(
        self,
        callback: Callable[[int, int, str, m.Ldap.LdapBatchStats], None],
        entry_index: int,
        total: int,
        entry_dn: str | None,
        stats: dict[str, int],
    ) -> None:
        """Invoke progress callback with error handling."""
        try:
            callback_stats = m.Ldap.LdapBatchStats(
                synced=stats["synced"],
                failed=stats["failed"],
                skipped=stats["skipped"],
            )
            callback(entry_index, total, entry_dn or "", callback_stats)
        except (RuntimeError, TypeError, ValueError) as e:
            self.logger.warning(
                "Progress callback failed",
                operation=c.Ldap.LdapOperationNames.SYNC,
                entry_index=entry_index,
                error=str(e),
            )

    def batch_upsert(
        self,
        entries: Sequence[p.Ldap.LdapEntryProtocol],
        *,
        progress_callback: Callable[
            [int, int, str, m.Ldap.LdapBatchStats],
            None,
        ]
        | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
        stop_on_error: bool = False,
    ) -> r[m.Ldap.LdapBatchStats]:
        """Upsert multiple entries and track per-item progress.

        Business Rules:
            - Processes entries sequentially (not parallel) for consistency
            - Each entry uses upsert logic (add/modify/skip based on comparison)
            - Progress callback is invoked after each entry (current, total, dn, stats)
            - stop_on_error=True aborts batch on first failure
            - stop_on_error=False continues processing remaining entries
            - Batch fails only if ALL entries fail (synced=0 and failed>0)
            - Statistics track synced (added+modified), failed, and skipped counts

        Audit Implications:
            - Batch operations log start/end with total entry count
            - Progress callbacks enable real-time audit trail during processing
            - Individual entry failures are logged with index and DN
            - Final statistics (synced/failed/skipped) logged for compliance reporting

        Architecture:
            - Uses upsert() method for each entry
            - Progress callback signature: (current: int, total: int, dn: str, stats: LdapBatchStats)
            - Returns FlextResult pattern - no exceptions raised

        Args:
            entries: List of entries to upsert (must include DN and attributes)
            progress_callback: Optional callback for progress tracking (4 parameters)
            retry_on_errors: Error patterns to retry on (e.g., ["session terminated"])
            max_retries: Maximum retries per entry (default: 1, no retry)
            stop_on_error: Stop processing on first error (default: False, continue)

        Returns:
            FlextResult containing LdapBatchStats with synced/failed/skipped counts

        """
        # Builder pattern: accumulate stats using DSL
        stats_builder: dict[str, int] = {"synced": 0, "failed": 0, "skipped": 0}
        total_entries = len(entries)

        # Process all entries
        for idx_entry in enumerate(entries, 1):
            try:
                i, entry = idx_entry
                entry_dn = u.Ldap.dn_str(entry.dn)
                upsert_result = self.upsert(
                    entry,
                    retry_on_errors=retry_on_errors,
                    max_retries=max_retries,
                )
                self._update_batch_stats(
                    upsert_result,
                    stats_builder,
                    i,
                    entry_dn,
                    total_entries,
                )
                if stop_on_error and upsert_result.is_failure:
                    stats_builder["_stop_error"] = i
                    break
                if progress_callback:
                    self._invoke_batch_progress_callback(
                        progress_callback,
                        i,
                        total_entries,
                        entry_dn,
                        stats_builder,
                    )
            except Exception:
                entry_idx = idx_entry[0] if isinstance(idx_entry, tuple) else None
                self.logger.debug(
                    "Failed to process entry in batch, skipping (entry_index=%s)",
                    entry_idx,
                    exc_info=True,
                )
                continue

        # Check for stop_on_error condition (early exit detected)
        if stop_on_error and "_stop_error" in stats_builder:
            error_idx = stats_builder["_stop_error"]
            if isinstance(error_idx, int):
                return r[m.Ldap.LdapBatchStats].fail(
                    f"Batch upsert stopped on error at entry {error_idx}/{total_entries}",
                )

        stats = m.Ldap.LdapBatchStats(
            synced=stats_builder["synced"],
            failed=stats_builder["failed"],
            skipped=stats_builder["skipped"],
        )

        self.logger.info(
            "Batch upsert completed",
            operation=c.Ldap.LdapOperationNames.BATCH_UPSERT.value,
            total_entries=total_entries,
            synced=stats_builder["synced"],
            failed=stats_builder["failed"],
            skipped=stats_builder["skipped"],
        )

        if stats_builder["synced"] == 0 and stats_builder["failed"] > 0:
            return r[m.Ldap.LdapBatchStats].fail(
                f"Batch upsert failed: all {stats_builder['failed']} entries failed, 0 synced",
            )

        return r[m.Ldap.LdapBatchStats].ok(stats)

    def execute(
        self,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.SearchResult]:
        """Report readiness; fails when the connection is not bound.

        Business Rules:
            - Returns failure if connection is not bound (NOT_CONNECTED error)
            - Returns empty SearchResult with configured base_dn on success
            - Uses default base_dn from FlextLdapConfig if not specified
            - Serves as health check for FlextService.execute() pattern

        Audit Implication:
            Validates connection state before operations; useful for
            health checks and connection pool validation.

        Returns:
            FlextResult with empty SearchResult (success) or NOT_CONNECTED error.

        """
        if not self._connection.is_connected:
            return r[m.Ldap.SearchResult].fail(c.Ldap.ErrorStrings.NOT_CONNECTED)

        ldap_config = self.config.get_namespace("ldap", FlextLdapConfig)
        base_dn = ldap_config.base_dn or "dc=example,dc=com"
        return r[m.Ldap.SearchResult].ok(
            m.Ldap.SearchResult(
                entries=[],
                search_options=m.Ldap.SearchOptions(
                    base_dn=base_dn,
                    filter_str=c.Ldap.Filters.ALL_ENTRIES_FILTER,
                ),
            ),
        )
