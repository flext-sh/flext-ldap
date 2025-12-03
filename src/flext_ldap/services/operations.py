"""Search, CRUD, and upsert helpers built on ``Ldap3Adapter``.

This module keeps protocol concerns inside the adapter while exposing typed
inputs, normalized results, and reusable comparison utilities for callers.

Business Rules:
    - All LDAP operations are delegated to the adapter layer (Ldap3Adapter)
    - DN normalization is applied before all search operations using
      FlextLdifUtilities.DN.norm_string() to ensure consistent DN format
            - Entry comparison ignores operational attributes defined in
      c.OperationalAttributes.IGNORE_SET
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
    - FlextRuntime.is_list_like() used for type narrowing (not isinstance)
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import cast

from flext_core import FlextRuntime
from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.utilities import FlextLdifUtilities
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from pydantic import ConfigDict

from flext_ldap import c, m, p, r, t, u
from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.config import FlextLdapConfig
from flext_ldap.services.connection import FlextLdapConnection


class FlextLdapOperations(FlextLdapServiceBase[m.SearchResult]):
    """Coordinate LDAP operations on an active connection.

    Protocol calls are delegated to :class:`~flext_ldap.adapters.ldap3.Ldap3Adapter`
    so this layer can concentrate on typed arguments, predictable
    :class:`flext_core.FlextResult` responses, and shared comparison helpers.

    Business Rules:
        - Connection must be bound before operations (validated via is_connected)
        - Search operations normalize base_dn using FlextLdifUtilities.DN.norm_string()
        - Add/Modify/Delete operations convert string DNs to DistinguishedName models
        - Upsert implements LDAP idempotent write: add → exists check → modify
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
        >>> result = ops.search(m.SearchOptions(base_dn="dc=example,dc=com"))
        >>> if result.is_success:
        ...     entries = result.unwrap().entries

    """

    model_config = ConfigDict(
        frozen=False,  # Service needs mutable state for connection reference
        extra="allow",
        arbitrary_types_allowed=True,
    )

    _connection: FlextLdapConnection

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
            - Changes dict maps attribute name → list of LDAP modify operations

        Performance Notes:
            - O(n) for attribute extraction and comparison
            - Uses set comparison for value differences (O(1) lookups)
        """

        @staticmethod
        def extract_attributes(
            entry: p.LdapEntry.EntryProtocol | FlextLdifModels.Entry,
        ) -> Mapping[str, Sequence[str]]:
            """Return entry attributes as a normalized mapping of lists.

            Business Rule:
                Normalizes FlextLdifModels.Entry and EntryProtocol to a common
                Mapping[str, Sequence[str]] format. FlextLdifModels.Entry has
                nested LdifAttributes.attributes, while EntryProtocol has direct
                attributes mapping.

            Audit Implication:
                Returns empty dict for entries without attributes, ensuring
                comparison operations handle edge cases gracefully.

            Returns:
                Mapping of attribute names to list of string values.

            """
            if not entry.attributes:
                return {}
            # Type narrowing: FlextLdifModels.Entry has LdifAttributes with .attributes
            if isinstance(entry, FlextLdifModels.Entry):
                # LdifAttributes has .attributes: dict[str, list[str]]
                ldif_attrs = entry.attributes
                if ldif_attrs and hasattr(ldif_attrs, "attributes"):
                    # Type is already dict[str, list[str]], no isinstance needed
                    return ldif_attrs.attributes
                return {}
            # EntryProtocol has attributes: Mapping[str, Sequence[str]]
            attrs = entry.attributes
            if isinstance(attrs, Mapping):
                # Use u.process() for consistent conversion
                transform_result = u.process(
                    attrs,
                    processor=lambda _k, v: list(v)
                    if FlextRuntime.is_list_like(v)
                    else [v],
                    on_error="collect",
                )
                transformed = (
                    transform_result.value
                    if transform_result.is_success
                    else cast("dict[str, list[str]]", dict(attrs))
                )
                return cast("Mapping[str, Sequence[str]]", transformed)
            if hasattr(attrs, "attributes"):
                attrs_dict = attrs.attributes
                # Type is already Mapping[str, Sequence[str]], isinstance check redundant
                # Use u.process() for consistent conversion
                transform_result = u.process(
                    attrs_dict,
                    processor=lambda _k, v: list(v)
                    if FlextRuntime.is_list_like(v)
                    else [v],
                    on_error="collect",
                )
                transformed = (
                    transform_result.value
                    if transform_result.is_success
                    else cast("dict[str, list[str]]", dict(attrs_dict))
                )
                return cast("Mapping[str, Sequence[str]]", transformed)
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
            # Use u.filter() and u.map() for consistent processing
            filtered = u.filter(values, predicate=bool)
            normalized = u.map(
                cast("list[str]", filtered),
                mapper=lambda v: cast(
                    "str",
                    u.normalize(
                        cast("str", u.ensure(v, target_type="str", default="")),
                        case="lower",
                    ),
                ),
            )
            return set(cast("list[str]", normalized))

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
            # Use u.find with case-insensitive match for efficient lookup
            found_result = u.find(
                existing_attrs,
                predicate=lambda k, _v: cast("bool", u.normalize(k, attr_name)),
            )
            # Convert Sequence[str] to list[str] for return type compatibility
            # Type narrowing: existing_attrs is Mapping[str, Sequence[str]], so found_result is Sequence[str]
            if found_result is not None:
                if isinstance(found_result, Sequence) and not isinstance(
                    found_result, str
                ):
                    return list(cast("Sequence[str]", found_result))
                # Single string value - wrap in list (shouldn't happen with Sequence[str] values)
                if isinstance(found_result, str):
                    return [found_result]
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
                - FlextRuntime.is_list_like() validates sequences (not isinstance)

            Audit Implication:
                Returns tuple of (changes, processed_attrs) for audit trail.
                processed_attrs enables deletion detection in second pass.

            Returns:
                Tuple of (modify changes dict, set of processed attribute names).

            """
            changes: t.Ldap.ModifyChanges = {}
            processed = set()

            # Use u.filter() for filtering attributes
            # Filter out non-list-like values and ignored attributes
            filtered_attrs = cast(
                "dict[str, Sequence[str]]",
                u.filter(
                    new_attrs,
                    predicate=lambda k, v: (
                        FlextRuntime.is_list_like(v)
                        and not cast("bool", u.normalize(k, list(ignore)))
                    ),
                ),
            )

            # Process attributes using u.process() for efficient processing
            def process_attr(
                attr_name: str, new_vals: Sequence[str]
            ) -> tuple[str, list[tuple[str, list[str]]] | None]:
                """Process single attribute and return change if needed."""
                # Use u.normalize for consistent case handling
                normalized_name = cast("str", u.normalize(attr_name, case="lower"))
                processed.add(normalized_name)

                existing_vals = (
                    FlextLdapOperations.EntryComparison.find_existing_values(
                        attr_name,
                        existing_attrs,
                    )
                )
                if existing_vals and FlextRuntime.is_list_like(existing_vals):
                    # Use u.filter() for efficient filtering
                    existing_set = (
                        FlextLdapOperations.EntryComparison.normalize_value_set(
                            cast(
                                "list[str]",
                                u.filter(
                                    u.ensure(
                                        existing_vals,
                                        target_type="str_list",
                                        default=[],
                                    ),
                                    predicate=bool,
                                ),
                            )
                        )
                    )
                else:
                    existing_set = set()
                # Use u.filter() for efficient filtering
                new_set = FlextLdapOperations.EntryComparison.normalize_value_set(
                    cast(
                        "list[str]",
                        u.filter(
                            u.ensure(new_vals, target_type="str_list", default=[]),
                            predicate=bool,
                        ),
                    )
                )
                if existing_set != new_set:
                    return (
                        attr_name,
                        [
                            (
                                MODIFY_REPLACE,
                                cast(
                                    "list[str]",
                                    u.filter(
                                        u.ensure(
                                            new_vals, target_type="str_list", default=[]
                                        ),
                                        predicate=bool,
                                    ),
                                ),
                            ),
                        ],
                    )
                return (attr_name, None)

            # Process all attributes using u.process()
            process_result = u.process(
                filtered_attrs,
                processor=process_attr,
                on_error="skip",
            )
            if process_result.is_success:
                processed_dict = cast(
                    "dict[str, list[tuple[str, list[str]]] | None]",
                    process_result.value,
                )
                # Use u.filter() for efficient filtering
                filtered_changes = u.filter(
                    processed_dict, predicate=lambda _k, v: v is not None
                )
                changes = cast("t.Ldap.ModifyChanges", filtered_changes)

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
                - FlextRuntime.is_list_like() validates sequences (not isinstance)

            Audit Implication:
                Returns deletions needed to sync existing entry with new state.
                Critical for maintaining data integrity during upsert operations.

            Returns:
                Dict mapping attribute names to MODIFY_DELETE operations.

            """
            # Use u.filter() and u.map() for efficient processing
            # Filter out non-list-like values, ignored attributes, and processed attributes
            filtered_attrs = u.filter(
                existing_attrs,
                predicate=lambda k, v: (
                    FlextRuntime.is_list_like(v)
                    and not cast("bool", u.normalize(k, list(ignore)))
                    and not cast("bool", u.normalize(k, list(processed)))
                ),
            )
            # Transform to MODIFY_DELETE operations
            changes_dict = cast(
                "dict[str, list[tuple[int, list[str]]]]",
                u.map(
                    cast("dict[str, Sequence[str]]", filtered_attrs),
                    mapper=lambda _k, _v: [(MODIFY_DELETE, [])],
                )
                if isinstance(filtered_attrs, dict)
                else {},
            )

            return cast("t.Ldap.ModifyChanges", changes_dict)

        @staticmethod
        def compare(
            existing_entry: p.LdapEntry.EntryProtocol | FlextLdifModels.Entry,
            new_entry: p.LdapEntry.EntryProtocol | FlextLdifModels.Entry,
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
            # Convert to dict for processing using u.process()
            existing_result = u.process(
                existing_attrs_raw,
                processor=lambda _k, v: list(v)
                if FlextRuntime.is_list_like(v)
                else [v],
                on_error="collect",
            )
            existing_attrs_transformed: t.Ldap.AttributeDict = (
                cast("t.Ldap.AttributeDict", existing_result.value)
                if existing_result.is_success
                else cast(
                    "t.Ldap.AttributeDict",
                    {
                        k: list(v) if FlextRuntime.is_list_like(v) else [v]
                        for k, v in existing_attrs_raw.items()
                    },
                )
            )
            existing_attrs: t.Ldap.AttributeDict = cast(
                "t.Ldap.AttributeDict",
                existing_attrs_transformed,
            )
            new_result = u.process(
                new_attrs_raw,
                processor=lambda _k, v: list(v)
                if FlextRuntime.is_list_like(v)
                else [v],
                on_error="collect",
            )
            new_attrs_transformed: t.Ldap.AttributeDict = (
                cast("t.Ldap.AttributeDict", new_result.value)
                if new_result.is_success
                else cast(
                    "t.Ldap.AttributeDict",
                    {
                        k: list(v) if FlextRuntime.is_list_like(v) else [v]
                        for k, v in new_attrs_raw.items()
                    },
                )
            )
            new_attrs: t.Ldap.AttributeDict = cast(
                "t.Ldap.AttributeDict",
                new_attrs_transformed,
            )

            if not existing_attrs or not new_attrs:
                return None

            ignore = c.OperationalAttributes.IGNORE_SET
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
            # Use u.merge for safer dictionary merging
            merge_result = u.merge(
                changes,
                delete_changes,
                strategy="override",
            )
            if merge_result.is_success:
                changes = cast("t.Ldap.ModifyChanges", merge_result.value)

            return changes or None

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

        def execute(
            self,
            entry: FlextLdifModels.Entry,
        ) -> r[m.LdapOperationResult]:
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
            attrs = entry.attributes.attributes if entry.attributes else {}
            # Use u.extract for safer nested access
            changetype_result: r[list[str] | None] = u.extract(
                attrs,
                c.LdapAttributeNames.CHANGETYPE,
                default=[],
            )
            changetype_val: list[str] = (
                changetype_result.value
                if changetype_result.is_success and changetype_result.value is not None
                else []
            )
            # Use u.normalize for consistent case handling
            changetype = (
                cast("str", u.normalize(changetype_val[0], case="lower"))
                if changetype_val
                else ""
            )

            if changetype == c.ChangeTypeOperations.MODIFY:
                return self.handle_schema_modify(entry)
            return self.handle_regular_add(entry)

        def handle_schema_modify(
            self,
            entry: FlextLdifModels.Entry,
        ) -> r[m.LdapOperationResult]:
            """Apply a schema modification entry.

            Business Rules:
                - Entry must have 'add' attribute specifying the schema attribute to add
                - Uses MODIFY_ADD operation (not REPLACE) for additive schema changes
                - "Entry already exists" is interpreted as schema element exists → SKIPPED
                - Empty values are filtered out before modification

            Audit Implication:
                Schema modifications are critical; returns MODIFIED, SKIPPED, or error.
                Preserves LDAP error context for schema validation failures.

            Returns:
                FlextResult with operation type (MODIFIED or SKIPPED).

            """
            attrs = entry.attributes.attributes if entry.attributes else {}
            # Use u.extract for safer nested access
            add_op_result: r[list[str] | None] = u.extract(
                attrs,
                c.ChangeTypeOperations.ADD,
                default=[],
            )
            add_op: list[str] = (
                add_op_result.value
                if add_op_result.is_success and add_op_result.value is not None
                else []
            )
            if not add_op:
                return r[m.LdapOperationResult].fail(
                    "Schema modify entry missing 'add' attribute",
                )

            attr_type = add_op[0]
            # Use u.extract for safer nested access
            attr_values_result: r[list[str] | None] = u.extract(
                attrs,
                attr_type,
                default=[],
            )
            attr_values: list[str] = (
                attr_values_result.value
                if attr_values_result.is_success
                and attr_values_result.value is not None
                else []
            )
            # Use u.filter() for efficient filtering
            filtered: list[str] = cast(
                "list[str]",
                u.filter(
                    u.ensure(attr_values, target_type="str_list", default=[]),
                    predicate=bool,
                ),
            )

            if not filtered:
                return r[m.LdapOperationResult].fail(
                    f"Schema modify entry has only empty values for '{attr_type}'",
                )

            changes: t.Ldap.ModifyChanges = {
                attr_type: [(MODIFY_ADD, filtered)],
            }
            modify_result = self._ops.modify(str(entry.dn), changes)

            if modify_result.is_success:
                return r[m.LdapOperationResult].ok(
                    m.LdapOperationResult(
                        operation=c.UpsertOperations.MODIFIED,
                    ),
                )

            error_str = str(modify_result.error) if modify_result.error else ""
            if self._ops.is_already_exists_error(error_str):
                return r[m.LdapOperationResult].ok(
                    m.LdapOperationResult(
                        operation=c.UpsertOperations.SKIPPED,
                    ),
                )

            return r[m.LdapOperationResult].fail(
                error_str or c.ErrorStrings.UNKNOWN_ERROR,
            )

        def handle_regular_add(
            self,
            entry: FlextLdifModels.Entry,
        ) -> r[m.LdapOperationResult]:
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
            add_result = self._ops.add(entry)

            if add_result.is_success:
                return r[m.LdapOperationResult].ok(
                    m.LdapOperationResult(
                        operation=c.UpsertOperations.ADDED,
                    ),
                )

            error_str = str(add_result.error) if add_result.error else ""
            if not self._ops.is_already_exists_error(error_str):
                return r[m.LdapOperationResult].fail(error_str)

            return self.handle_existing_entry(entry)

        def handle_existing_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> r[m.LdapOperationResult]:
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
            entry_dn = str(entry.dn) if entry.dn else "unknown"
            search_options = m.SearchOptions(
                base_dn=entry_dn,
                filter_str=c.Filters.ALL_ENTRIES_FILTER,
                scope=c.SearchScope.BASE,
            )

            search_result = self._ops.search(search_options)
            if search_result.is_failure:
                return r[m.LdapOperationResult].ok(
                    m.LdapOperationResult(
                        operation=c.UpsertOperations.SKIPPED,
                    ),
                )

            existing_entries = search_result.unwrap().entries
            if not existing_entries:
                retry_result = self._ops.add(entry)
                if retry_result.is_success:
                    return r[m.LdapOperationResult].ok(
                        m.LdapOperationResult(
                            operation=c.UpsertOperations.ADDED,
                        ),
                    )
                return r[m.LdapOperationResult].fail(
                    str(retry_result.error) if retry_result.error else "",
                )

            changes = FlextLdapOperations.EntryComparison.compare(
                existing_entries[0],
                entry,
            )
            if not changes:
                return r[m.LdapOperationResult].ok(
                    m.LdapOperationResult(
                        operation=c.UpsertOperations.SKIPPED,
                    ),
                )

            modify_result = self._ops.modify(entry_dn, changes)
            if modify_result.is_success:
                return r[m.LdapOperationResult].ok(
                    m.LdapOperationResult(
                        operation=c.UpsertOperations.MODIFIED,
                    ),
                )

            return r[m.LdapOperationResult].fail(
                str(modify_result.error) if modify_result.error else "",
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
        error_lower = cast("str", u.normalize(error_message, case="lower"))
        return (
            str(c.ErrorStrings.ENTRY_ALREADY_EXISTS) in error_lower
            or str(c.ErrorStrings.ENTRY_ALREADY_EXISTS_ALT) in error_lower
            or str(c.ErrorStrings.ENTRY_ALREADY_EXISTS_LDAP) in error_lower
        )

    def __init__(
        self,
        connection: FlextLdapConnection,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize the operations service with a live connection."""
        super().__init__(**kwargs)
        self._connection = connection
        self._upsert_handler = self._UpsertHandler(self)

    def search(
        self,
        search_options: m.SearchOptions,
        server_type: FlextLdifConstants.ServerTypes
        | str = FlextLdifConstants.ServerTypes.RFC,
        **_kwargs: str | float | bool | None,
    ) -> r[m.SearchResult]:
        """Perform an LDAP search using normalized search options.

        Business Rules:
            - Base DN is normalized using FlextLdifUtilities.DN.norm_string() before search
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
                "base_dn": FlextLdifUtilities.DN.norm_string(search_options.base_dn),
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
            return r[m.SearchResult].ok(search_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return r[m.SearchResult].fail(error_msg)

    def add(
        self,
        entry: FlextLdifModels.Entry,
        **_kwargs: str | float | bool | None,
    ) -> r[m.OperationResult]:
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
        result = self._connection.adapter.add(entry)
        # Adapter returns r[OperationResultProtocol] - unwrap directly
        if result.is_success:
            operation_result = result.unwrap()
            return r[m.OperationResult].ok(operation_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return r[m.OperationResult].fail(error_msg)

    def modify(
        self,
        dn: str | p.LdapEntry.DistinguishedNameProtocol,
        changes: t.Ldap.ModifyChanges,
        **_kwargs: str | float | bool | None,
    ) -> r[m.OperationResult]:
        """Modify an LDAP entry with the provided change set.

        Business Rules:
            - Entry must exist before modification (LDAP error 32 if not found)
            - Changes use ldap3 format: {attr_name: [(MODIFY_ADD|MODIFY_DELETE|MODIFY_REPLACE, [values])]}
            - DN normalization is applied using FlextLdifUtilities.DN.get_dn_value()
            - String DNs are converted to DistinguishedName models for type safety
            - Schema constraints are validated by LDAP server

        Audit Implications:
            - Modify operations are logged with DN and change summary
            - Successful modifies log affected count (always 1)
            - Failed modifies log error message and DN

        Architecture:
            - Delegates to Ldap3Adapter.modify() for protocol-level execution
            - DN conversion handled by FlextLdifUtilities.DN
            - Returns FlextResult pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to modify (string or DistinguishedName model)
            changes: Modification changes dict in ldap3 format

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        # Type narrowing: convert str to DistinguishedName model if needed
        if isinstance(dn, str):
            dn_model: p.LdapEntry.DistinguishedNameProtocol = (
                FlextLdifModels.DistinguishedName(
                    value=FlextLdifUtilities.DN.get_dn_value(dn),
                )
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
            return r[m.OperationResult].ok(operation_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return r[m.OperationResult].fail(error_msg)

    def delete(
        self,
        dn: str | p.LdapEntry.DistinguishedNameProtocol,
        **_kwargs: str | float | bool | None,
    ) -> r[m.OperationResult]:
        """Delete an LDAP entry identified by DN.

        Business Rules:
            - Entry must exist before deletion (LDAP error 32 if not found)
            - Entry must not have children (LDAP error 66 if has children)
            - DN normalization is applied using FlextLdifUtilities.DN.get_dn_value()
            - String DNs are converted to DistinguishedName models for type safety
            - Deletion is permanent - no undo capability

        Audit Implications:
            - Delete operations are logged with DN for critical audit trail
            - Successful deletes log affected count (always 1)
            - Failed deletes log error message and DN

        Architecture:
            - Delegates to Ldap3Adapter.delete() for protocol-level execution
            - DN conversion handled by FlextLdifUtilities.DN
            - Returns FlextResult pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to delete (string or DistinguishedName model)

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        # Type narrowing: convert str to DistinguishedName model if needed
        if isinstance(dn, str):
            dn_model: p.LdapEntry.DistinguishedNameProtocol = (
                FlextLdifModels.DistinguishedName(
                    value=FlextLdifUtilities.DN.get_dn_value(dn),
                )
            )
        else:
            dn_model = dn
        result = self._connection.adapter.delete(dn_model)
        # Adapter returns r[OperationResultProtocol] - unwrap directly
        if result.is_success:
            operation_result = result.unwrap()
            return r[m.OperationResult].ok(operation_result)
        error_msg = str(result.error) if result.error else "Unknown error"
        return r[m.OperationResult].fail(error_msg)

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
        entry: FlextLdifModels.Entry,
        *,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
    ) -> r[m.LdapOperationResult]:
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
        if not retry_on_errors or max_retries <= 1:
            return self._upsert_handler.execute(entry)

        result = self._upsert_handler.execute(entry)
        if result.is_success or not retry_on_errors:
            return result

        # Use u.normalize for consistent case handling
        error_str = cast("str", u.normalize(str(result.error), case="lower"))
        if not any(
            cast("bool", u.normalize(error_str, pattern)) for pattern in retry_on_errors
        ):
            return result

        return u.Reliability.retry(
            operation=lambda: self._upsert_handler.execute(entry),
            max_attempts=max_retries,
            delay_seconds=1.0,
        )

    def batch_upsert(
        self,
        entries: list[FlextLdifModels.Entry],
        *,
        progress_callback: Callable[
            [int, int, str, m.LdapBatchStats],
            None,
        ]
        | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
        stop_on_error: bool = False,
    ) -> r[m.LdapBatchStats]:
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
        synced = 0
        failed = 0
        skipped = 0
        total_entries = len(entries)

        for i, entry in enumerate(entries, 1):
            entry_dn = entry.dn.value if entry.dn else "unknown"
            upsert_result = self.upsert(
                entry,
                retry_on_errors=retry_on_errors,
                max_retries=max_retries,
            )

            if upsert_result.is_success:
                operation = upsert_result.unwrap().operation
                if operation == c.UpsertOperations.SKIPPED:
                    skipped += 1
                elif operation in {
                    c.UpsertOperations.ADDED,
                    c.UpsertOperations.MODIFIED,
                }:
                    synced += 1
            else:
                failed += 1
                self.logger.error(
                    "Batch upsert entry failed",
                    entry_index=i,
                    total_entries=total_entries,
                    entry_dn=entry_dn[:100] if entry_dn else None,
                    error=cast(
                        "str",
                        u.ensure(upsert_result.error, target_type="str", default=""),
                    )[:200],
                )

                if stop_on_error:
                    return r[m.LdapBatchStats].fail(
                        f"Batch upsert stopped on error at entry {i}/{total_entries}: {upsert_result.error}",
                    )

            if progress_callback:
                try:
                    callback_stats = m.LdapBatchStats(
                        synced=synced,
                        failed=failed,
                        skipped=skipped,
                    )
                    progress_callback(i, total_entries, entry_dn, callback_stats)
                except (RuntimeError, TypeError, ValueError) as e:
                    self.logger.warning(
                        "Progress callback failed",
                        operation=c.LdapOperationNames.SYNC,
                        entry_index=i,
                        error=str(e),
                    )

        stats = m.LdapBatchStats(
            synced=synced,
            failed=failed,
            skipped=skipped,
        )

        self.logger.info(
            "Batch upsert completed",
            operation=c.LdapOperationNames.BATCH_UPSERT.value,
            total_entries=total_entries,
            synced=synced,
            failed=failed,
            skipped=skipped,
        )

        if synced == 0 and failed > 0:
            return r[m.LdapBatchStats].fail(
                f"Batch upsert failed: all {failed} entries failed, 0 synced",
            )

        return r[m.LdapBatchStats].ok(stats)

    def execute(
        self,
        **_kwargs: str | float | bool | None,
    ) -> r[m.SearchResult]:
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
            return r[m.SearchResult].fail(
                c.ErrorStrings.NOT_CONNECTED,
            )

        ldap_config = self.config.get_namespace("ldap", FlextLdapConfig)
        base_dn = ldap_config.base_dn or "dc=example,dc=com"
        return r[m.SearchResult].ok(
            m.SearchResult(
                entries=[],
                search_options=m.SearchOptions(
                    base_dn=base_dn,
                    filter_str=c.Filters.ALL_ENTRIES_FILTER,
                ),
            ),
        )
