"""LDAP Operations Service.

This service provides LDAP CRUD operations (search, add, modify, delete).
Delegates to Ldap3Adapter which already handles conversion to Entry models
using FlextLdifParser, maximizing code reuse.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal, TypeVar, cast

from flext_core import (
    FlextConfig,
    FlextExceptions,
    FlextLogger,
    FlextResult,
    FlextService,
)
from flext_ldif.models import FlextLdifModels
from flext_ldif.utilities import FlextLdifUtilities
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
from pydantic import computed_field

from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection

T = TypeVar("T")


def _get_error_message[T](result: FlextResult[T]) -> str:
    """Get error message from FlextResult with type safety.

    FlextResult contract guarantees error is non-None when is_failure is True.
    This helper provides type-safe access without assert statements.

    Args:
        result: FlextResult with is_failure=True

    Returns:
        Error message string (guaranteed non-empty)

    """
    # FlextResult contract: error is guaranteed non-None when is_failure is True
    # Use str() for type safety and to handle edge cases
    return str(result.error) if result.error else "Unknown error"


def _normalize_dn(dn: str | FlextLdifModels.DistinguishedName) -> FlextLdifModels.DistinguishedName:
    """Normalize DN to DistinguishedName model (DRY helper).

    Converts string DN to DistinguishedName model if needed.
    DN format validation is handled by Pydantic v2 validators during model creation.

    Args:
        dn: DN as string or DistinguishedName model

    Returns:
        DistinguishedName model (guaranteed by Pydantic validation)

    """
    return (
        dn
        if isinstance(dn, FlextLdifModels.DistinguishedName)
        else FlextLdifModels.DistinguishedName(value=dn)
    )


def _is_already_exists_error(error_message: str) -> bool:
    """Check if error indicates entry/attribute already exists (DRY helper).

    Centralized logic for detecting "already exists" errors across services.
    Used by both operations and sync services.

    FlextResult contract guarantees error is non-None when is_failure is True.
    This function expects non-empty string (use _get_error_message helper if needed).

    Args:
        error_message: Error message to check (guaranteed non-None from FlextResult)

    Returns:
        True if error indicates duplicate, False otherwise

    """
    error_lower = error_message.lower()
    return (
        "already exists" in error_lower
        or "entryalreadyexists" in error_lower
        or "attributeorvalueexists" in error_lower
    )


class FlextLdapOperations(FlextService[FlextLdapModels.SearchResult]):
    """LDAP operations service providing CRUD operations.

    Handles search, add, modify, and delete operations.
    Delegates to Ldap3Adapter which already uses FlextLdifParser for conversion.
    This maximizes code reuse - adapter handles all parsing logic.
    """

    _connection: FlextLdapConnection
    _logger: FlextLogger

    @computed_field  # type: ignore[misc]
    def service_config(self) -> FlextConfig:
        """Automatic config binding via Pydantic v2 computed_field."""
        return FlextConfig.get_global_instance()

    @property
    def project_config(self) -> FlextConfig:
        """Auto-resolve project-specific configuration by naming convention."""
        try:
            return cast(
                "FlextConfig",
                self._resolve_project_component(
                    "Config",
                    lambda obj: isinstance(obj, FlextConfig),
                ),
            )
        except Exception:
            # Fast fail: return global config if project config not found
            return FlextConfig.get_global_instance()

    def _resolve_project_component(
        self,
        component_suffix: str,
        type_check_func: Callable[[object], bool],
    ) -> object:
        """Resolve project component by naming convention (DRY helper)."""
        service_class_name = self.__class__.__name__
        component_class_name = service_class_name.replace("Service", component_suffix)

        # Fast fail: container must be accessible
        container = self.container

        # Fast fail: component must exist in container
        result = container.get(component_class_name)
        if result.is_failure:
            raise FlextExceptions.NotFoundError(
                message=f"Component '{component_class_name}' not found in container",
                resource_type="component",
                resource_id=component_class_name,
            )

        obj = result.unwrap()
        if not type_check_func(obj):
            msg = (
                f"Component '{component_class_name}' found but type check failed. "
                f"Expected type validated by {type_check_func.__name__}"
            )
            raise FlextExceptions.TypeError(
                message=msg,
                expected_type=component_class_name,
                actual_type=type(obj).__name__,
            )
        return obj

    def __init__(
        self,
        connection: FlextLdapConnection,
    ) -> None:
        """Initialize operations service.

        Args:
            connection: FlextLdapConnection instance

        """
        super().__init__()
        self._connection = connection
        self._logger = FlextLogger.create_module_logger(__name__)

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: str = FlextLdapConstants.ServerTypes.RFC,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation.

        Delegates to Ldap3Adapter which already converts results to Entry models
        using FlextLdifParser.parse_ldap3_results(), maximizing code reuse.

        Args:
            search_options: Search configuration
            server_type: LDAP server type for parsing (default: RFC constant)

        Returns:
            FlextResult containing SearchResult with Entry models
                (reusing FlextLdifModels.Entry)

        """
        # FASE 2: Normalize base_dn using FlextLdifUtilities.DN
        # DN format validation is handled by Pydantic v2 field validator in SearchOptions model
        normalized_base_dn = FlextLdifUtilities.DN.norm_string(search_options.base_dn)
        
        # Update search_options with normalized DN for consistency
        normalized_options = FlextLdapModels.SearchOptions(
            base_dn=normalized_base_dn,
            filter_str=search_options.filter_str,
            scope=search_options.scope,
            attributes=search_options.attributes,
            size_limit=search_options.size_limit,
            time_limit=search_options.time_limit,
        )

        # Adapter handles connection check via _get_connection() - no duplication
        # Adapter.search returns FlextResult[FlextLdapModels.SearchResult]
        search_result = self._connection.adapter.search(
            normalized_options,
            server_type=server_type,
        )
        
        if search_result.is_success:
            result = search_result.unwrap()
            self._logger.debug(
                "LDAP search completed",
                operation="search",
                base_dn=normalized_base_dn,
                entries_found=len(result.entries),
            )
        else:
            self._logger.error(
                "LDAP search failed",
                operation="search",
                base_dn=normalized_base_dn,
                error=_get_error_message(search_result),
            )
        
        if search_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                _get_error_message(search_result)
            )
        # Adapter.search already returns SearchResult - just return it
        return search_result

    def add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry.

        Delegates to Ldap3Adapter which accepts Entry model directly,
        reusing FlextLdifModels.Entry for type safety.

        Args:
            entry: Entry model to add (reusing FlextLdifModels.Entry)

        Returns:
            FlextResult containing OperationResult

        """
        entry_dn_str = str(entry.dn) if entry.dn else "unknown"
        
        # Adapter handles connection check via _get_connection() - no duplication
        add_result = self._connection.adapter.add(entry)
        
        if add_result.is_success:
            self._logger.debug(
                "LDAP entry added",
                operation="add",
                entry_dn=entry_dn_str,
            )
        else:
            # Don't log warning for "entryAlreadyExists" - this is expected in upsert context
            # Don't log warning for "session terminated" - this is handled by sync retry logic
            error_str = _get_error_message(add_result)
            is_expected_error = (
                _is_already_exists_error(error_str)
                or "session terminated" in error_str.lower()
            )

            if not is_expected_error:
                self._logger.error(
                    "LDAP add entry failed",
                    operation="add",
                    entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                    error=error_str,
                    error_type=type(add_result.error).__name__,
                )
            else:
                self._logger.debug(
                    "LDAP add entry failed with expected error",
                    operation="add",
                    entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                    error=error_str,
                    error_type=type(add_result.error).__name__,
                )

        return add_result

    def modify(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Args:
            dn: Distinguished name of entry to modify (str or DistinguishedName)
            changes: Modification changes in ldap3 format

        Returns:
            FlextResult containing OperationResult

        """
        # DN format validation is handled by Pydantic v2 validators when converting to DistinguishedName
        # Use DRY helper to normalize DN
        dn_model = _normalize_dn(dn)
        
        # Adapter handles connection check via _get_connection() - no duplication
        modify_result = self._connection.adapter.modify(dn_model, changes)
        
        if modify_result.is_success:
            self._logger.debug(
                "LDAP entry modified",
                operation="modify",
                entry_dn=str(dn_model),
                changes_count=len(changes),
            )
        else:
            self._logger.error(
                "LDAP modify failed",
                operation="modify",
                entry_dn=str(dn_model),
                error=_get_error_message(modify_result),
            )

        return modify_result

    def delete(
        self,
        dn: str | FlextLdifModels.DistinguishedName,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete (str or DistinguishedName)

        Returns:
            FlextResult containing OperationResult

        """
        # DN format validation is handled by Pydantic v2 validators when converting to DistinguishedName
        # Use DRY helper to normalize DN
        dn_model = _normalize_dn(dn)
        
        # Adapter handles connection check via _get_connection() - no duplication
        delete_result = self._connection.adapter.delete(dn_model)
        
        if delete_result.is_success:
            self._logger.debug(
                "LDAP entry deleted",
                operation="delete",
                entry_dn=str(dn_model),
            )
        else:
            self._logger.error(
                "LDAP delete failed",
                operation="delete",
                entry_dn=str(dn_model),
                error=_get_error_message(delete_result),
            )

        return delete_result

    @property
    def is_connected(self) -> bool:
        """Check if operations service has active connection.

        Returns:
            True if connected, False otherwise

        """
        return self._connection.is_connected

    def _compare_entries(
        self,
        existing_entry: FlextLdifModels.Entry,
        new_entry: FlextLdifModels.Entry,
    ) -> dict[str, list[tuple[str, list[str]]]] | None:
        """Compare two entries and return modify changes if different.

        Args:
            existing_entry: Entry currently in LDAP
            new_entry: Entry to be upserted

        Returns:
            Dict with modify changes if entries differ, None if identical.
            Changes format: {attr_name: [(operation, [values])]}

        """
        existing_dn = str(existing_entry.dn) if existing_entry.dn else "unknown"
        new_dn = str(new_entry.dn) if new_entry.dn else "unknown"
        self._logger.debug(
            "Comparing entries",
            existing_dn=existing_dn[:100] if existing_dn else None,
            new_dn=new_dn[:100] if new_dn else None,
        )
        
        if not existing_entry.attributes or not new_entry.attributes:
            self._logger.debug(
                "Entry comparison skipped - missing attributes",
                existing_dn=existing_dn[:100] if existing_dn else None,
                new_dn=new_dn[:100] if new_dn else None,
                existing_has_attributes=existing_entry.attributes is not None,
                new_has_attributes=new_entry.attributes is not None,
            )
            return None

        existing_attrs = existing_entry.attributes.attributes
        new_attrs = new_entry.attributes.attributes
        
        self._logger.debug(
            "Attributes extracted for comparison",
            existing_dn=existing_dn[:100] if existing_dn else None,
            new_dn=new_dn[:100] if new_dn else None,
            existing_attributes_count=len(existing_attrs),
            new_attributes_count=len(new_attrs),
        )

        # Attributes to ignore in comparison (operational attributes)
        ignore_attrs = {
            "changetype",
            "add",
            "delete",
            "replace",
            "modify",
            "createTimestamp",
            "modifyTimestamp",
            "creatorsName",
            "modifiersName",
            "entryUUID",
            "entryCSN",
        }

        changes: dict[str, list[tuple[str, list[str]]]] = {}
        has_changes = False

        # Normalize attribute names to lowercase for case-insensitive comparison
        existing_attrs_lower = {k.lower(): (k, v) for k, v in existing_attrs.items()}
        new_attrs_lower = {k.lower(): (k, v) for k, v in new_attrs.items()}

        self._logger.debug(
            "Comparing attributes",
            existing_dn=existing_dn[:100] if existing_dn else None,
            new_dn=new_dn[:100] if new_dn else None,
            existing_attributes_count=len(existing_attrs_lower),
            new_attributes_count=len(new_attrs_lower),
            ignore_attributes_count=len(ignore_attrs),
        )
        
        # Check for new/modified attributes
        modified_attrs: list[str] = []
        for attr_name_lower, (attr_name, new_values) in new_attrs_lower.items():
            if attr_name_lower in ignore_attrs:
                continue

            existing_attr_name, existing_values = existing_attrs_lower.get(
                attr_name_lower,
                (attr_name, []),
            )

            # Normalize values for comparison (convert to sets, ignoring order)
            existing_set = {str(v).lower() for v in existing_values if v}
            new_set = {str(v).lower() for v in new_values if v}

            if existing_set != new_set:
                # Replace entire attribute with new values
                # Use original attribute name from existing entry if available
                changes[existing_attr_name] = [
                    (MODIFY_REPLACE, [str(v) for v in new_values if v])
                ]
                has_changes = True
                modified_attrs.append(existing_attr_name)
                
                self._logger.debug(
                    "Attribute difference found",
                    existing_dn=existing_dn[:100] if existing_dn else None,
                    new_dn=new_dn[:100] if new_dn else None,
                    attribute_name=existing_attr_name,
                    existing_values_count=len(existing_values),
                    new_values_count=len(new_values),
                )

        # Check for deleted attributes (in existing but not in new)
        deleted_attrs: list[str] = []
        for attr_name_lower, (
            attr_name,
            _existing_values,
        ) in existing_attrs_lower.items():
            if attr_name_lower in ignore_attrs:
                continue

            if attr_name_lower not in new_attrs_lower:
                # Attribute was removed - delete it
                changes[attr_name] = [(MODIFY_DELETE, [])]
                has_changes = True
                deleted_attrs.append(attr_name)
                
                self._logger.debug(
                    "Attribute deletion detected",
                    existing_dn=existing_dn[:100] if existing_dn else None,
                    new_dn=new_dn[:100] if new_dn else None,
                    attribute_name=attr_name,
                )

        self._logger.debug(
            "Entry comparison completed",
            existing_dn=existing_dn[:100] if existing_dn else None,
            new_dn=new_dn[:100] if new_dn else None,
            has_changes=has_changes,
            changes_count=len(changes) if has_changes else 0,
            modified_attributes=modified_attrs[:20] if modified_attrs else [],
            deleted_attributes=deleted_attrs[:20] if deleted_attrs else [],
        )

        return changes if has_changes else None

    def upsert(
        self,
        entry: FlextLdifModels.Entry,
        *,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
    ) -> FlextResult[dict[str, str]]:
        """Upsert LDAP entry (add if doesn't exist, modify if exists with differences, skip if identical).

        Generic method that handles both regular entries and schema modifications.
        For regular entries:
            - Tries add first
            - If entryAlreadyExists, fetches existing entry and compares attributes
            - If different, performs modify operation
            - If identical, skips
        For schema entries (changetype=modify): checks if attribute exists, adds if not.

        Args:
            entry: Entry model to upsert
            retry_on_errors: List of error patterns to retry on (case-insensitive substring match).
                           Example: ["session terminated", "connection lost"]
            max_retries: Maximum number of retry attempts (default: 1)

        Returns:
            FlextResult containing dict with "operation" key:
                - "added": Entry was added
                - "modified": Entry was modified (differences found and updated)
                - "skipped": Entry already exists (identical)

        """
        entry_dn_str = str(entry.dn) if entry.dn else "unknown"
        result = self._upsert_internal(entry)

        if not retry_on_errors or result.is_success:
            if result.is_success:
                operation_result = result.unwrap()
                self._logger.debug(
                    "Upsert completed",
                    operation="upsert",
                    entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                    operation_type=operation_result.get("operation", "unknown"),
                )
            return result

        error_str = str(result.error).lower()
        should_retry = any(
            pattern.lower() in error_str for pattern in retry_on_errors
        )

        if not should_retry:
            self._logger.debug(
                "Upsert error not retriable",
                operation="upsert",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                error=error_str[:200],
                retry_on_errors=retry_on_errors,
            )
            return result
        
        last_error = result.error
        for attempt in range(1, max_retries + 1):
            self._logger.warning(
                "Upsert failed, retrying",
                operation="upsert",
                attempt=attempt,
                max_retries=max_retries,
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                error=str(last_error)[:200],
            )

            result = self._upsert_internal(entry)
            if result.is_success:
                operation_result = result.unwrap()
                self._logger.info(
                    "Upsert succeeded after retry",
                    operation="upsert",
                    attempt=attempt,
                    entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                    operation_type=operation_result.get("operation", "unknown"),
                )
                return result

            error_str = str(result.error).lower()
            should_retry = any(
                pattern.lower() in error_str for pattern in retry_on_errors
            )

            if not should_retry:
                self._logger.warning(
                    "Upsert error changed to non-retriable, stopping retries",
                    operation="upsert",
                    attempt=attempt,
                    entry_dn=str(entry.dn),
                    error=str(result.error),
                )
                return result

            last_error = result.error

        self._logger.error(
            "Upsert failed after all retries",
            operation="upsert",
            max_retries=max_retries,
            entry_dn=str(entry.dn),
            final_error=str(last_error),
        )
        return FlextResult[dict[str, str]].fail(
            f"Upsert failed after {max_retries} retries: {last_error}"
        )

    def _upsert_internal(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, str]]:
        """Internal upsert implementation (extracted for retry logic).

        Args:
            entry: Entry model to upsert

        Returns:
            FlextResult containing dict with "operation" key

        """
        changetype_values = entry.attributes.attributes.get("changetype", []) if entry.attributes else []
        is_modify = changetype_values and changetype_values[0].lower() == "modify"

        if is_modify:
            return self._upsert_schema_modify(entry)
        
        return self._upsert_regular_add(entry)

    def _upsert_schema_modify(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, str]]:
        """Handle schema modify operation in upsert.

        Args:
            entry: Entry model with changetype=modify

        Returns:
            FlextResult containing dict with "operation" key

        """
        # Schema modify operation using ldap3 MODIFY_ADD
        # Duplicate detection handled by LDAP server error responses
        add_op = entry.attributes.attributes.get("add", [])
        if not add_op:
            self._logger.warning(
                "Schema modify entry missing 'add' attribute",
                operation="schema_modify",
                entry_dn=str(entry.dn),
            )
            return FlextResult[dict[str, str]].fail(
                "Schema modify entry missing 'add' attribute",
            )

        # Extract the attribute being added (e.g., "attributeTypes", "objectClasses")
        attr_type = add_op[0]
        attr_values = entry.attributes.attributes.get(attr_type, [])

        if not attr_values:
            self._logger.warning(
                "Schema modify entry missing attribute values",
                operation="schema_modify",
                entry_dn=str(entry.dn),
                attribute_type=attr_type,
            )
            return FlextResult[dict[str, str]].fail(
                f"Schema modify entry missing '{attr_type}' values",
            )

        filtered_values = [v for v in attr_values if v]

        if not filtered_values:
            self._logger.warning(
                "Schema modify entry has only empty values",
                operation="schema_modify",
                entry_dn=str(entry.dn),
                attribute_type=attr_type,
                original_values_count=len(attr_values),
            )
            return FlextResult[dict[str, str]].fail(
                f"Schema modify entry has only empty values for '{attr_type}'",
            )

        self._logger.debug(
            "Performing schema modify operation",
            operation="schema_modify",
            entry_dn=str(entry.dn),
            attribute_type=attr_type,
            original_values_count=len(attr_values),
            filtered_values_count=len(filtered_values),
            filtered_empty_values=len(attr_values) - len(filtered_values),
            modify_operation=MODIFY_ADD,
        )

        # Build modify changes dict for ldap3
        # Format: {attr_name: [(operation, [values])]}
        schema_changes: dict[str, list[tuple[str, list[str]]]] = {
            attr_type: [(MODIFY_ADD, filtered_values)],
        }

        modify_result = self.modify(str(entry.dn), schema_changes)
        if modify_result.is_success:
            self._logger.debug(
                "Schema modify operation succeeded",
                entry_dn=str(entry.dn),
                attribute_type=attr_type,
                values_added=len(filtered_values),
            )
            return FlextResult[dict[str, str]].ok({"operation": "modified"})

        # Check if error is "attribute already exists" - then skip
        error_str = _get_error_message(modify_result)
        if _is_already_exists_error(error_str):
            self._logger.debug(
                "Schema modify operation skipped - attribute already exists",
                entry_dn=str(entry.dn),
                attribute_type=attr_type,
            )
            return FlextResult[dict[str, str]].ok({"operation": "skipped"})

        self._logger.error(
            "Schema modify operation failed",
            entry_dn=str(entry.dn),
            error=error_str,
            error_type=type(modify_result.error).__name__ if modify_result.error else "Unknown",
            attribute_type=attr_type,
            values_count=len(filtered_values),
        )
        return FlextResult[dict[str, str]].fail(_get_error_message(modify_result))

    def _upsert_regular_add(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, str]]:
        """Handle regular add operation in upsert (with compare on conflict).

        Args:
            entry: Entry model to add

        Returns:
            FlextResult containing dict with "operation" key

        """
        entry_dn_str = str(entry.dn) if entry.dn else "unknown"
        add_result = self.add(entry)
        
        if add_result.is_success:
            return FlextResult[dict[str, str]].ok({"operation": "added"})

        error_str = _get_error_message(add_result)
        is_already_exists = _is_already_exists_error(error_str)
        
        if not is_already_exists:
            self._logger.error(
                "Add operation failed",
                operation="upsert",
                entry_dn=entry_dn_str,
                error=error_str,
                error_type=type(add_result.error).__name__ if add_result.error else "Unknown",
            )
            return FlextResult[dict[str, str]].fail(error_str)
        
        # Check if error is "already exists" - fetch and compare

        # Entry already exists - fetch and compare
        return self._upsert_handle_existing_entry(entry)

    def _upsert_handle_existing_entry(
        self,
        entry: FlextLdifModels.Entry,
    ) -> FlextResult[dict[str, str]]:
        """Handle upsert when entry already exists (fetch and compare).

        Args:
            entry: Entry model to upsert

        Returns:
            FlextResult containing dict with "operation" key

        """
        entry_dn_str = str(entry.dn) if entry.dn else "unknown"
        
        # Search for existing entry using BASE scope (exact DN match)
        search_options = FlextLdapModels.SearchOptions(
            base_dn=entry_dn_str,
            filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
            scope=cast(
                "Literal['BASE', 'ONELEVEL', 'SUBTREE']",
                str(FlextLdapConstants.SearchScope.BASE),
            ),
            attributes=None,  # Get all attributes
        )
        
        search_result = self.search(search_options)
        
        if search_result.is_failure:
            self._logger.error(
                "Failed to fetch existing entry for comparison",
                operation="upsert",
                entry_dn=entry_dn_str,
                error=str(search_result.error),
                error_type=type(search_result.error).__name__ if search_result.error else "Unknown",
            )
            return FlextResult[dict[str, str]].ok({"operation": "skipped"})
        
        existing_entries = search_result.unwrap().entries
        
        if not existing_entries:
            self._logger.warning(
                "Existing entry not found, retrying add",
                operation="upsert",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
            )
            add_result_retry = self.add(entry)
            if add_result_retry.is_success:
                self._logger.debug(
                    "Entry added after retry",
                    operation="upsert",
                    entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                )
                return FlextResult[dict[str, str]].ok({"operation": "added"})
            
            self._logger.error(
                "Failed to add entry after retry",
                operation="upsert",
                entry_dn=entry_dn_str[:100] if entry_dn_str else None,
                error=str(add_result_retry.error),
                error_type=type(add_result_retry.error).__name__ if add_result_retry.error else "Unknown",
            )
            return FlextResult[dict[str, str]].fail(_get_error_message(add_result_retry))

        existing_entry = existing_entries[0]

        # Compare entries
        changes_or_none = self._compare_entries(existing_entry, entry)
        
        if changes_or_none is None:
            self._logger.debug(
                "Entry already exists and is identical, skipping",
                operation="upsert",
                entry_dn=entry_dn_str,
            )
            return FlextResult[dict[str, str]].ok({"operation": "skipped"})

        # Entries differ - perform modify
        # Type narrowing: changes_or_none is not None here (checked above)
        changes: dict[str, list[tuple[str, list[str]]]] = changes_or_none
        
        modify_result = self.modify(entry_dn_str, changes)
        
        if modify_result.is_success:
            self._logger.info(
                "Entry updated",
                operation="upsert",
                entry_dn=entry_dn_str,
                changed_attributes=len(changes),
                changed_attribute_names=list(changes.keys())[:20],
            )
            return FlextResult[dict[str, str]].ok({"operation": "modified"})

        self._logger.error(
            "Failed to modify existing entry during upsert",
            operation="upsert",
            entry_dn=entry_dn_str[:100] if entry_dn_str else None,
            error=str(modify_result.error),
            error_type=type(modify_result.error).__name__ if modify_result.error else "Unknown",
            changed_attributes=list(changes.keys())[:20],
            changes_count=len(changes),
        )
        return FlextResult[dict[str, str]].fail(_get_error_message(modify_result))

    def batch_upsert(
        self,
        entries: list[FlextLdifModels.Entry],
        *,
        progress_callback: Callable[[int, int, str, dict[str, int]], None] | None = None,
        retry_on_errors: list[str] | None = None,
        max_retries: int = 1,
        stop_on_error: bool = False,
    ) -> FlextResult[dict[str, int]]:
        """Batch upsert multiple LDAP entries with progress tracking and retry logic.

        Processes entries sequentially, applying retry logic per-entry if configured.
        Aggregates results into synced/failed/skipped counters.

        Args:
            entries: List of entries to upsert
            progress_callback: Optional callback(idx: int, total: int, dn: str, stats: dict[str, int]) called after each entry
            retry_on_errors: Error patterns to retry on (passed to upsert)
            max_retries: Maximum retries per entry (default: 1)
            stop_on_error: Stop processing on first error (default: False)

        Returns:
            FlextResult with dict containing:
                - "synced": Number of entries successfully added/modified
                - "failed": Number of entries that failed
                - "skipped": Number of entries skipped (already identical)

        """
        synced = 0
        failed = 0
        skipped = 0
        total_entries = len(entries)

        for i, entry in enumerate(entries, 1):
            entry_dn = entry.dn.value if entry.dn else "unknown"

            # Upsert with retry if configured
            upsert_result = self.upsert(
                entry,
                retry_on_errors=retry_on_errors,
                max_retries=max_retries,
            )

            if upsert_result.is_success:
                operation = upsert_result.unwrap().get("operation", "unknown")

                if operation == "skipped":
                    skipped += 1
                elif operation in {"added", "modified"}:
                    synced += 1
            else:
                failed += 1
                self._logger.error(
                    "Batch upsert entry failed",
                    entry_index=i,
                    total_entries=total_entries,
                    entry_dn=entry_dn[:100] if entry_dn else None,
                    error=str(upsert_result.error)[:200],
                )

                if stop_on_error:
                    self._logger.error(
                        "Batch upsert stopped on error",
                        operation="batch_upsert",
                        entry_index=i,
                        total_entries=total_entries,
                        error=str(upsert_result.error)[:200],
                    )
                    return FlextResult[dict[str, int]].fail(
                        f"Batch upsert stopped on error at entry {i}/{total_entries}: {upsert_result.error}"
                    )

            if progress_callback:
                try:
                    stats_dict: dict[str, int] = {
                        "synced": synced,
                        "failed": failed,
                        "skipped": skipped,
                    }
                    progress_callback(i, total_entries, entry_dn, stats_dict)
                except Exception as e:
                    self._logger.warning(
                        "Progress callback failed",
                        operation="batch_upsert",
                        entry_index=i,
                        total_entries=total_entries,
                        error=str(e),
                        error_type=type(e).__name__,
                    )

        stats = {
            "synced": synced,
            "failed": failed,
            "skipped": skipped,
        }

        self._logger.info(
            "Batch upsert completed",
            operation="batch_upsert",
            total_entries=total_entries,
            synced=synced,
            failed=failed,
            skipped=skipped,
            success_rate=f"{(synced / total_entries * 100):.1f}%" if total_entries > 0 else "0%",
            skip_rate=f"{(skipped / total_entries * 100):.1f}%" if total_entries > 0 else "0%",
            failure_rate=f"{(failed / total_entries * 100):.1f}%" if total_entries > 0 else "0%",
        )

        return FlextResult[dict[str, int]].ok(stats)

    def execute(self, **_kwargs: object) -> FlextResult[FlextLdapModels.SearchResult]:
        """Execute service health check.

        Returns health check result based on connection status.
        Fast fail if not connected - no fallback.

        Args:
            **_kwargs: Unused - health check requires no configuration

        Returns:
            FlextResult containing SearchResult if connected,
            or failure if not connected

        """
        if not self._connection.is_connected:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                "Not connected to LDAP server",
            )

        # Return empty search result as health check indicator
        # Get base_dn from service config or use a safe default
        # Use service_config property from FlextService pattern
        # service_config is a computed_field that returns FlextConfig
        base_dn: str | None = None
        config_instance = self.service_config
        if hasattr(config_instance, "ldap"):
            ldap_config = cast("FlextLdapConfig", config_instance.ldap)  # type: ignore[attr-defined]
            base_dn = ldap_config.base_dn
        
        # If base_dn is None or empty, use a safe default
        if not base_dn or not base_dn.strip():
            base_dn = "dc=example,dc=com"
        
        empty_options = FlextLdapModels.SearchOptions(
            base_dn=base_dn,
            filter_str=FlextLdapConstants.Filters.ALL_ENTRIES_FILTER,
        )
        result = FlextLdapModels.SearchResult(
            entries=[],
            total_count=0,
            search_options=empty_options,
        )
        return FlextResult[FlextLdapModels.SearchResult].ok(result)
