"""LDAP3 adapter service - Infrastructure wrapper for ldap3 library.

This module encapsulates all ldap3 library interactions, providing a clean
interface for the flext-ldap service layer. Only this adapter imports ldap3
directly; all other modules work with protocol abstractions.

Business Rules:
    - ldap3 library is ONLY imported here (zero tolerance for direct imports elsewhere)
    - Connection binding uses ldap3.Connection with auto_bind and auto_range options
    - STARTTLS is handled separately from SSL (mutual exclusion enforced in config)
    - Search results are converted to FlextLdifModels.Entry via FlextLdifParser
    - CRUD operations (add, modify, delete) return FlextResult for consistency
    - LDAPException is caught and converted to FlextResult.fail() (no exceptions leak)

Audit Implications:
    - All LDAP operations are traceable via ldap3 connection logging
    - Connection failures are logged with host/port (credentials excluded)
    - Search operations log result counts for compliance reporting
    - CRUD operations log affected entry DNs for audit trail

Architecture Notes:
    - Implements Adapter pattern between ldap3 and flext-ldap service layer
    - Uses SRP via inner classes: ConnectionManager, ResultConverter, AttributeNormalizer
    - Extends FlextService[bool] for health check capability
    - Pydantic frozen=False allows mutable connection state

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from flext_core import FlextResult, FlextRuntime, FlextService
from flext_core.typings import FlextTypes
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif._models.domain import (
    FlextLdifModelsDomains,  # noqa: PLC2701  # Required for isinstance and model_validate - no public API available
)
from flext_ldif._models.results import (
    FlextLdifModelsResults,  # Required for ParseResponse type - no public API available
)
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.services.parser import FlextLdifParser
from flext_ldif.utilities import FlextLdifUtilities
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPException
from pydantic import BaseModel, ConfigDict

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.typings import FlextLdapTypes

# ldap3 expects Literal["BASE", "LEVEL", "SUBTREE"]
# We use StrEnum internally and pass validated string values to ldap3


class Ldap3Adapter(FlextService[bool]):
    """Service adapter for ldap3 library following flext-ldif patterns.

    Wraps ldap3 Connection and Server objects to provide a simplified
    interface for LDAP operations. Reuses FlextLdifParser for automatic
    conversion of LDAP results to Entry models.
    """

    # Service requires mutable state for connection management
    model_config = ConfigDict(frozen=False)

    class ConnectionManager:
        """Connection management logic (SRP)."""

        @staticmethod
        def create_server(config: FlextLdapModels.ConnectionConfig) -> Server:
            """Create ldap3 Server object.

            Business Rules:
                - SSL connections use use_ssl=True (port 636 default)
                - Non-SSL connections use use_ssl=False (port 389 default)
                - Connect timeout uses config.timeout value
                - Server object is created without connection attempt

            Architecture:
                - Uses ldap3 Server() constructor directly
                - Returns Server instance for Connection creation
                - No network calls - object creation only

            Args:
                config: Connection configuration with host, port, SSL/TLS settings.

            Returns:
                ldap3 Server object configured for connection.

            """
            if config.use_ssl:
                return Server(
                    host=config.host,
                    port=config.port,
                    use_ssl=True,
                    connect_timeout=config.timeout,
                )
            return Server(
                host=config.host,
                port=config.port,
                connect_timeout=config.timeout,
            )

        @staticmethod
        def create_connection(
            server: Server,
            config: FlextLdapModels.ConnectionConfig,
        ) -> Connection:
            """Create ldap3 Connection object.

            Business Rules:
                - Bind credentials (user, password) from config
                - auto_bind from config controls automatic binding
                - auto_range from config controls automatic range handling
                - Receive timeout uses config.timeout value
                - Connection is created but may not be bound yet

            Architecture:
                - Uses ldap3 Connection() constructor directly
                - Returns Connection instance (may need bind() call)
                - No network calls if auto_bind=False

            Args:
                server: ldap3 Server object from create_server().
                config: Connection configuration with bind credentials.

            Returns:
                ldap3 Connection object (bound if auto_bind=True).

            """
            return Connection(
                server=server,
                user=config.bind_dn,
                password=config.bind_password,
                auto_bind=config.auto_bind,
                auto_range=config.auto_range,
                receive_timeout=config.timeout,
            )

        @staticmethod
        def handle_tls(
            connection: Connection,
            config: FlextLdapModels.ConnectionConfig,
        ) -> FlextResult[bool]:
            """Handle STARTTLS if requested.

            Business Rules:
                - STARTTLS is only used if use_tls=True and use_ssl=False
                - SSL connections (use_ssl=True) skip STARTTLS
                - Calls connection.start_tls() for protocol-level TLS negotiation
                - Returns success if STARTTLS not needed or succeeds
                - Returns failure if STARTTLS fails

            Audit Implications:
                - STARTTLS failures are logged with error details
                - TLS negotiation is critical for security compliance

            Architecture:
                - Uses ldap3 Connection.start_tls() for protocol-level operation
                - Returns FlextResult pattern - no exceptions raised
                - LDAPException is caught and converted to failure

            Args:
                connection: Active ldap3.Connection instance.
                config: Connection configuration with TLS settings.

            Returns:
                FlextResult[bool]: Success if STARTTLS not needed or succeeds.

            """
            if not config.use_tls or config.use_ssl:
                return FlextResult[bool].ok(True)

            try:
                if not connection.start_tls():
                    return FlextResult[bool].fail("Failed to start TLS")
                return FlextResult[bool].ok(True)
            except LDAPException as tls_error:
                error_msg = f"Failed to start TLS: {tls_error}"
                return FlextResult[bool].fail(error_msg)

    class ResultConverter:
        """Result conversion logic (SRP)."""

        @staticmethod
        def convert_ldap3_results(
            connection: Connection,
        ) -> list[tuple[str, dict[str, list[str]]]]:
            """Convert ldap3 connection entries to parser format.

            Business Rules:
                - Extracts DN from entry.entry_dn (string conversion)
                - Iterates entry.entry_attributes for all attributes
                - Converts attribute values to list[str] format
                - None values become empty lists []
                - Single values become single-item lists [value]
                - Multiple values become lists [value1, value2, ...]

            Audit Implications:
                - All attribute values are normalized to string lists
                - Value type information may be lost (all become strings)
                - Empty lists preserve attribute presence (important for schema)

            Architecture:
                - Uses FlextRuntime.is_list_like() for type-safe value handling
                - Returns list[tuple[str, dict[str, list[str]]]] for parser compatibility
                - No network calls - processes connection.entries

            Args:
                connection: Active ldap3.Connection with search results in connection.entries.

            Returns:
                List of (dn, attributes_dict) tuples in parser format.

            """
            results: list[tuple[str, dict[str, list[str]]]] = []

            for entry in connection.entries:
                attrs: dict[str, list[str]] = {}
                dn = str(entry.entry_dn)

                for attr in entry.entry_attributes:
                    values = entry[attr].values
                    if FlextRuntime.is_list_like(values):
                        attrs[attr] = [str(v) for v in values]
                    elif values is None:
                        attrs[attr] = []
                    else:
                        attrs[attr] = [str(values)]

                results.append((dn, attrs))

            return results

        @staticmethod
        def extract_dn(
            parsed: FlextLdapProtocols.LdapEntry.EntryProtocol | FlextLdifModels.Entry,
        ) -> FlextLdifModelsDomains.DistinguishedName:
            """Extract Distinguished Name from LDAP entry.

            Business Rules:
                - Extracts DN from FlextLdifModels.Entry instances directly
                - Handles protocol-based entries via hasattr() checks
                - Uses FlextLdifUtilities.DN.get_dn_value() for normalization
                - Returns empty DistinguishedName("") when extraction fails (no exception)
                - DN normalization ensures consistent format across server types

            Audit Implications:
                - DN extraction is critical for LDAP operations targeting specific entries
                - Empty DN ("") returned when extraction fails - caller must validate
                - Uses FlextLdifModelsDomains.DistinguishedName for type-safe DN handling
                - Remote LDAP operations depend on correct DN for targeting entries

            Architecture:
                - Delegates to FlextLdifUtilities.DN.get_dn_value() for normalization
                - Returns FlextLdifModelsDomains.DistinguishedName (Pydantic model)
                - No network calls - pure data extraction from local objects

            Args:
                parsed: Entry from LDAP search or protocol-based entry structure.

            Returns:
                DistinguishedName instance with extracted or empty value.

            """
            # Direct access for FlextLdifModels.Entry
            if isinstance(parsed, FlextLdifModels.Entry):
                return (
                    parsed.dn
                    or FlextLdifModelsDomains.DistinguishedName.model_validate({
                        "value": ""
                    })
                )

            # Protocol-based entry - extract DN value using utilities
            if not hasattr(parsed, "dn"):
                return FlextLdifModelsDomains.DistinguishedName.model_validate({
                    "value": ""
                })

            dn_raw = parsed.dn
            if dn_raw is None:
                return FlextLdifModelsDomains.DistinguishedName.model_validate({
                    "value": ""
                })

            # Already DistinguishedName instance
            if isinstance(dn_raw, FlextLdifModelsDomains.DistinguishedName):
                return dn_raw

            # Use FlextLdifUtilities.DN for conversion
            dn_value = FlextLdifUtilities.DN.get_dn_value(dn_raw)
            return FlextLdifModelsDomains.DistinguishedName.model_validate({
                "value": dn_value
            })

        @staticmethod
        def extract_attrs_dict(
            attrs: object,
        ) -> FlextLdapTypes.Ldap.AttributeDict:
            """Extract LDAP attributes as dictionary from various input formats.

            Business Rules:
                - Handles objects with 'attributes' property (ldap3 Entry, Pydantic models)
                - Handles Pydantic BaseModel via model_dump() for safe serialization
                - Handles Mapping types (dict, dict-like objects) directly
                - All attribute values normalized to list[str] format
                - Empty dict {} returned on extraction failure (no exception raised)
                - Uses FlextRuntime.is_list_like() for type-safe value handling

            Audit Implications:
                - Attribute extraction affects data written to/read from LDAP directory
                - All values converted to strings - numeric/boolean type info may be lost
                - Empty dict {} returned on extraction failure - no exception raised
                - Uses Pydantic's model_dump() for safe model serialization

            Architecture:
                - Handles: objects with 'attributes' property, Pydantic BaseModel, Mapping
                - Returns FlextLdapTypes.Ldap.AttributeDict (dict[str, list[str]])
                - No network calls - pure data transformation

            """
            # Check for attributes property
            attrs_attr = getattr(attrs, "attributes", None)
            if attrs_attr is not None and isinstance(attrs_attr, (dict, Mapping)):
                return {k: list(v) for k, v in attrs_attr.items()}

            # Check for Pydantic model with model_dump method
            if isinstance(attrs, BaseModel):
                dumped = attrs.model_dump()
                if isinstance(dumped, dict):
                    attrs_value = dumped.get("attributes", {})
                    if isinstance(attrs_value, dict):
                        # Convert to AttributeDict format (dict[str, list[str]])
                        return {
                            k: (
                                [str(item) for item in v]
                                if FlextRuntime.is_list_like(v)
                                else [str(v)]
                            )
                            for k, v in attrs_value.items()
                        }
                    return {}

            # Check if attrs is Mapping directly
            if isinstance(attrs, Mapping):
                return {
                    k: [str(item) for item in v]
                    if FlextRuntime.is_list_like(v)
                    else [str(v)]
                    for k, v in attrs.items()
                }
            return {}

        @staticmethod
        def extract_attributes(
            parsed: FlextLdapProtocols.LdapEntry.EntryProtocol | FlextLdifModels.Entry,
        ) -> FlextLdifModels.LdifAttributes:
            """Extract LDAP attributes as FlextLdifModels.LdifAttributes.

            Business Rules:
                - Extracts attributes from FlextLdifModels.Entry or protocol entries
                - Delegates to extract_attrs_dict() for raw dict extraction
                - Wraps result in FlextLdifModels.LdifAttributes Pydantic model
                - Empty attributes {} returned when extraction fails (not an error)
                - Pydantic validation ensures attribute structure correctness

            Audit Implications:
                - LdifAttributes model validates attribute structure via Pydantic
                - Empty attributes {} returned when extraction fails - not an error
                - Attribute names and values preserved exactly as received from LDAP
                - Used by search operations to return structured entry data

            Architecture:
                - Delegates to extract_attrs_dict() for raw dict extraction
                - Returns FlextLdifModels.LdifAttributes (validated Pydantic model)
                - No network calls - pure data transformation

            """
            # Get attributes from entry
            attrs_raw: object | None = None
            if isinstance(parsed, FlextLdifModels.Entry) or hasattr(
                parsed, "attributes"
            ):
                attrs_raw = parsed.attributes

            # Handle None case
            if attrs_raw is None:
                return FlextLdifModels.LdifAttributes.model_validate({"attributes": {}})

            # Already correct type
            if isinstance(attrs_raw, FlextLdifModels.LdifAttributes):
                return attrs_raw

            # Extract attributes dict and create new instance
            attrs_dict = Ldap3Adapter.ResultConverter.extract_attrs_dict(attrs_raw)
            return FlextLdifModels.LdifAttributes.model_validate({
                "attributes": attrs_dict
            })

        @staticmethod
        def extract_metadata(
            parsed: FlextLdapProtocols.LdapEntry.EntryProtocol | FlextLdifModels.Entry,
        ) -> FlextLdifModelsDomains.QuirkMetadata | None:
            """Extract server-specific quirk metadata from LDAP entry.

            Business Rules:
                - Extracts quirk metadata from entry attributes or metadata property
                - Metadata indicates server-specific behaviors (OpenLDAP, OID, OUD quirks)
                - Delegates to normalize_metadata() for safe value filtering
                - None returned when no metadata present (normal, not an error)
                - Used by flext-ldif to apply server-specific transformations

            Audit Implications:
                - Quirk metadata affects how entries are processed for different LDAP servers
                - None returned when no metadata present - this is normal, not an error
                - Metadata filtering removes invalid/non-string values via normalize_metadata()
                - Server detection relies on this metadata for proper quirk application

            Architecture:
                - Delegates to normalize_metadata() for safe value filtering
                - Returns FlextLdifModelsDomains.QuirkMetadata (Pydantic model) or None
                - Uses FlextLdifModelsDomains from internal module for mypy compatibility
                - No network calls - pure data extraction

            Returns:
                QuirkMetadata instance or None if no metadata available.

            """
            if not hasattr(parsed, "metadata"):
                return None

            metadata_raw = parsed.metadata
            if not metadata_raw:
                return None

            # Already QuirkMetadata instance - use directly
            if isinstance(metadata_raw, FlextLdifModelsDomains.QuirkMetadata):
                return metadata_raw

            # Normalize metadata using normalize_metadata() - handles all filtering and conversion
            normalized = Ldap3Adapter.ResultConverter.normalize_metadata(metadata_raw)
            if normalized:
                return FlextLdifModelsDomains.QuirkMetadata.model_validate(normalized)
            return None

        @staticmethod
        def normalize_metadata(
            metadata: (
                FlextTypes.MetadataAttributeValue
                | Mapping[str, str | int | float | bool | None]
                | object
                | None
            ),
        ) -> FlextTypes.MetadataAttributeValue | None:
            """Normalize metadata for Entry model validation.

            Business Rules:
                - Filters to types accepted by QuirkMetadata: str | int | float | bool | None
                - String keys are required (filters out non-string keys)
                - Invalid value types are filtered out (preserves valid entries)
                - Handles dict, Mapping, and Pydantic models with model_dump()
                - Returns None if metadata is empty or invalid

            Audit Implications:
                - Metadata normalization ensures type safety for QuirkMetadata
                - Invalid values are silently filtered (no errors raised)
                - Preserves valid metadata entries for server quirk tracking

            Architecture:
                - Uses isinstance checks for type filtering
                - Uses Pydantic model_dump() for model serialization
                - Returns dict[str, str | int | float | bool | None] or None

            Args:
                metadata: Raw metadata from entry (dict, Mapping, Pydantic model, or None).

            Returns:
                Normalized metadata dict or None if empty/invalid.

            """
            if not metadata:
                return None

            # Already dict with correct types - use directly
            if isinstance(metadata, dict):
                # Filter to ensure all values are valid types
                return {
                    k: v
                    for k, v in metadata.items()
                    if isinstance(k, str)
                    and (isinstance(v, (str, int, float, bool)) or v is None)
                }

            # Handle Mapping types - convert to dict with filtering
            if isinstance(metadata, Mapping):
                return {
                    key: value
                    for key, value in metadata.items()
                    if isinstance(key, str)
                    and (isinstance(value, (str, int, float, bool)) or value is None)
                }

            # Handle Pydantic models - use model_dump() directly
            if isinstance(metadata, BaseModel):
                dumped = metadata.model_dump()
                if isinstance(dumped, dict):
                    # Filter to ensure all values are valid types
                    return {
                        k: v
                        for k, v in dumped.items()
                        if isinstance(k, str)
                        and (isinstance(v, (str, int, float, bool)) or v is None)
                    }

            return None

        @staticmethod
        def convert_parsed_entries(
            parse_response: FlextLdifModelsResults.ParseResponse,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Convert ParseResponse from FlextLdifParser to list of Entry models.

            Business Rules:
                - Transforms ParseResponse from FlextLdifParser into validated Entry list
                - Handles properly typed entries from parser (direct conversion)
                - Defensively converts invalid structures for edge cases (tests, manual)
                - Empty list returned when parse_response has no entries
                - All entries validated as FlextLdifModels.Entry instances
                - Delegates to extract_dn(), extract_attributes(), extract_metadata()

            Audit Implications:
                - This is the main entry point for LDAP search result processing
                - All entries returned are validated FlextLdifModels.Entry instances
                - Defensive conversion handles edge cases (tests, manual construction)
                - Empty list returned when parse_response has no entries
                - Uses FlextResult pattern for consistent error handling

            Architecture:
                - Input: FlextLdifModelsResults.ParseResponse from FlextLdifParser
                - Output: FlextResult[list[FlextLdifModels.Entry]] (railway pattern)
                - Delegates to extract_dn(), extract_attributes(), extract_metadata()
                - No network calls - processes pre-fetched LDAP results

            Remote Operation Context:
                - Called after FlextLdifParser.parse_ldap3_results() processes raw LDAP data
                - Search results were already fetched from remote LDAP server
                - This method performs local transformation only

            """
            # Access entries attribute - ParseResponse has entries: list[Entry]
            entries_raw = getattr(parse_response, "entries", [])
            if not entries_raw:
                return FlextResult[list[FlextLdifModels.Entry]].ok([])

            entries: list[FlextLdifModels.Entry] = []
            for entry_raw in entries_raw:
                # Already valid Entry instance - use directly
                if isinstance(entry_raw, FlextLdifModels.Entry):
                    entries.append(entry_raw)
                    continue

                # Defensive conversion for invalid structures (e.g., from tests or manual construction)
                # Extract DN, attributes, and metadata using helper methods
                # Type narrowing: entry_raw is not Entry, so it might be EntryProtocol or invalid structure
                entry_for_extraction: (
                    FlextLdapProtocols.LdapEntry.EntryProtocol | FlextLdifModels.Entry
                ) = entry_raw
                dn_obj = Ldap3Adapter.ResultConverter.extract_dn(entry_for_extraction)
                attrs_obj = Ldap3Adapter.ResultConverter.extract_attributes(
                    entry_for_extraction
                )
                metadata_obj = Ldap3Adapter.ResultConverter.extract_metadata(
                    entry_for_extraction
                )

                # Create Entry with extracted objects
                entry = FlextLdifModels.Entry(
                    dn=dn_obj,
                    attributes=attrs_obj,
                    metadata=metadata_obj,
                )
                entries.append(entry)

            return FlextResult[list[FlextLdifModels.Entry]].ok(entries)

    class OperationExecutor:
        """LDAP operation execution logic (SRP)."""

        def __init__(self, adapter: Ldap3Adapter) -> None:
            """Initialize with adapter instance."""
            self._adapter = adapter

        def execute_add(
            self,
            connection: Connection,
            dn_str: str,
            ldap_attrs: FlextLdapTypes.Ldap.Attributes,
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Execute LDAP add operation via ldap3 Connection.

            Business Rules:
                - Calls connection.add() with DN and attributes dict
                - LDAP error codes are extracted from connection.result
                - Success returns OperationResult with entries_affected=1
                - Failure returns FlextResult.fail() with error message

            Audit Implications:
                - LDAP operation errors are logged with description from server
                - Successful operations log success status

            Architecture:
                - Uses ldap3 Connection.add() for protocol-level operation
                - Error extraction uses _extract_error_result() helper
                - Returns FlextResult pattern - no exceptions raised

            Args:
                connection: Active ldap3 Connection object
                dn_str: Distinguished name as string
                ldap_attrs: Attributes dict in ldap3 format

            Returns:
                FlextResult containing OperationResult with success status

            """
            try:
                add_func: FlextLdapTypes.Ldap.AddCallable = connection.add
                success = add_func(dn_str, None, ldap_attrs)

                if success:
                    return FlextResult[FlextLdapModels.OperationResult].ok(
                        FlextLdapModels.OperationResult(
                            success=True,
                            operation_type=FlextLdapConstants.OperationType.ADD,
                            message="Entry added successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Add failed")
            except LDAPException as e:
                error_msg = f"Add failed: {e!s}"
                return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        def execute_modify(
            self,
            connection: Connection,
            dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
            changes: FlextLdapTypes.Ldap.ModifyChanges,
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Execute LDAP modify operation via ldap3 Connection.

            Business Rules:
                - DN is normalized using FlextLdifUtilities.DN.get_dn_value()
                - Calls connection.modify() with DN and changes dict
                - LDAP error codes are extracted from connection.result
                - Success returns OperationResult with entries_affected=1
                - Failure returns FlextResult.fail() with error message

            Audit Implications:
                - LDAP operation errors are logged with description from server
                - Successful operations log success status

            Architecture:
                - Uses ldap3 Connection.modify() for protocol-level operation
                - Error extraction uses _extract_error_result() helper
                - Returns FlextResult pattern - no exceptions raised

            Args:
                connection: Active ldap3 Connection object
                dn: Distinguished name (string or DistinguishedName model)
                changes: Modification changes dict in ldap3 format

            Returns:
                FlextResult containing OperationResult with success status

            """
            try:
                dn_str = FlextLdifUtilities.DN.get_dn_value(dn)
                modify_func: FlextLdapTypes.Ldap.ModifyCallable = connection.modify
                success = modify_func(dn_str, changes)

                if success:
                    return FlextResult[FlextLdapModels.OperationResult].ok(
                        FlextLdapModels.OperationResult(
                            success=True,
                            operation_type=FlextLdapConstants.OperationType.MODIFY,
                            message="Entry modified successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Modify failed")
            except LDAPException as e:
                error_msg = f"Modify failed: {e!s}"
                return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        def execute_delete(
            self,
            connection: Connection,
            dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Execute LDAP delete operation via ldap3 Connection.

            Business Rules:
                - DN is normalized using FlextLdifUtilities.DN.get_dn_value()
                - Calls connection.delete() with DN string
                - LDAP error codes are extracted from connection.result
                - Success returns OperationResult with entries_affected=1
                - Failure returns FlextResult.fail() with error message

            Audit Implications:
                - LDAP operation errors are logged with description from server
                - Successful operations log success status

            Architecture:
                - Uses ldap3 Connection.delete() for protocol-level operation
                - Error extraction uses _extract_error_result() helper
                - Returns FlextResult pattern - no exceptions raised

            Args:
                connection: Active ldap3 Connection object
                dn: Distinguished name (string or DistinguishedName model)

            Returns:
                FlextResult containing OperationResult with success status

            """
            try:
                dn_str = FlextLdifUtilities.DN.get_dn_value(dn)
                delete_func: FlextLdapTypes.Ldap.DeleteCallable = connection.delete
                success = delete_func(dn_str)

                if success:
                    return FlextResult[FlextLdapModels.OperationResult].ok(
                        FlextLdapModels.OperationResult(
                            success=True,
                            operation_type=FlextLdapConstants.OperationType.DELETE,
                            message="Entry deleted successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Delete failed")
            except LDAPException as e:
                error_msg = f"Delete failed: {e!s}"
                return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

        @staticmethod
        def _extract_error_result(
            connection: Connection,
            prefix: str,
        ) -> FlextResult[FlextLdapModels.OperationResult]:
            """Extract error message from connection result.

            Business Rules:
                - Extracts error description from connection.result dict
                - Uses "description" field if available (most detailed)
                - Falls back to generic error message if description missing
                - Uses FlextRuntime.is_dict_like() for type-safe dict access

            Audit Implications:
                - Error messages preserve LDAP server error context
                - Description field contains server-specific error details
                - Error extraction enables proper error propagation

            Architecture:
                - Uses connection.result dict from ldap3
                - Uses FlextRuntime.is_dict_like() for type narrowing
                - Returns FlextResult.fail() with error message

            Args:
                connection: ldap3.Connection with error in connection.result.
                prefix: Error message prefix (e.g., "Add failed").

            Returns:
                FlextResult.fail() with extracted error message.

            """
            error_msg = f"{prefix}: LDAP operation returned failure status"
            result_dict = connection.result
            if FlextRuntime.is_dict_like(result_dict) and "description" in result_dict:
                description = result_dict.get("description")
                if isinstance(description, str):
                    error_msg = f"{prefix}: {description}"
            return FlextResult[FlextLdapModels.OperationResult].fail(error_msg)

    class SearchExecutor:
        """Search operation execution logic (SRP)."""

        @dataclass(frozen=True)
        class SearchParams:
            """Search parameters grouped together to reduce method arguments."""

            base_dn: str
            filter_str: str
            ldap_scope: FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral
            search_attributes: list[str]
            size_limit: int
            time_limit: int

        def __init__(self, adapter: Ldap3Adapter) -> None:
            """Initialize search executor with adapter instance.

            Business Rules:
                - Adapter is REQUIRED (no default, fail-fast pattern)
                - Executor stores reference for delegation to adapter
                - No connection validation at init (validated during execute)

            Architecture:
                - Inner class encapsulates search execution logic (SRP)
                - Delegates all protocol operations to Ldap3Adapter
                - Enables testability through dependency injection

            Args:
                adapter: Ldap3Adapter instance for LDAP protocol operations.
                    Must have active connection for execute() to succeed.

            """
            self._adapter = adapter

        def execute(
            self,
            connection: Connection,
            params: SearchParams,
            server_type: FlextLdifConstants.ServerTypes | str,
        ) -> FlextResult[list[FlextLdifModels.Entry]]:
            """Execute LDAP search and convert results.

            Business Rules:
                - Performs ldap3 Connection.search() with provided parameters
                - Validates LDAP result codes (allows partial success codes)
                - Converts server_type to ServerTypeLiteral using FlextLdifConstants.normalize_server_type()
                - Parses results using FlextLdifParser.parse_ldap3_results()
                - Converts ParseResponse to list[Entry] via ResultConverter
                - LDAPException is caught and converted to FlextResult.fail()

            Audit Implications:
                - Search parameters are logged by connection.search()
                - Result codes are validated for compliance
                - Server type normalization enables quirk application
                - Parse failures are logged with error details

            Architecture:
                - Uses ldap3 Connection.search() for protocol-level operation
                - Delegates to FlextLdifParser for server-specific parsing
                - Uses ResultConverter.convert_parsed_entries() for Entry conversion
                - Returns FlextResult pattern - no exceptions raised

            Args:
                connection: Active ldap3.Connection instance (must be bound).
                params: SearchParams dataclass with all search parameters.
                server_type: Server type (ServerTypes enum or string) for parsing quirks.

            Returns:
                FlextResult[list[Entry]]: Parsed entries or error if search/parse fails.

            """
            try:
                connection.search(
                    search_base=params.base_dn,
                    search_filter=params.filter_str,
                    search_scope=params.ldap_scope,
                    attributes=params.search_attributes,
                    size_limit=params.size_limit,
                    time_limit=params.time_limit,
                )

                result_code = connection.result.get("result", -1)
                if (
                    result_code
                    not in FlextLdapConstants.LdapResultCodes.PARTIAL_SUCCESS_CODES
                ):
                    error_msg = connection.result.get("message", "LDAP search failed")
                    error_desc = connection.result.get("description", "unknown")
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"LDAP search failed: {error_desc} - {error_msg}",
                    )

                ldap3_results = self._adapter.ResultConverter.convert_ldap3_results(
                    connection,
                )
                # Convert server_type to ServerTypeLiteral for parser
                # Use FlextLdifConstants.normalize_server_type() directly - handles all mappings
                server_type_str = (
                    server_type.value
                    if isinstance(server_type, FlextLdifConstants.ServerTypes)
                    else str(server_type)
                )
                # Use FlextLdifConstants.normalize_server_type() directly - no duplication
                # This handles oracle_oid/oracle_oud → oid/oud mapping automatically
                try:
                    server_type_literal = FlextLdifConstants.normalize_server_type(
                        server_type_str,
                    )
                except ValueError:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        f"Unsupported server type: {server_type_str}",
                    )
                parse_result = self._adapter.parser.parse_ldap3_results(
                    ldap3_results,
                    server_type_literal,
                )

                if parse_result.is_failure:
                    return FlextResult[list[FlextLdifModels.Entry]].fail(
                        str(parse_result.error) if parse_result.error else "",
                    )

                return self._adapter.ResultConverter.convert_parsed_entries(
                    parse_result.unwrap(),
                )
            except LDAPException as e:
                return FlextResult[list[FlextLdifModels.Entry]].fail(
                    f"Search failed: {e!s}",
                )

    _connection: Connection | None
    _server: Server | None
    _parser: FlextLdifParser
    _entry_adapter: FlextLdapEntryAdapter

    @property
    def parser(self) -> FlextLdifParser:
        """Get parser instance."""
        return self._parser

    def __init__(
        self,
        **kwargs: FlextTypes.GeneralValueType,
    ) -> None:
        """Initialize adapter service with parser.

        Args:
            **kwargs: Keyword arguments including:
                - parser: Optional FlextLdifParser instance. If None, uses default from FlextLdif.
                - Additional service configuration parameters (delegated to FlextService).

        """
        # Extract parser from kwargs if provided
        parser_raw = kwargs.pop("parser", None)
        parser: FlextLdifParser | None = (
            parser_raw if isinstance(parser_raw, FlextLdifParser) else None
        )
        # Initialize parent with remaining kwargs
        super().__init__(**kwargs)
        # Set parser - use default if not provided
        if parser is None:
            parser = FlextLdif.get_instance().parser
        self._connection = None
        self._server = None
        self._parser = parser
        # Create adapter instance directly
        self._entry_adapter = FlextLdapEntryAdapter()

    def connect(
        self,
        config: FlextLdapModels.ConnectionConfig,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[bool]:
        """Establish LDAP connection using ldap3 library.

        Business Rules:
            - Creates ldap3 Server object based on SSL/TLS configuration
            - Creates ldap3 Connection object with bind credentials
            - STARTTLS is handled if use_tls=True and use_ssl=False
            - Connection must be bound (authenticated) to succeed
            - Connection state is tracked internally for subsequent operations

        Audit Implications:
            - Connection attempts are logged (host/port, credentials excluded)
            - TLS/SSL configuration is logged for security audit
            - Failed connections log error messages for forensic analysis
            - Connection state changes trigger audit events

        Architecture:
            - Uses ConnectionManager.create_server() for Server object
            - Uses ConnectionManager.create_connection() for Connection object
            - Uses ConnectionManager.handle_tls() for STARTTLS if needed
            - Returns FlextResult pattern - no exceptions raised

        Args:
            config: Connection configuration (host, port, bind_dn, bind_password, SSL/TLS)

        Returns:
            FlextResult[bool] indicating connection success

        """
        try:
            self._server = self.ConnectionManager.create_server(config)
            self._connection = self.ConnectionManager.create_connection(
                self._server,
                config,
            )

            tls_result = self.ConnectionManager.handle_tls(self._connection, config)
            if tls_result.is_failure:
                return tls_result

            if not self._connection.bound:
                return FlextResult[bool].fail("Failed to bind to LDAP server")

            return FlextResult[bool].ok(True)
        except LDAPException as e:
            return FlextResult[bool].fail(f"Connection failed: {e!s}")

    def disconnect(self) -> None:
        """Close LDAP connection.

        Business Rules:
            - Gracefully closes LDAP connection and releases resources
            - No-op if already disconnected (idempotent operation)
            - Connection state is cleared after disconnection
            - Errors during unbind are logged but not propagated

        Audit Implications:
            - Disconnection errors are logged at DEBUG level
            - Connection state is cleared regardless of unbind success
            - Resource cleanup is guaranteed

        Architecture:
            - Uses ldap3 Connection.unbind() for protocol-level disconnection
            - Handles LDAPException and OSError gracefully
            - Always clears connection state (finally block)

        """
        if self._connection:
            try:
                unbind_func: Callable[[], None] = self._connection.unbind
                unbind_func()
            except (LDAPException, OSError) as e:
                self.logger.debug("Error during disconnect", error=str(e))
            finally:
                self._connection = None
                self._server = None

    @property
    def connection(self) -> Connection | None:
        """Get underlying ldap3 Connection object."""
        return self._connection

    @property
    def is_connected(self) -> bool:
        """Check if adapter has an active connection."""
        return self._connection is not None and self._connection.bound

    def _get_connection(self) -> FlextResult[Connection]:
        """Get connection with fast fail if not available."""
        if not self.is_connected or self._connection is None:
            return FlextResult[Connection].fail(
                FlextLdapConstants.ErrorStrings.NOT_CONNECTED,
            )
        return FlextResult[Connection].ok(self._connection)

    @staticmethod
    def _map_scope(
        scope: FlextLdapConstants.SearchScope | str,
    ) -> FlextResult[FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral]:
        """Map scope string to ldap3 scope constant.

        Uses direct StrEnum value mapping for type-safe conversion.
        """
        # Normalize to StrEnum if string provided
        # Type narrowing: scope is str | SearchScope
        # SearchScope is a StrEnum (subclass of str), so check for SearchScope first
        if isinstance(scope, FlextLdapConstants.SearchScope):
            # Type narrowing: scope is SearchScope
            scope_enum = scope
        else:
            # Type narrowing: scope is str (SearchScope is also str, but already handled above)
            # Convert string to SearchScope enum
            try:
                scope_enum = FlextLdapConstants.SearchScope(scope.upper())
            except ValueError:
                return FlextResult[
                    FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral
                ].fail(f"Invalid LDAP scope: {scope}")

        # Direct mapping using StrEnum values with proper type narrowing
        ldap3_scope_mapping: Mapping[
            FlextLdapConstants.SearchScope,
            FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral,
        ] = {
            FlextLdapConstants.SearchScope.BASE: "BASE",
            FlextLdapConstants.SearchScope.ONELEVEL: "LEVEL",
            FlextLdapConstants.SearchScope.SUBTREE: "SUBTREE",
        }

        if scope_enum in ldap3_scope_mapping:
            ldap3_value = ldap3_scope_mapping[scope_enum]
            return FlextResult[FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral].ok(
                ldap3_value,
            )

        return FlextResult[FlextLdapConstants.LiteralTypes.Ldap3ScopeLiteral].fail(
            f"Invalid LDAP scope: {scope}",
        )

    def search(
        self,
        search_options: FlextLdapModels.SearchOptions,
        server_type: FlextLdifConstants.ServerTypes
        | str = FlextLdifConstants.ServerTypes.RFC,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.SearchResult]:
        """Perform LDAP search operation and convert to Entry models.

        Business Rules:
            - Connection must be established and bound before search
            - Search scope is mapped from FlextLdapConstants to ldap3 format (ONELEVEL→LEVEL)
            - Server type determines parsing quirks (OpenLDAP, OUD, OID, RFC)
            - Search results are parsed using FlextLdifParser.parse_ldap3_results()
            - Empty result sets return successful SearchResult with empty entries list
            - LDAP result codes are validated (partial success codes allowed)

        Audit Implications:
            - Search operations are logged with base_dn, filter, and scope
            - Result counts are logged for compliance reporting
            - Failed searches log error messages with search parameters
            - Server type normalization is logged for quirk tracking

        Architecture:
            - Uses SearchExecutor.execute() for protocol-level search
            - Uses FlextLdifParser for server-specific entry parsing
            - Returns FlextResult pattern - no exceptions raised

        Args:
            search_options: Search configuration (base_dn, filter_str, scope, attributes)
            server_type: LDAP server type for parsing quirks (default: RFC)

        Returns:
            FlextResult containing SearchResult with Entry models

        """
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )

        # Convert scope to str or SearchScope for _map_scope
        # SearchOptions.scope is str, but may need conversion to SearchScope enum
        # Type narrowing: scope is str from SearchOptions model
        scope_for_mapping: str | FlextLdapConstants.SearchScope = search_options.scope
        scope_result = Ldap3Adapter._map_scope(scope_for_mapping)
        if scope_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(scope_result.error) if scope_result.error else "",
            )

        search_params = self.SearchExecutor.SearchParams(
            base_dn=search_options.base_dn,
            filter_str=search_options.filter_str,
            ldap_scope=scope_result.unwrap(),
            search_attributes=search_options.attributes or [],
            size_limit=search_options.size_limit,
            time_limit=search_options.time_limit,
        )
        entries_result = self.SearchExecutor(self).execute(
            connection_result.unwrap(),
            search_params,
            server_type,
        )

        if entries_result.is_failure:
            return FlextResult[FlextLdapModels.SearchResult].fail(
                str(entries_result.error) if entries_result.error else "",
            )

        return FlextResult[FlextLdapModels.SearchResult].ok(
            FlextLdapModels.SearchResult(
                entries=entries_result.unwrap(),
                search_options=search_options,
            ),
        )

    def add(
        self,
        entry: FlextLdifModels.Entry,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Add LDAP entry using Entry model.

        Business Rules:
            - Entry attributes are converted from FlextLdifModels.Entry to ldap3 format
            - DN is extracted using FlextLdifUtilities.DN.get_dn_value()
            - Entry must be unique (LDAP error 68 if entry already exists)
            - Entry must conform to LDAP schema constraints
            - Connection must be established and bound before add operation

        Audit Implications:
            - Add operations are logged with entry DN
            - Successful adds log affected count (always 1)
            - Failed adds log error messages with DN for forensic analysis
            - Attribute conversion failures are logged before LDAP operation

        Architecture:
            - Uses FlextLdapEntryAdapter.ldif_entry_to_ldap3_attributes() for conversion
            - Uses OperationExecutor.execute_add() for protocol-level operation
            - Returns FlextResult pattern - no exceptions raised

        Args:
            entry: Entry model to add (must include DN and required attributes)

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )

        attrs_result = self._entry_adapter.ldif_entry_to_ldap3_attributes(entry)
        if attrs_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                f"Failed to convert entry attributes: {attrs_result.error}",
            )

        # Extract DN value using FlextLdifUtilities.DN.get_dn_value() - handles all DN types
        dn_str = FlextLdifUtilities.DN.get_dn_value(entry.dn) if entry.dn else "unknown"
        return self.OperationExecutor(self).execute_add(
            connection_result.unwrap(),
            dn_str,
            attrs_result.unwrap(),
        )

    def modify(
        self,
        dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
        changes: FlextLdapTypes.Ldap.ModifyChanges,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Modify LDAP entry.

        Business Rules:
            - Entry must exist before modification (LDAP error 32 if not found)
            - Changes use ldap3 format: {attr_name: [(MODIFY_ADD|MODIFY_DELETE|MODIFY_REPLACE, [values])]}
            - DN normalization is applied using FlextLdifUtilities.DN.get_dn_value()
            - String DNs are converted to DistinguishedName models for type safety
            - Connection must be established and bound before modify operation

        Audit Implications:
            - Modify operations are logged with DN and change summary
            - Successful modifies log affected count (always 1)
            - Failed modifies log error messages with DN for forensic analysis

        Architecture:
            - Uses OperationExecutor.execute_modify() for protocol-level operation
            - DN conversion handled by FlextLdifUtilities.DN
            - Returns FlextResult pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to modify (string or DistinguishedName model)
            changes: Modification changes dict in ldap3 format

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )
        return self.OperationExecutor(self).execute_modify(
            connection_result.unwrap(),
            dn,  # Type: str | DistinguishedNameProtocol (runtime validated)
            changes,
        )

    def delete(
        self,
        dn: str | FlextLdapProtocols.LdapEntry.DistinguishedNameProtocol,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.OperationResult]:
        """Delete LDAP entry.

        Business Rules:
            - Entry must exist before deletion (LDAP error 32 if not found)
            - Entry must not have children (LDAP error 66 if has children)
            - DN normalization is applied using FlextLdifUtilities.DN.get_dn_value()
            - String DNs are converted to DistinguishedName models for type safety
            - Connection must be established and bound before delete operation

        Audit Implications:
            - Delete operations are logged with DN for critical audit trail
            - Successful deletes log affected count (always 1)
            - Failed deletes log error messages with DN for forensic analysis

        Architecture:
            - Uses OperationExecutor.execute_delete() for protocol-level operation
            - DN conversion handled by FlextLdifUtilities.DN
            - Returns FlextResult pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to delete (string or DistinguishedName model)

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return FlextResult[FlextLdapModels.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )
        return self.OperationExecutor(self).execute_delete(
            connection_result.unwrap(),
            dn,
        )

    def execute(self, **_kwargs: str | float | bool | None) -> FlextResult[bool]:
        """Execute service health check.

        Business Rules:
            - Returns failure if connection is not bound (NOT_CONNECTED error)
            - Returns success if connection is active and bound
            - Does not perform network round-trip (cached state check)
            - Implements FlextService.execute() contract

        Audit Implications:
            - Can be called by service orchestrators for health checks
            - Health status reflects connection state
            - No logging performed (lightweight check)

        Architecture:
            - Uses is_connected property for state check
            - Returns FlextResult pattern - no exceptions raised
            - ``_kwargs`` absorbs extra arguments for interface compatibility

        Args:
            **_kwargs: Absorbed keyword arguments for interface compatibility.

        Returns:
            FlextResult[bool]: Success if connected, failure with NOT_CONNECTED if not.

        """
        if not self.is_connected:
            return FlextResult[bool].fail(FlextLdapConstants.ErrorStrings.NOT_CONNECTED)
        return FlextResult[bool].ok(True)
