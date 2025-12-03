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
    - LDAPException is caught and converted to r.fail() (no exceptions leak)

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
from typing import cast

from flext_core import FlextRuntime
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

from flext_ldap import c, m, p, r, s, t
from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.utilities import FlextLdapUtilities as u

# ldap3 expects Literal["BASE", "LEVEL", "SUBTREE"]
# We use StrEnum internally and pass validated string values to ldap3


class Ldap3Adapter(s[bool]):
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
        def create_server(config: m.ConnectionConfig) -> Server:
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
            config: m.ConnectionConfig,
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
            config: m.ConnectionConfig,
        ) -> r[bool]:
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
                r[bool]: Success if STARTTLS not needed or succeeds.

            """
            if not config.use_tls or config.use_ssl:
                return u.ok(True)

            try:
                if not connection.start_tls():
                    return u.fail("Failed to start TLS")
                return u.ok(True)
            except LDAPException as tls_error:
                error_msg = f"Failed to start TLS: {tls_error}"
                return u.fail(error_msg)

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

            # Use u.process() for efficient entry processing
            def process_entry(entry: object) -> tuple[str, dict[str, list[str]]]:
                """Process single entry to (dn, attrs) tuple."""
                # Type narrowing: entry is ldap3.Entry with dynamic attributes
                entry_typed = cast("Mapping[str, object]", entry)
                dn = str(entry.entry_dn)  # type: ignore[attr-defined]

                # Process attributes using u.map() and u.process()
                entry_attrs = entry.entry_attributes  # type: ignore[attr-defined]
                # Build attrs dict - dict comprehension is most efficient for this pattern
                attrs_dict = {
                    attr: entry_typed[attr].values  # type: ignore[attr-defined, index]
                    for attr in entry_attrs  # type: ignore[index]
                }
                # Process values using u.process()
                attrs_result = u.process(
                    attrs_dict,
                    processor=lambda _k, v: cast(
                        "list[str]",
                        u.ensure(
                            cast("t.GeneralValueType", v),
                            target_type="str_list",
                            default=[],
                        ),
                    )
                    if v is not None
                    else (
                        cast(
                            "list[str]",
                            u.ensure(
                                cast("t.GeneralValueType", [v]),
                                target_type="str_list",
                                default=[],
                            ),
                        )
                        if v is not None
                        else []
                    ),
                    on_error="skip",
                )
                # Use u.val() mnemonic: extract value with default
                attrs = cast("dict[str, list[str]]", u.val(attrs_result, default={}))
                return (dn, attrs)

            # Process all entries using u.map()
            results = u.map(list(connection.entries), mapper=process_entry)
            return cast("list[tuple[str, dict[str, list[str]]]]", results)

        @staticmethod
        def extract_dn(
            parsed: p.LdapEntry.EntryProtocol | FlextLdifModels.Entry,
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
        ) -> t.Ldap.AttributeDict:
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
                - Returns t.Ldap.AttributeDict (dict[str, list[str]])
                - No network calls - pure data transformation

            """
            # Check for attributes property
            attrs_attr = getattr(attrs, "attributes", None)
            if attrs_attr is not None and isinstance(attrs_attr, (dict, Mapping)):
                # Use u.process() for consistent conversion
                transform_result = u.process(
                    attrs_attr,
                    processor=lambda _k, v: list(v)
                    if FlextRuntime.is_list_like(v)
                    else [v],
                    on_error="collect",
                )
                transformed = (
                    transform_result.value
                    if transform_result.is_success
                    else dict(attrs_attr)
                )
                return cast("dict[str, list[str]]", transformed)

            # Check for Pydantic model with model_dump method
            if isinstance(attrs, BaseModel):
                dumped = attrs.model_dump()
                if isinstance(dumped, dict):
                    # Use u.extract for safer nested access
                    attrs_value_result: r[dict[str, object] | None] = u.extract(
                        dumped,
                        "attributes",
                        default={},
                    )
                    attrs_value = (
                        attrs_value_result.value
                        if attrs_value_result.is_success
                        and attrs_value_result.value is not None
                        else {}
                    )
                    if isinstance(attrs_value, dict):
                        # Convert to AttributeDict format using u.map()
                        result = cast(
                            "dict[str, list[str]]",
                            u.map(
                                cast("dict[str, object]", attrs_value),
                                mapper=lambda _k, v: cast(
                                    "list[str]",
                                    u.ensure(
                                        cast("t.GeneralValueType", v),
                                        target_type="str_list",
                                        default=[],
                                    ),
                                )
                                if FlextRuntime.is_list_like(
                                    cast("t.GeneralValueType", v)
                                )
                                else [str(v)],
                            ),
                        )
                        return cast("t.Ldap.AttributeDict", result)
                    return {}

            # Check if attrs is Mapping directly - use u.map() for conversion
            if isinstance(attrs, Mapping):
                result = cast(
                    "dict[str, list[str]]",
                    u.map(
                        cast("dict[str, object]", attrs),
                        mapper=lambda _k, v: cast(
                            "list[str]",
                            u.ensure(
                                cast("t.GeneralValueType", v),
                                target_type="str_list",
                                default=[],
                            ),
                        )
                        if FlextRuntime.is_list_like(cast("t.GeneralValueType", v))
                        else [str(v)],
                    ),
                )
                return cast("t.Ldap.AttributeDict", result)
            return {}

        @staticmethod
        def extract_attributes(
            parsed: p.LdapEntry.EntryProtocol | FlextLdifModels.Entry,
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
            parsed: p.LdapEntry.EntryProtocol | FlextLdifModels.Entry,
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
                t.MetadataAttributeValue
                | Mapping[str, str | int | float | bool | None]
                | object
                | None
            ),
        ) -> t.MetadataAttributeValue | None:
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

            # Convert to dict if needed
            metadata_dict: Mapping[str, object] | None = None
            if isinstance(metadata, (dict, Mapping)):
                metadata_dict = dict(metadata)
            elif isinstance(metadata, BaseModel):
                dumped = metadata.model_dump()
                if isinstance(dumped, dict):
                    metadata_dict = dumped
            else:
                return None

            if not metadata_dict:
                return None

            # Filter to ensure all values are valid types for QuirkMetadata
            # Use u.filter() for consistent filtering pattern
            filtered = u.filter(
                metadata_dict,
                predicate=lambda k, v: (
                    isinstance(k, str)
                    and (isinstance(v, (str, int, float, bool)) or v is None)
                ),
            )
            return cast("t.MetadataAttributeValue | None", filtered or None)

        @staticmethod
        def convert_parsed_entries(
            parse_response: FlextLdifModelsResults.ParseResponse,
        ) -> r[list[FlextLdifModels.Entry]]:
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
                - Output: r[list[FlextLdifModels.Entry]] (railway pattern)
                - Delegates to extract_dn(), extract_attributes(), extract_metadata()
                - No network calls - processes pre-fetched LDAP results

            Remote Operation Context:
                - Called after FlextLdifParser.parse_ldap3_results() processes raw LDAP data
                - Search results were already fetched from remote LDAP server
                - This method performs local transformation only

            """
            # Access entries attribute - ParseResponse has entries: list[Entry]
            entries_raw = getattr(parse_response, "entries", [])
            # Use u.empty() mnemonic: check if collection is empty
            if u.empty(entries_raw):
                return u.ok([])

            # Use u.process() for efficient entry conversion
            def convert_entry(entry_raw: object) -> FlextLdifModels.Entry:
                """Convert entry_raw to Entry model."""
                # Already valid Entry instance - use directly
                if isinstance(entry_raw, FlextLdifModels.Entry):
                    return entry_raw

                # Defensive conversion for invalid structures (e.g., from tests or manual construction)
                # Extract DN, attributes, and metadata using helper methods
                # Type narrowing: entry_raw is not Entry, so it might be EntryProtocol or invalid structure
                entry_for_extraction: (
                    p.LdapEntry.EntryProtocol | FlextLdifModels.Entry
                ) = cast("p.LdapEntry.EntryProtocol | FlextLdifModels.Entry", entry_raw)
                dn_obj = Ldap3Adapter.ResultConverter.extract_dn(entry_for_extraction)
                attrs_obj = Ldap3Adapter.ResultConverter.extract_attributes(
                    entry_for_extraction
                )
                metadata_obj = Ldap3Adapter.ResultConverter.extract_metadata(
                    entry_for_extraction
                )

                # Create Entry with extracted objects
                return FlextLdifModels.Entry(
                    dn=dn_obj,
                    attributes=attrs_obj,
                    metadata=metadata_obj,
                )

            # Process all entries using u.process()
            process_result = u.process(
                entries_raw,
                processor=convert_entry,
                on_error="collect",
            )
            # Use u.val() mnemonic: extract entries or return empty list
            entries = cast(
                "list[FlextLdifModels.Entry]",
                u.val(process_result, default=[]),
            )
            return u.ok(entries)

    class OperationExecutor:
        """LDAP operation execution logic (SRP)."""

        def __init__(self, adapter: Ldap3Adapter) -> None:
            """Initialize with adapter instance."""
            self._adapter = adapter

        def execute_add(
            self,
            connection: Connection,
            dn_str: str,
            ldap_attrs: t.Ldap.Attributes,
        ) -> r[m.OperationResult]:
            """Execute LDAP add operation via ldap3 Connection.

            Business Rules:
                - Calls connection.add() with DN and attributes dict
                - LDAP error codes are extracted from connection.result
                - Success returns OperationResult with entries_affected=1
                - Failure returns r.fail() with error message

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
                add_func: t.Ldap.AddCallable = connection.add
                success = add_func(dn_str, None, ldap_attrs)

                # Use u.ok()/u.fail() mnemonic: create results
                if success:
                    return u.ok(
                        m.OperationResult(
                            success=True,
                            operation_type=c.OperationType.ADD,
                            message="Entry added successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Add failed")
            except LDAPException as e:
                error_msg = f"Add failed: {e!s}"
                return u.fail(error_msg)

        def execute_modify(
            self,
            connection: Connection,
            dn: str | p.LdapEntry.DistinguishedNameProtocol,
            changes: t.Ldap.ModifyChanges,
        ) -> r[m.OperationResult]:
            """Execute LDAP modify operation via ldap3 Connection.

            Business Rules:
                - DN is normalized using FlextLdifUtilities.DN.get_dn_value()
                - Calls connection.modify() with DN and changes dict
                - LDAP error codes are extracted from connection.result
                - Success returns OperationResult with entries_affected=1
                - Failure returns r.fail() with error message

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
                modify_func: t.Ldap.ModifyCallable = connection.modify
                success = modify_func(dn_str, changes)

                # Use u.ok()/u.fail() mnemonic: create results
                if success:
                    return u.ok(
                        m.OperationResult(
                            success=True,
                            operation_type=c.OperationType.MODIFY,
                            message="Entry modified successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Modify failed")
            except LDAPException as e:
                error_msg = f"Modify failed: {e!s}"
                return u.fail(error_msg)

        def execute_delete(
            self,
            connection: Connection,
            dn: str | p.LdapEntry.DistinguishedNameProtocol,
        ) -> r[m.OperationResult]:
            """Execute LDAP delete operation via ldap3 Connection.

            Business Rules:
                - DN is normalized using FlextLdifUtilities.DN.get_dn_value()
                - Calls connection.delete() with DN string
                - LDAP error codes are extracted from connection.result
                - Success returns OperationResult with entries_affected=1
                - Failure returns r.fail() with error message

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
                delete_func: t.Ldap.DeleteCallable = connection.delete
                success = delete_func(dn_str)

                # Use u.ok()/u.fail() mnemonic: create results
                if success:
                    return u.ok(
                        m.OperationResult(
                            success=True,
                            operation_type=c.OperationType.DELETE,
                            message="Entry deleted successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Delete failed")
            except LDAPException as e:
                error_msg = f"Delete failed: {e!s}"
                return u.fail(error_msg)

        @staticmethod
        def _extract_error_result(
            connection: Connection,
            prefix: str,
        ) -> r[m.OperationResult]:
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
                - Returns r.fail() with error message

            Args:
                connection: ldap3.Connection with error in connection.result.
                prefix: Error message prefix (e.g., "Add failed").

            Returns:
                r.fail() with extracted error message.

            """
            error_msg = f"{prefix}: LDAP operation returned failure status"
            result_dict = connection.result
            if FlextRuntime.is_dict_like(result_dict):
                # Use u.extract for safer nested access
                description_result: r[str | None] = u.extract(
                    result_dict,
                    "description",
                    default=None,
                )
                # Use u.val() mnemonic: extract value with default
                description: str | None = u.val(description_result, default=None)
                if isinstance(description, str):
                    error_msg = f"{prefix}: {description}"
            return u.fail(error_msg)

    class SearchExecutor:
        """Search operation execution logic (SRP)."""

        @dataclass(frozen=True)
        class SearchParams:
            """Search parameters grouped together to reduce method arguments."""

            base_dn: str
            filter_str: str
            ldap_scope: c.LiteralTypes.Ldap3ScopeLiteral
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
        ) -> r[list[FlextLdifModels.Entry]]:
            """Execute LDAP search and convert results.

            Business Rules:
                - Performs ldap3 Connection.search() with provided parameters
                - Validates LDAP result codes (allows partial success codes)
                - Converts server_type to ServerTypeLiteral using FlextLdifConstants.normalize_server_type()
                - Parses results using FlextLdifParser.parse_ldap3_results()
                - Converts ParseResponse to list[Entry] via ResultConverter
                - LDAPException is caught and converted to r.fail()

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
                r[list[Entry]]: Parsed entries or error if search/parse fails.

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

                # Use u.extract for safer nested access
                result_code_result: r[int | None] = u.extract(
                    connection.result,
                    "result",
                    default=-1,
                )
                result_code: int = (
                    result_code_result.value
                    if result_code_result.is_success
                    and result_code_result.value is not None
                    else -1
                )
                if result_code not in c.LdapResultCodes.PARTIAL_SUCCESS_CODES:
                    error_msg_result: r[str | None] = u.extract(
                        connection.result,
                        "message",
                        default="LDAP search failed",
                    )
                    error_msg: str = (
                        error_msg_result.value
                        if error_msg_result.is_success
                        and error_msg_result.value is not None
                        else "LDAP search failed"
                    )
                    error_desc_result: r[str | None] = u.extract(
                        connection.result,
                        "description",
                        default="unknown",
                    )
                    # DSL pattern: extract value with default (u.val handles None)
                    error_desc: str = cast("str", u.val(error_desc_result, default="unknown"))
                    return u.fail(f"LDAP search failed: {error_desc} - {error_msg}")

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
                    return u.fail(f"Unsupported server type: {server_type_str}")
                parse_result = self._adapter.parser.parse_ldap3_results(
                    ldap3_results,
                    server_type_literal,
                )

                if parse_result.is_failure:
                    return u.fail(u.err(parse_result, default=""))

                return self._adapter.ResultConverter.convert_parsed_entries(
                    parse_result.unwrap(),
                )
            except LDAPException as e:
                return u.fail(f"Search failed: {e!s}")

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
        **kwargs: t.GeneralValueType,
    ) -> None:
        """Initialize adapter service with parser.

        Args:
            **kwargs: Keyword arguments including:
                - parser: Optional FlextLdifParser instance. If None, uses default from FlextLdif.
                - Additional service configuration parameters (delegated to FlextService).

        """
        # Extract parser from kwargs if provided
        # Use u.get() mnemonic: extract from kwargs with default
        parser_raw = u.get(kwargs, "parser")
        # Use u.when() for conditional type check
        parser: FlextLdifParser | None = cast("FlextLdifParser | None", u.when(condition=isinstance(parser_raw, FlextLdifParser), then_value=parser_raw, else_value=None))
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
        config: m.ConnectionConfig,
        **_kwargs: str | float | bool | None,
    ) -> r[bool]:
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
            r[bool] indicating connection success

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

            # Use u.when() mnemonic: conditional result based on bound state
            if not self._connection.bound:
                return u.fail("Failed to bind to LDAP server")

            return u.ok(True)
        except LDAPException as e:
            return u.fail(f"Connection failed: {e!s}")

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

    def _get_connection(self) -> r[Connection]:
        """Get connection with fast fail if not available."""
        # Use u.when() mnemonic: conditional result based on connection state
        if not self.is_connected or self._connection is None:
            return u.fail(c.ErrorStrings.NOT_CONNECTED)
        return u.ok(self._connection)

    @staticmethod
    def _map_scope(
        scope: c.SearchScope | str,
    ) -> r[c.LiteralTypes.Ldap3ScopeLiteral]:
        """Map scope string to ldap3 scope constant.

        Uses direct StrEnum value mapping for type-safe conversion.
        """
        # Normalize to StrEnum if string provided
        # Type narrowing: scope is str | SearchScope
        # SearchScope is a StrEnum (subclass of str), so check for SearchScope first
        if isinstance(scope, c.SearchScope):
            # Type narrowing: scope is SearchScope
            scope_enum = scope
        else:
            # Type narrowing: scope is str (SearchScope is also str, but already handled above)
            # Convert string to SearchScope enum
            try:
                # Use u.normalize for consistent case handling
                normalized_scope = u.normalize(scope, case="upper")
                # Type narrowing: normalize with single str returns str
                scope_str = (
                    cast("str", normalized_scope)
                    if isinstance(normalized_scope, str)
                    else str(scope)
                )
                scope_enum = c.SearchScope(scope_str)
            except ValueError:
                return u.fail(f"Invalid LDAP scope: {scope}")

        # Direct mapping using StrEnum values with proper type narrowing
        ldap3_scope_mapping: Mapping[
            c.SearchScope,
            c.LiteralTypes.Ldap3ScopeLiteral,
        ] = {
            c.SearchScope.BASE: "BASE",
            c.SearchScope.ONELEVEL: "LEVEL",
            c.SearchScope.SUBTREE: "SUBTREE",
        }

        # Use u.ok()/u.fail() mnemonic: create results
        if scope_enum in ldap3_scope_mapping:
            ldap3_value = ldap3_scope_mapping[scope_enum]
            return u.ok(ldap3_value)

        return u.fail(f"Invalid LDAP scope: {scope}")

    def search(
        self,
        search_options: m.SearchOptions,
        server_type: FlextLdifConstants.ServerTypes
        | str = FlextLdifConstants.ServerTypes.RFC,
        **_kwargs: str | float | bool | None,
    ) -> r[m.SearchResult]:
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
            return u.fail(u.err(connection_result, default=""))

        # Convert scope to str or SearchScope for _map_scope
        # SearchOptions.scope is str, but may need conversion to SearchScope enum
        # Type narrowing: scope is str from SearchOptions model
        scope_for_mapping: str | c.SearchScope = search_options.scope
        scope_result = Ldap3Adapter._map_scope(scope_for_mapping)
        if scope_result.is_failure:
            return u.fail(u.err(scope_result, default=""))

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
            return u.fail(u.err(entries_result, default=""))

        return u.ok(
            m.SearchResult(
                entries=entries_result.unwrap(),
                search_options=search_options,
            ),
        )

    def add(
        self,
        entry: FlextLdifModels.Entry,
        **_kwargs: str | float | bool | None,
    ) -> r[m.OperationResult]:
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
            return u.fail(u.err(connection_result, default=""))

        attrs_result = self._entry_adapter.ldif_entry_to_ldap3_attributes(entry)
        if attrs_result.is_failure:
            return u.fail(f"Failed to convert entry attributes: {u.err(attrs_result, default='')}")

        # Extract DN value using FlextLdifUtilities.DN.get_dn_value() - handles all DN types
        # DSL pattern: use when for conditional default
        dn_str = cast(
            "str",
            u.when(
                condition=entry.dn is not None,
                then_value=FlextLdifUtilities.DN.get_dn_value(entry.dn) if entry.dn else None,
                else_value="unknown",
            ) or "unknown",
        )
        return self.OperationExecutor(self).execute_add(
            connection_result.unwrap(),
            dn_str,
            attrs_result.unwrap(),
        )

    def modify(
        self,
        dn: str | p.LdapEntry.DistinguishedNameProtocol,
        changes: t.Ldap.ModifyChanges,
        **_kwargs: str | float | bool | None,
    ) -> r[m.OperationResult]:
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
            return u.fail(u.err(connection_result, default=""))
        return self.OperationExecutor(self).execute_modify(
            connection_result.unwrap(),
            dn,  # Type: str | DistinguishedNameProtocol (runtime validated)
            changes,
        )

    def delete(
        self,
        dn: str | p.LdapEntry.DistinguishedNameProtocol,
        **_kwargs: str | float | bool | None,
    ) -> r[m.OperationResult]:
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
            return u.fail(u.err(connection_result, default=""))
        return self.OperationExecutor(self).execute_delete(
            connection_result.unwrap(),
            dn,
        )

    def execute(self, **_kwargs: str | float | bool | None) -> r[bool]:
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
            r[bool]: Success if connected, failure with NOT_CONNECTED if not.

        """
        # Use u.ok()/u.fail() mnemonic: create results
        if not self.is_connected:
            return u.fail(c.ErrorStrings.NOT_CONNECTED)
        return u.ok(True)
