"""LDAP3 adapter service - Infrastructure wrapper for ldap3 library.

This module encapsulates all ldap3 library interactions, providing a clean
interface for the flext-ldap service layer. Only this adapter imports ldap3
directly; all other modules work with protocol abstractions.

Business Rules:
    - ldap3 library is ONLY imported here (zero tolerance for direct imports elsewhere)
    - Connection binding uses ldap3.Connection with auto_bind and auto_range options
    - STARTTLS is handled separately from SSL (mutual exclusion enforced in config)
    - Search results are converted to LdifEntry via FlextLdifParser
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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, TypeGuard

from flext_core import FlextRuntime, r
from flext_ldif import (
    FlextLdif,
    FlextLdifParser,
    FlextLdifUtilities,
)
from flext_ldif.models import FlextLdifModels
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPException
from pydantic import BaseModel, ConfigDict

from flext_ldap.adapters.entry import FlextLdapEntryAdapter
from flext_ldap.base import s
from flext_ldap.constants import FlextLdapConstants, c
from flext_ldap.models import HasItemsMethod, m
from flext_ldap.protocols import p
from flext_ldap.typings import t
from flext_ldap.utilities import u

# Local alias for cleaner code
LdifEntry = FlextLdifModels.Ldif.Entry

# Protocol references from centralized protocols.py for backward compatibility
HasDynamicAttribute = p.Ldap.HasDynamicAttribute
HasAttributesProperty = p.Ldap.HasAttributesProperty


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
        def create_server(config: m.Ldap.ConnectionConfig) -> Server:
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
            config: m.Ldap.ConnectionConfig,
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
            config: m.Ldap.ConnectionConfig,
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
                return r[bool].ok(True)

            try:
                if not connection.start_tls():
                    return r[bool].fail("Failed to start TLS")
                return r[bool].ok(True)
            except LDAPException as tls_error:
                error_msg = f"Failed to start TLS: {tls_error}"
                return r[bool].fail(error_msg)

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
                - Python 3.13: Uses isinstance(..., Sequence) for type-safe value handling
                - Returns list[tuple[str, dict[str, list[str]]]] for parser compatibility
                - No network calls - processes connection.entries

            Args:
                connection: Active ldap3.Connection with search results in connection.entries.

            Returns:
                List of (dn, attributes_dict) tuples in parser format.

            """
            # Process entries efficiently
            results: list[tuple[str, dict[str, list[str]]]] = []
            for entry in connection.entries:
                # Type narrowing: entry is ldap3.Entry with dynamic attributes
                # Use Protocol for type-safe attribute access
                if not hasattr(entry, "entry_dn"):
                    # Fallback for non-protocol entries
                    dn = str(entry) if entry else ""
                    results.append((dn, {}))
                    continue

                dn_raw = entry.entry_dn
                dn = str(dn_raw) if dn_raw is not None else ""

                # Process attributes
                entry_attrs = entry.entry_attributes
                attrs_dict = Ldap3Adapter.ResultConverter.process_entry_attributes(
                    entry,
                    entry_attrs,
                )
                results.append((dn, attrs_dict))
            return results

        @staticmethod
        def has_dynamic_attribute(
            obj: t.GeneralValueType | p.Ldap.Ldap3EntryProtocol | LdifEntry,
            attr_name: str,
        ) -> TypeGuard[HasDynamicAttribute]:
            """Type guard for dynamic attribute access.

            Args:
                obj: Object to check
                attr_name: Attribute name to check

            Returns:
                True if object has the attribute

            """
            return hasattr(obj, attr_name)

        @staticmethod
        def get_dynamic_attribute(
            obj: t.GeneralValueType | p.Ldap.Ldap3EntryProtocol | LdifEntry,
            attr_name: str,
        ) -> t.GeneralValueType | None:
            """Get dynamic attribute with type safety.

            Args:
                obj: Object to access
                attr_name: Attribute name

            Returns:
                Attribute value or None

            """
            # Python 3.13: Use getattr() built-in for dynamic attributes after type narrowing
            if not Ldap3Adapter.ResultConverter.has_dynamic_attribute(obj, attr_name):
                return None
            # Type narrowing: TypeGuard ensures obj is HasDynamicAttribute
            # Protocol guarantees dynamic attributes exist - use getattr() for dynamic access
            # Note: getattr() is required here as attributes are dynamic (ldap3 library pattern)
            dynamic_obj: HasDynamicAttribute = obj
            return getattr(dynamic_obj, attr_name, None)

        @staticmethod
        def process_entry_attributes(
            entry: p.Ldap.Ldap3EntryProtocol,
            entry_attrs: Sequence[str],
        ) -> dict[str, list[str]]:
            """Process entry attributes into dict[str, list[str]].

            Args:
                entry: LDAP entry with dynamic attributes
                entry_attrs: List of attribute names to process

            Returns:
                Dictionary mapping attribute names to list of string values

            """
            attrs_dict: dict[str, list[str]] = {}
            for attr in entry_attrs:
                # Access dynamic attribute - ldap3.Entry has dynamic attributes
                # entry is runtime-validated as Ldap3EntryProtocol - protocol is structurally compatible
                attr_obj = Ldap3Adapter.ResultConverter.get_dynamic_attribute(
                    entry,
                    attr,
                )
                if attr_obj is None:
                    continue

                # Use getattr() to safely access attributes on object type
                attr_values = getattr(attr_obj, "values", None)
                if attr_values is not None:
                    # Protocol guarantees values is Sequence[object], which is iterable
                    # No isinstance check needed - Sequence is directly iterable
                    attrs_dict[attr] = [str(v) for v in attr_values]
                else:
                    # Fallback for non-protocol attributes
                    attrs_dict[attr] = [str(attr_obj)]
            return attrs_dict

        @staticmethod
        def extract_dn(
            parsed: LdifEntry | t.GeneralValueType,
        ) -> m.Ldif.DN:
            """Extract Distinguished Name from LDAP entry.

            Business Rules:
                - Extracts DN from LdifEntry instances directly
                - Handles protocol-based entries via hasattr() checks
                - Uses FlextLdifUtilities.Ldif.DN.get_dn_value() for normalization
                - Returns empty DN("") when extraction fails (no exception)
                - DN normalization ensures consistent format across server types

            Audit Implications:
                - DN extraction is critical for LDAP operations targeting specific entries
                - Empty DN ("") returned when extraction fails - caller must validate
                - Uses m.Ldif.DN for type-safe DN handling
                - Remote LDAP operations depend on correct DN for targeting entries

            Architecture:
                - Delegates to FlextLdifUtilities.Ldif.DN.get_dn_value() for normalization
                - Returns m.Ldif.DN (Pydantic model)
                - No network calls - pure data extraction from local objects

            Args:
                parsed: Entry from LDAP search or protocol-based entry structure.

            Returns:
                DN instance with extracted or empty value.

            """
            # Direct access for LdifEntry
            if isinstance(parsed, LdifEntry):
                if parsed.dn is not None:
                    # parsed.dn may be internal type, always convert to public API type
                    # Use model_validate to ensure public API type
                    return m.Ldif.DN.model_validate(parsed.dn.model_dump())
                return m.Ldif.DN.model_validate({"value": ""})

            # Protocol-based entry - extract DN value using utilities
            dn_raw: t.GeneralValueType | None = None
            if isinstance(parsed, LdifEntry):
                dn_raw = parsed.dn
            else:
                # Use getattr() for safe access to attributes on object type
                dn_raw = getattr(parsed, "entry_dn", None)
                if dn_raw is None:
                    # Fallback: try dynamic attribute access for unknown types
                    dn_raw = Ldap3Adapter.ResultConverter.get_dynamic_attribute(
                        parsed,
                        "dn",
                    )
                    if dn_raw is None:
                        return m.Ldif.DN.model_validate({"value": ""})

            if dn_raw is None:
                return m.Ldif.DN.model_validate({"value": ""})

            # Check if already DN instance - use m.Ldif.DN (public API)
            if isinstance(dn_raw, m.Ldif.DN):
                return dn_raw
            # Check if it has value attribute (duck typing for DN-like objects)
            if isinstance(dn_raw, m.Ldif.DN):
                # Convert to m.Ldif.DN (public API)
                return m.Ldif.DN.model_validate({"value": dn_raw.value})

            # Use FlextLdifUtilities.Ldif.DN for conversion
            dn_value = FlextLdifUtilities.Ldif.DN.get_dn_value(dn_raw)
            return m.Ldif.DN.model_validate({"value": dn_value})

        @staticmethod
        def normalize_attr_values(
            attrs_dict: dict[str, str] | Mapping[str, t.GeneralValueType] | Mapping[str, object],
        ) -> t.Ldap.Operation.AttributeDict:
            """Normalize attribute values to list[str] format.

            Args:
                attrs_dict: Dictionary or Mapping with attribute values

            Returns:
                Normalized dict[str, list[str]]

            """
            result: dict[str, list[str]] = {}
            # Python 3.13: Use modern comprehension with type narrowing
            for k, v in attrs_dict.items():
                # isinstance needed for Sequence type narrowing (TypeGuard limitation)
                result[k] = (
                    [str(item) for item in v if item is not None]
                    if isinstance(v, Sequence)
                    else ([str(v)] if v is not None else [])
                )
            return result

        @staticmethod
        def extract_attrs_dict(
            attrs: (
                HasAttributesProperty
                | Mapping[str, t.GeneralValueType | Sequence[str]]
                | HasItemsMethod
                | m.Ldif.Attributes
                | BaseModel
            ),
        ) -> t.Ldap.Operation.AttributeDict:
            """Extract LDAP attributes as dictionary from various input formats.

            Business Rules:
                - Handles objects with 'attributes' property (ldap3 Entry, Pydantic models)
                - Handles Pydantic BaseModel via model_dump() for safe serialization
                - Handles Mapping types (dict, dict-like objects) directly
                - All attribute values normalized to list[str] format
                - Empty dict {} returned on extraction failure (no exception raised)
                - Python 3.13: Uses isinstance(..., Sequence) for type-safe value handling

            Audit Implications:
                - Attribute extraction affects data written to/read from LDAP directory
                - All values converted to strings - numeric/boolean type info may be lost
                - Empty dict {} returned on extraction failure - no exception raised
                - Uses Pydantic's model_dump() for safe model serialization

            Architecture:
                - Handles: objects with 'attributes' property, Pydantic BaseModel, Mapping
                - Returns t.Ldap.Operation.AttributeDict (dict[str, list[str]])
                - No network calls - pure data transformation

            """
            # Extract attributes property with Protocol check
            # Use isinstance with Protocol for type narrowing
            if isinstance(attrs, HasAttributesProperty):
                # Type narrowing: isinstance ensures attrs has "attributes" property
                attrs_attr = attrs.attributes
                # Protocol ensures correct types - no cast needed
                return Ldap3Adapter.ResultConverter.normalize_attr_values(
                    attrs_attr
                )

            # Check for Pydantic model with model_dump method
            if isinstance(attrs, BaseModel):
                # Python 3.13: model_dump() always returns dict - direct access
                dumped = attrs.model_dump()
                # u.mapper().get() with default={} - extract and narrow type
                attrs_value_raw = u.mapper().get(
                    dumped,
                    "attributes",
                    default={},
                )
                attrs_value: dict[str, t.GeneralValueType] | None = (
                    attrs_value_raw if isinstance(attrs_value_raw, dict) else None
                )
                # Type narrowing: ensure dict before passing
                if isinstance(attrs_value, dict):
                    return Ldap3Adapter.ResultConverter.normalize_attr_values(
                        attrs_value,
                    )
                return {}

            # Python 3.13: Use isinstance for Mapping type narrowing
            if isinstance(attrs, Mapping):
                return Ldap3Adapter.ResultConverter.normalize_attr_values(attrs)
            return {}

        @staticmethod
        def extract_attributes(
            parsed: LdifEntry | t.GeneralValueType,
        ) -> m.Ldif.Attributes:
            """Extract LDAP attributes as m.Ldif.Attributes.

            Business Rules:
                - Extracts attributes from LdifEntry or protocol entries
                - Delegates to extract_attrs_dict() for raw dict extraction
                - Wraps result in m.Ldif.Attributes Pydantic model
                - Empty attributes {} returned when extraction fails (not an error)
                - Pydantic validation ensures attribute structure correctness

            Audit Implications:
                - Attributes model validates attribute structure via Pydantic
                - Empty attributes {} returned when extraction fails - not an error
                - Attribute names and values preserved exactly as received from LDAP
                - Used by search operations to return structured entry data

            Architecture:
                - Delegates to extract_attrs_dict() for raw dict extraction
                - Returns m.Ldif.Attributes (validated Pydantic model)
                - No network calls - pure data transformation

            """
            # Get attributes from entry
            attrs_raw: t.GeneralValueType | None = None
            if isinstance(parsed, (LdifEntry, LdifEntry)):
                attrs_raw = parsed.attributes
            else:
                # Fallback: try dynamic attribute access for unknown types
                # Note: ldap3.Entry uses entry_attributes (Sequence[str]), not attributes
                # So we need to use get_dynamic_attribute for compatibility
                attrs_raw = Ldap3Adapter.ResultConverter.get_dynamic_attribute(
                    parsed,
                    "attributes",
                )

            # Handle None case
            if attrs_raw is None:
                return m.Ldif.Attributes.model_validate({"attributes": {}})

            # Already correct type
            if isinstance(attrs_raw, m.Ldif.Attributes):
                return attrs_raw

            # Extract attributes dict and create new instance
            # Type narrowing: check if attrs_raw is compatible with extract_attrs_dict types
            if isinstance(
                attrs_raw,
                (
                    HasAttributesProperty,
                    m.Ldif.Attributes,
                    BaseModel,
                    Mapping,
                ),
            ):
                attrs_dict = Ldap3Adapter.ResultConverter.extract_attrs_dict(attrs_raw)
            else:
                attrs_dict = {}
            return m.Ldif.Attributes.model_validate({"attributes": attrs_dict})

        @staticmethod
        def extract_metadata(
            parsed: LdifEntry | t.GeneralValueType,
        ) -> m.Ldif.QuirkMetadata | None:
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
                - Returns m.Ldif.QuirkMetadata (Pydantic model) or None
                - No network calls - pure data extraction

            Returns:
                QuirkMetadata instance or None if no metadata available.

            """
            # Extract metadata using protocol check
            metadata_raw: t.GeneralValueType | None = None
            if isinstance(parsed, LdifEntry):
                metadata_raw = parsed.metadata
            else:
                # Fallback: try dynamic attribute access for unknown types
                # get_dynamic_attribute handles type conversion internally
                metadata_raw = Ldap3Adapter.ResultConverter.get_dynamic_attribute(
                    parsed,
                    "metadata",
                )
                if metadata_raw is None:
                    return None
            if not metadata_raw:
                return None

            # Already QuirkMetadata instance - use directly
            if isinstance(metadata_raw, m.Ldif.QuirkMetadata):
                return metadata_raw

            # Normalize metadata using normalize_metadata() - handles all filtering and conversion
            normalized = Ldap3Adapter.ResultConverter.normalize_metadata(metadata_raw)
            if normalized:
                return m.Ldif.QuirkMetadata.model_validate(normalized)
            return None

        @staticmethod
        def normalize_metadata(
            metadata: (
                t.MetadataAttributeValue
                | Mapping[str, str | int | float | bool | None]
                | t.GeneralValueType
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

            # Python 3.13: Use match-case for modern pattern matching
            metadata_dict: Mapping[str, t.GeneralValueType] | None = None
            match metadata:
                case dict() | Mapping():
                    metadata_dict = dict(metadata)
                case BaseModel():
                    # model_dump() always returns dict - direct access
                    metadata_dict = metadata.model_dump()
                case _:
                    return None

            if not metadata_dict:
                return None

            # Python 3.13: Filter with type narrowing - metadata_dict is Mapping[str, object]
            # Note: MetadataAttributeValue dict variant includes datetime and list types
            # but we filter to basic scalar types for QuirkMetadata compatibility
            filtered: dict[
                str,
                str
                | int
                | float
                | bool
                | datetime
                | list[str | int | float | bool | datetime | None]
                | None,
            ] = {
                k: v
                for k, v in metadata_dict.items()
                if isinstance(k, str)
                and isinstance(v, (str, int, float, bool, type(None)))
            }
            return filtered or None

        @staticmethod
        def convert_parsed_entries(
            parse_response: t.GeneralValueType,
        ) -> r[list[LdifEntry]]:
            """Convert ParseResponse from FlextLdifParser to list of Entry models.

            Business Rules:
                - Transforms ParseResponse from FlextLdifParser into validated Entry list
                - Handles properly typed entries from parser (direct conversion)
                - Defensively converts invalid structures for edge cases (tests, manual)
                - Empty list returned when parse_response has no entries
                - All entries validated as LdifEntry instances
                - Delegates to extract_dn(), extract_attributes(), extract_metadata()

            Audit Implications:
                - This is the main entry point for LDAP search result processing
                - All entries returned are validated LdifEntry instances
                - Defensive conversion handles edge cases (tests, manual construction)
                - Empty list returned when parse_response has no entries
                - Uses FlextResult pattern for consistent error handling

            Architecture:
                - Input: m.Ldif.ParseResponse from FlextLdifParser
                - Output: r[list[LdifEntry]] (railway pattern)
                - Delegates to extract_dn(), extract_attributes(), extract_metadata()
                - No network calls - processes pre-fetched LDAP results

            Remote Operation Context:
                - Called after FlextLdifParser.parse_ldap3_results() processes raw LDAP data
                - Search results were already fetched from remote LDAP server
                - This method performs local transformation only

            """
            # Access entries attribute - ParseResponse has entries: list[Entry]
            # Defensive access using hasattr for type narrowing
            entries_raw = (
                getattr(parse_response, "entries", None)
                if hasattr(parse_response, "entries")
                else None
            )
            if not entries_raw:
                return r[list[LdifEntry]].ok([])

            # Convert entries efficiently
            entries: list[LdifEntry] = []
            for entry_raw in entries_raw:
                # Already valid Entry instance - use directly
                # Handle LdifEntry and LdapEntryProtocol instances
                if isinstance(entry_raw, LdifEntry):
                    entries.append(entry_raw)
                    continue

                # Defensive conversion for invalid structures (e.g., from tests or manual construction)
                entry_for_extraction: LdifEntry | None = None
                # Only accept LdifEntry instances for direct processing
                # Other types must be validated and converted in service layer
                if hasattr(entry_raw, "entry_dn"):
                    # ldap3.Entry - convert to EntryProtocol-compatible structure
                    # This requires extracting entry_dn and building attributes dict
                    # For now, skip - ldap3 entries should be converted via ldap3_to_ldif_entry first
                    entry_for_extraction = None
                else:
                    # Unknown type - cannot extract safely without Protocol
                    entry_type = type(entry_raw)
                    error_msg = (
                        f"Entry must be EntryProtocol or LdifEntry, got {entry_type}"
                    )
                    raise TypeError(error_msg)

                if entry_for_extraction is None:
                    continue
                dn_obj = Ldap3Adapter.ResultConverter.extract_dn(entry_for_extraction)
                attrs_obj = Ldap3Adapter.ResultConverter.extract_attributes(
                    entry_for_extraction,
                )
                metadata_obj = Ldap3Adapter.ResultConverter.extract_metadata(
                    entry_for_extraction,
                )
                entry = LdifEntry.model_validate({
                    "dn": dn_obj,
                    "attributes": attrs_obj,
                    "metadata": metadata_obj,
                })
                entries.append(entry)
                continue

            return r[list[LdifEntry]].ok(entries)

    class OperationExecutor:
        """LDAP operation execution logic (SRP)."""

        def __init__(self, adapter: Ldap3Adapter) -> None:
            """Initialize with adapter instance."""
            self._adapter = adapter

        def execute_add(
            self,
            connection: Connection,
            dn_str: str,
            ldap_attrs: t.Ldap.Operation.Attributes,
        ) -> r[m.Ldap.OperationResult]:
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
                # Call connection.add directly - ldap3 is untyped
                # Convert Attributes (Mapping[str, Sequence[str]]) to dict for ldap3
                # LDAP attributes are multi-valued, so values are lists
                attrs_dict: dict[str, list[str]] = {
                    k: list(v) for k, v in ldap_attrs.items()
                }

                # Use wrapper method for type safety
                if self._add_entry_to_ldap(connection, dn_str, attrs_dict):
                    return r[m.Ldap.OperationResult].ok(
                        m.Ldap.OperationResult(
                            success=True,
                            operation_type=c.Ldap.OperationType.ADD,
                            message="Entry added successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Add failed")
            except LDAPException as e:
                error_msg = f"Add failed: {e!s}"
                return r[m.Ldap.OperationResult].fail(error_msg)

        def execute_modify(
            self,
            connection: Connection,
            dn: str | m.Ldif.DN,
            changes: t.Ldap.Operation.Changes,
        ) -> r[m.Ldap.OperationResult]:
            """Execute LDAP modify operation via ldap3 Connection.

            Business Rules:
                - DN is normalized using FlextLdifUtilities.Ldif.DN.get_dn_value()
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
                dn: Distinguished name (string or DN model)
                changes: Modification changes dict in ldap3 format

            Returns:
                FlextResult containing OperationResult with success status

            """
            try:
                dn_str = u.Ldif.DN.get_dn_value(dn)
                # Use wrapper method for type safety
                if self._modify_entry_in_ldap(connection, dn_str, changes):
                    return r[m.Ldap.OperationResult].ok(
                        m.Ldap.OperationResult(
                            success=True,
                            operation_type=c.Ldap.OperationType.MODIFY,
                            message="Entry modified successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Modify failed")
            except LDAPException as e:
                error_msg = f"Modify failed: {e!s}"
                return r[m.Ldap.OperationResult].fail(error_msg)

        def execute_delete(
            self,
            connection: Connection,
            dn: str | m.Ldif.DN,
        ) -> r[m.Ldap.OperationResult]:
            """Execute LDAP delete operation via ldap3 Connection.

            Business Rules:
                - DN is normalized using FlextLdifUtilities.Ldif.DN.get_dn_value()
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
                dn: Distinguished name (string or DN model)

            Returns:
                FlextResult containing OperationResult with success status

            """
            try:
                dn_str = u.Ldif.DN.get_dn_value(dn)
                # Use wrapper method for type safety
                if self._delete_entry_from_ldap(connection, dn_str):
                    return r[m.Ldap.OperationResult].ok(
                        m.Ldap.OperationResult(
                            success=True,
                            operation_type=c.Ldap.OperationType.DELETE,
                            message="Entry deleted successfully",
                            entries_affected=1,
                        ),
                    )

                return self._extract_error_result(connection, "Delete failed")
            except LDAPException as e:
                error_msg = f"Delete failed: {e!s}"
                return r[m.Ldap.OperationResult].fail(error_msg)

        @staticmethod
        def _add_entry_to_ldap(
            connection: Connection,
            dn_str: str,
            attrs_dict: dict[str, list[str]],
        ) -> bool:
            """Add entry to LDAP directory.

            This typed wrapper handles the untyped ldap3 add() call.

            Args:
                connection: Active ldap3 Connection object.
                dn_str: Distinguished name string.
                attrs_dict: Attributes dictionary (str -> list[str]).

            Returns:
                True if add succeeded, False otherwise.

            """
            return connection.add(dn_str, None, attrs_dict)

        @staticmethod
        def _modify_entry_in_ldap(
            connection: Connection,
            dn_str: str,
            changes: dict[str, tuple[str, list[str]]],
        ) -> bool:
            """Modify entry in LDAP directory.

            This typed wrapper handles the untyped ldap3 modify() call.

            Args:
                connection: Active ldap3 Connection object.
                dn_str: Distinguished name string.
                changes: Modification changes dict in ldap3 format.

            Returns:
                True if modify succeeded, False otherwise.

            """
            return connection.modify(dn_str, changes)

        @staticmethod
        def _delete_entry_from_ldap(
            connection: Connection,
            dn_str: str,
        ) -> bool:
            """Delete entry from LDAP directory.

            This typed wrapper handles the untyped ldap3 delete() call.

            Args:
                connection: Active ldap3 Connection object.
                dn_str: Distinguished name string.

            Returns:
                True if delete succeeded, False otherwise.

            """
            return connection.delete(dn_str)

        @staticmethod
        def _extract_error_result(
            connection: Connection,
            prefix: str,
        ) -> r[m.Ldap.OperationResult]:
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
                # Extract description from result dict
                description = u.mapper().get(result_dict, "description")
                if isinstance(description, str):
                    error_msg = f"{prefix}: {description}"
            return r[m.Ldap.OperationResult].fail(error_msg)

    class SearchExecutor:
        """Search operation execution logic (SRP)."""

        @dataclass(frozen=True)
        class SearchParams:
            """Search parameters grouped together to reduce method arguments."""

            base_dn: str
            filter_str: str
            ldap_scope: Literal[
                "BASE",
                "LEVEL",
                "SUBTREE",
            ]  # c.Ldap.LiteralTypes.Ldap3ScopeLiteral
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
            server_type: FlextLdapConstants.Ldif.ServerTypes | str,
        ) -> r[list[LdifEntry]]:
            """Execute LDAP search and convert results.

            Business Rules:
                - Performs ldap3 Connection.search() with provided parameters
                - Validates LDAP result codes (allows partial success codes)
                - Converts server_type to ServerTypeLiteral (validated via c.Ldap.LiteralTypes.LdapServerTypeLiteral)
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

                # Extract result code from connection result
                result_code = u.mapper().get(connection.result, "result", default=-1)
                if result_code not in c.Ldap.LdapResultCodes.PARTIAL_SUCCESS_CODES:
                    error_msg = u.mapper().get(
                        connection.result,
                        "message",
                        default="LDAP search failed",
                    )
                    error_desc = u.mapper().get(
                        connection.result,
                        "description",
                        default="unknown",
                    )
                    return r[list[LdifEntry]].fail(
                        f"LDAP search failed: {error_desc} - {error_msg}",
                    )

                ldap3_results = self._adapter.ResultConverter.convert_ldap3_results(
                    connection,
                )
                # Convert server_type to ServerTypeLiteral for parser
                # Convert server_type to string for parser
                if isinstance(server_type, FlextLdapConstants.Ldif.ServerTypes):
                    server_type_enum: FlextLdapConstants.Ldif.ServerTypes = server_type
                    server_type_str = server_type_enum.value
                else:
                    server_type_str = str(server_type)
                # Validate server_type_str is a valid LdapServerTypeLiteral
                # Type narrowing: server_type_str is validated to be LdapServerTypeLiteral
                valid_server_types = {
                    FlextLdapConstants.Ldif.ServerTypes.RFC,
                    FlextLdapConstants.Ldif.ServerTypes.OID,
                    FlextLdapConstants.Ldif.ServerTypes.OUD,
                    FlextLdapConstants.Ldif.ServerTypes.OPENLDAP,
                    FlextLdapConstants.Ldif.ServerTypes.OPENLDAP1,
                    FlextLdapConstants.Ldif.ServerTypes.APACHE,
                    FlextLdapConstants.Ldif.ServerTypes.DS389,
                    FlextLdapConstants.Ldif.ServerTypes.NOVELL,
                    FlextLdapConstants.Ldif.ServerTypes.IBM_TIVOLI,
                    FlextLdapConstants.Ldif.ServerTypes.AD,
                    FlextLdapConstants.Ldif.ServerTypes.RELAXED,
                }
                if server_type_str not in valid_server_types:
                    return r[list[LdifEntry]].fail(
                        f"Unsupported server type: {server_type_str}",
                    )
                # Type narrowing: server_type_str is now validated as LdapServerTypeLiteral
                # Parser expects c.Ldif.LiteralTypes.ServerTypeLiteral | None
                # After validation, server_type_str is a valid server type string
                # Pass None to use default server type detection in parser
                parse_result = self._adapter.parser.parse_ldap3_results(
                    ldap3_results,
                    None,  # Let parser detect server type automatically
                )

                if parse_result.is_failure:
                    error_msg = str(parse_result.error) if parse_result.error else ""
                    return r[list[LdifEntry]].fail(error_msg)

                # Use parse_response directly - m.Ldif.ParseResponse is the public API
                parse_response = parse_result.value
                return self._adapter.ResultConverter.convert_parsed_entries(
                    parse_response,
                )
            except LDAPException as e:
                return r[list[LdifEntry]].fail(f"Search failed: {e!s}")

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
        parser: FlextLdifParser | None = None,
    ) -> None:
        """Initialize adapter service with parser.

        Args:
            parser: Optional FlextLdifParser instance. If None, uses default from FlextLdif.

        """
        # Python 3.13: Modern comprehension with type narrowing
        # Removed unused service_kwargs filtering - super().__init__() doesn't need config kwargs
        # Type narrowing was: service_kwargs is dict[str, str | float | bool | None]
        # which matches FlextService.__init__ signature
        # Protocols are structurally compatible - no type ignore needed
        super().__init__()
        # Use default parser if not provided
        if parser is None:
            parser = FlextLdif().parser
        self._connection = None
        self._server = None
        self._parser = parser
        # Create adapter instance directly
        self._entry_adapter = FlextLdapEntryAdapter()

    def connect(
        self,
        config: m.Ldap.ConnectionConfig,
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

            # Check bound state - connection is guaranteed to be non-None after create_connection
            if self._connection is None or not self._connection.bound:
                return r[bool].fail("Failed to bind to LDAP server")

            return r[bool].ok(True)
        except LDAPException as e:
            return r[bool].fail(f"Connection failed: {e!s}")

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
        if self._connection is not None:
            try:
                self._unbind_connection()
            except (LDAPException, OSError) as e:
                self.logger.debug("Error during disconnect", error=str(e))
            finally:
                self._connection = None
                self._server = None

    def _unbind_connection(self) -> None:
        """Unbind and close LDAP connection.

        This typed wrapper handles the untyped ldap3 unbind() call.
        """
        if self._connection is not None:
            self._connection.unbind()

    @property
    def connection(self) -> Connection | None:
        """Get underlying ldap3 Connection object."""
        return self._connection

    @property
    def is_connected(self) -> bool:
        """Check if adapter has an active connection."""
        if self._connection is None:
            return False
        return bool(self._connection.bound)

    def _get_connection(self) -> r[Connection]:
        """Get connection with fast fail if not available."""
        # Check connection state
        if not self.is_connected or self._connection is None:
            return r[Connection].fail(c.Ldap.ErrorStrings.NOT_CONNECTED)
        return r[Connection].ok(self._connection)

    @staticmethod
    def _map_scope(
        scope: FlextLdapConstants.Ldap.SearchScope | str,
    ) -> r[
        Literal["BASE", "LEVEL", "SUBTREE"]
    ]:  # c.Ldap.LiteralTypes.Ldap3ScopeLiteral
        """Map scope string to ldap3 scope constant.

        Uses direct StrEnum value mapping for type-safe conversion.
        """
        # Python 3.13: Use match-case for modern pattern matching
        match scope:
            case FlextLdapConstants.Ldap.SearchScope():
                scope_enum = scope
            case str():
                try:
                    scope_enum = FlextLdapConstants.Ldap.SearchScope(scope.upper())
                except ValueError:
                    return r[Literal["BASE", "LEVEL", "SUBTREE"]].fail(
                        f"Invalid LDAP scope: {scope}",
                    )
            case _:
                try:
                    scope_enum = FlextLdapConstants.Ldap.SearchScope(str(scope).upper())
                except ValueError:
                    return r[Literal["BASE", "LEVEL", "SUBTREE"]].fail(
                        f"Invalid LDAP scope: {scope}",
                    )

        # Python 3.13: Direct mapping using StrEnum values
        ldap3_scope_mapping: Mapping[
            FlextLdapConstants.Ldap.SearchScope,
            Literal[
                "BASE",
                "LEVEL",
                "SUBTREE",
            ],  # c.Ldap.LiteralTypes.Ldap3ScopeLiteral
        ] = {
            FlextLdapConstants.Ldap.SearchScope.BASE: "BASE",
            FlextLdapConstants.Ldap.SearchScope.ONELEVEL: "LEVEL",
            FlextLdapConstants.Ldap.SearchScope.SUBTREE: "SUBTREE",
        }

        # Create results
        if scope_enum in ldap3_scope_mapping:
            ldap3_value = ldap3_scope_mapping[scope_enum]
            return r[Literal["BASE", "LEVEL", "SUBTREE"]].ok(ldap3_value)

        return r[Literal["BASE", "LEVEL", "SUBTREE"]].fail(
            f"Invalid LDAP scope: {scope}",
        )

    def search(
        self,
        search_options: m.Ldap.SearchOptions,
        server_type: FlextLdapConstants.Ldif.ServerTypes
        | str = FlextLdapConstants.Ldif.ServerTypes.RFC,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.SearchResult]:
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
            error_msg = str(connection_result.error) if connection_result.error else ""
            return r[m.Ldap.SearchResult].fail(error_msg)

        # Convert scope to str or SearchScope for _map_scope
        # SearchOptions.scope is str, but may need conversion to SearchScope enum
        # Type narrowing: scope is str from SearchOptions model
        scope_for_mapping: str | FlextLdapConstants.Ldap.SearchScope = (
            search_options.scope
        )
        scope_result = Ldap3Adapter._map_scope(scope_for_mapping)
        if scope_result.is_failure:
            return r[m.Ldap.SearchResult].fail(
                str(scope_result.error) if scope_result.error else "",
            )

        search_params = self.SearchExecutor.SearchParams(
            base_dn=search_options.base_dn,
            filter_str=search_options.filter_str,
            ldap_scope=scope_result.value,
            search_attributes=search_options.attributes or [],
            size_limit=search_options.size_limit,
            time_limit=search_options.time_limit,
        )
        entries_result = self.SearchExecutor(self).execute(
            connection_result.value,
            search_params,
            server_type,
        )

        if entries_result.is_failure:
            return r[m.Ldap.SearchResult].fail(
                str(entries_result.error) if entries_result.error else "",
            )

        # Use entries directly - LdifEntry is the public API
        # so all entries are compatible via duck-typing (same interface)
        entries_raw = entries_result.value

        return r[m.Ldap.SearchResult].ok(
            m.Ldap.SearchResult(
                entries=list(entries_raw),
                search_options=search_options,
            ),
        )

    def add(
        self,
        entry: LdifEntry,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.OperationResult]:
        """Add LDAP entry using Entry model.

        Business Rules:
            - Entry attributes are converted from LdifEntry to ldap3 format
            - DN is extracted using FlextLdifUtilities.Ldif.DN.get_dn_value()
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
            return r[m.Ldap.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )

        # entry is already LdifEntry from signature - use directly
        # Cast to protocol for type compatibility
        attrs_result = self._entry_adapter.ldif_entry_to_ldap3_attributes(entry)
        if attrs_result.is_failure:
            error_msg = str(attrs_result.error) if attrs_result.error else ""
            return r[m.Ldap.OperationResult].fail(
                f"Failed to convert entry attributes: {error_msg}",
            )

        # Extract DN value using u.Ldif.DN.get_dn_value() - handles all DN types
        # DSL pattern: conditional default
        dn_str = u.Ldif.DN.get_dn_value(entry.dn) if entry.dn is not None else "unknown"
        return self.OperationExecutor(self).execute_add(
            connection_result.value,
            dn_str,
            attrs_result.value,
        )

    def modify(
        self,
        dn: str | m.Ldif.DN,
        changes: t.Ldap.Operation.Changes,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.OperationResult]:
        """Modify LDAP entry.

        Business Rules:
            - Entry must exist before modification (LDAP error 32 if not found)
            - Changes use ldap3 format: {attr_name: [(MODIFY_ADD|MODIFY_DELETE|MODIFY_REPLACE, [values])]}
            - DN normalization is applied using FlextLdifUtilities.Ldif.DN.get_dn_value()
            - String DNs are converted to DN models for type safety
            - Connection must be established and bound before modify operation

        Audit Implications:
            - Modify operations are logged with DN and change summary
            - Successful modifies log affected count (always 1)
            - Failed modifies log error messages with DN for forensic analysis

        Architecture:
            - Uses OperationExecutor.execute_modify() for protocol-level operation
            - DN conversion handled by FlextLdifUtilities.Ldif.DN
            - Returns FlextResult pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to modify (string or DN model)
            changes: Modification changes dict in ldap3 format

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return r[m.Ldap.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )
        return self.OperationExecutor(self).execute_modify(
            connection_result.value,
            dn,
            changes,
        )

    def delete(
        self,
        dn: str | m.Ldif.DN,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.OperationResult]:
        """Delete LDAP entry.

        Business Rules:
            - Entry must exist before deletion (LDAP error 32 if not found)
            - Entry must not have children (LDAP error 66 if has children)
            - DN normalization is applied using FlextLdifUtilities.Ldif.DN.get_dn_value()
            - String DNs are converted to DN models for type safety
            - Connection must be established and bound before delete operation

        Audit Implications:
            - Delete operations are logged with DN for critical audit trail
            - Successful deletes log affected count (always 1)
            - Failed deletes log error messages with DN for forensic analysis

        Architecture:
            - Uses OperationExecutor.execute_delete() for protocol-level operation
            - DN conversion handled by FlextLdifUtilities.Ldif.DN
            - Returns FlextResult pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to delete (string or DN model)

        Returns:
            FlextResult containing OperationResult with success status and entries_affected=1

        """
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return r[m.Ldap.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )
        return self.OperationExecutor(self).execute_delete(
            connection_result.value,
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
        # Create results
        if not self.is_connected:
            return r[bool].fail(c.Ldap.ErrorStrings.NOT_CONNECTED)
        return r[bool].ok(True)
