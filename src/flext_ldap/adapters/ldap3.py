"""LDAP3 adapter service - Infrastructure wrapper for ldap3 library.

This module encapsulates all ldap3 library interactions, providing a clean
interface for the flext-ldap service layer. Only this adapter imports ldap3
directly; all other modules work with protocol abstractions.

Business Rules:
    - ldap3 library is ONLY imported here (zero tolerance for direct imports elsewhere)
    - Connection binding uses ldap3.Connection with auto_bind and auto_range options
    - STARTTLS is handled separately from SSL (mutual exclusion enforced in config)
    - Search results are converted to m.Ldif.Entry via FlextLdifParser
    - CRUD operations (add, modify, delete) return r for consistency
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

from collections.abc import Callable, Mapping, MutableMapping, MutableSequence, Sequence
from datetime import datetime
from typing import ClassVar, Literal, override

from flext_core import FlextService, r
from flext_ldif import FlextLdif, FlextLdifParser
from pydantic import BaseModel, ConfigDict

from flext_ldap import FlextLdapEntryAdapter, c, m, p, t, u
from ldap3 import Connection, Server


class FlextLdapLdap3Wrappers:
    """Type-safe static wrappers for untyped ldap3 Connection methods."""

    @staticmethod
    def value_to_str_list(
        value: t.Ldap.Ldap3EntryValue | t.ContainerValue | t.StrSequence,
    ) -> MutableSequence[str]:
        """Convert a list/tuple/sequence value to t.StrSequence without isinstance narrowing.

        Pyright narrows isinstance(v, list) on v:t.NormalizedValue to Sequence[Unknown], making
        element access return Unknown. This helper avoids that by using __len__
        and __getitem__ through getattr to maintain type safety.
        """
        length_fn: Callable[[], int] | None = getattr(value, "__len__", None)
        getitem_fn: Callable[[int], t.Ldap.Ldap3EntryValue] | None = getattr(
            value,
            "__getitem__",
            None,
        )
        if length_fn is None or getitem_fn is None:
            return []
        result: MutableSequence[str] = []
        for idx in range(length_fn()):
            el: t.Ldap.Ldap3EntryValue = getitem_fn(idx)
            if el is not None and isinstance(el, (str, int, float, bool, bytes)):
                result.append(str(el))
        return result

    @staticmethod
    def _ldap3_method(connection: Connection, method_name: str) -> Callable[..., bool]:
        """Get a typed callable for an untyped ldap3 Connection method.

        ldap3 library methods return Unknown types which cause pyright errors.
        This helper extracts the method via getattr and wraps the return as bool.
        """
        method: Callable[..., bool] = getattr(connection, method_name)
        return method

    @staticmethod
    def add(
        connection: Connection,
        dn: str,
        object_class: t.StrSequence | str | None,
        attributes: Mapping[str, t.StrSequence],
    ) -> bool:
        """Type-safe wrapper for untyped ldap3 Connection.add()."""
        normalized_attributes: t.FlatContainerMapping = {
            key: values[0] if values else "" for key, values in attributes.items()
        }
        add_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "add")
        return bool(add_fn(dn, object_class, normalized_attributes))

    @staticmethod
    def delete(connection: Connection, dn: str) -> bool:
        """Type-safe wrapper for untyped ldap3 Connection.delete()."""
        delete_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "delete")
        return bool(delete_fn(dn))

    @staticmethod
    def is_bound(connection: Connection) -> bool:
        """Safely read ldap3 bound state from dynamic connection objects."""
        bound_state: bool = getattr(connection, "bound", False)
        return bool(bound_state)

    @staticmethod
    def modify(
        connection: Connection,
        dn: str,
        changes: t.Ldap.OperationChanges,
    ) -> bool:
        """Type-safe wrapper for untyped ldap3 Connection.modify()."""
        modify_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "modify")
        return bool(modify_fn(dn, changes))

    @staticmethod
    def search(
        connection: Connection,
        *,
        search_base: str,
        search_filter: str,
        search_scope: int | str,
        attributes: t.StrSequence | str,
        size_limit: int,
        time_limit: int,
    ) -> bool:
        """Safely invoke ldap3 search on dynamic connection objects."""
        normalized_scope: Literal["BASE", "LEVEL", "SUBTREE"]
        if isinstance(search_scope, int):
            scope_map: Mapping[int, Literal["BASE", "LEVEL", "SUBTREE"]] = {
                c.Ldap.SearchScopeValue.BASE: "BASE",
                c.Ldap.SearchScopeValue.LEVEL: "LEVEL",
                c.Ldap.SearchScopeValue.SUBTREE: "SUBTREE",
            }
            normalized_scope = scope_map.get(search_scope, "SUBTREE")
        else:
            scope_str_map: Mapping[str, Literal["BASE", "LEVEL", "SUBTREE"]] = {
                "BASE": "BASE",
                "LEVEL": "LEVEL",
                "SUBTREE": "SUBTREE",
            }
            normalized_scope = scope_str_map.get(search_scope.upper(), "SUBTREE")
        search_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "search")
        return bool(
            search_fn(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=normalized_scope,
                attributes=list(attributes)
                if not isinstance(attributes, str)
                else attributes,
                size_limit=size_limit,
                time_limit=time_limit,
            ),
        )

    @staticmethod
    def start_tls(connection: Connection) -> bool:
        """Safely invoke STARTTLS from dynamic ldap3 connection objects."""
        result: bool = getattr(connection, "start_tls", lambda: False)()
        return bool(result)

    @staticmethod
    def unbind(connection: Connection) -> bool:
        """Type-safe wrapper for untyped ldap3 Connection.unbind()."""
        unbind_fn = FlextLdapLdap3Wrappers._ldap3_method(connection, "unbind")
        return bool(unbind_fn())


class FlextLdapLdap3Adapter(FlextService[bool]):
    """Service adapter for ldap3 library following flext-ldif patterns.

    Wraps ldap3 Connection and Server objects to provide a simplified
    interface for LDAP operations. Reuses FlextLdifParser for automatic
    conversion of LDAP results to Entry models.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=False)

    @staticmethod
    def _is_bound(connection: Connection) -> bool:
        """Check if ldap3 connection is bound."""
        bound_state: bool = getattr(connection, "bound", False)
        return bool(bound_state)

    class ConnectionManager:
        """Connection management logic (SRP)."""

        @staticmethod
        def create_connection(
            server: Server,
            config: m.Ldap.ConnectionConfig,
        ) -> Connection:
            """Create ldap3 Connection t.NormalizedValue.

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
                server: ldap3 Server t.NormalizedValue from create_server().
                config: Connection configuration with bind credentials.

            Returns:
                ldap3 Connection t.NormalizedValue (bound if auto_bind=True).

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
        def create_server(config: m.Ldap.ConnectionConfig) -> Server:
            """Create ldap3 Server t.NormalizedValue.

            Business Rules:
                - SSL connections use use_ssl=True (port 636 default)
                - Non-SSL connections use use_ssl=False (port 389 default)
                - Connect timeout uses config.timeout value
                - Server t.NormalizedValue is created without connection attempt

            Architecture:
                - Uses ldap3 Server() constructor directly
                - Returns Server instance for Connection creation
                - No network calls - t.NormalizedValue creation only

            Args:
                config: Connection configuration with host, port, SSL/TLS settings.

            Returns:
                ldap3 Server t.NormalizedValue configured for connection.

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
                - Returns r pattern - no exceptions raised
                - LDAPException is caught and converted to failure

            Args:
                connection: Active ldap3.Connection instance.
                config: Connection configuration with TLS settings.

            Returns:
                r[bool]: Success if STARTTLS not needed or succeeds.

            """
            if not config.use_tls or config.use_ssl:
                return r[bool].ok(value=True)
            try:
                if not FlextLdapLdap3Wrappers.start_tls(connection):
                    return r[bool].fail("Failed to start TLS")
                return r[bool].ok(value=True)
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ) as tls_error:
                error_msg = f"Failed to start TLS: {tls_error}"
                return r[bool].fail(error_msg)

    class ResultConverter:
        """Result conversion logic (SRP)."""

        @staticmethod
        def convert_ldap3_results(
            connection: Connection,
        ) -> Sequence[tuple[str, Mapping[str, t.StrSequence]]]:
            """Convert ldap3 connection entries to parser format.

            Business Rules:
                - Extracts DN from entry.entry_dn (string conversion)
                - Iterates entry.entry_attributes for all attributes
                - Converts attribute values to t.StrSequence format
                - None values become empty lists []
                - Single values become single-item lists [value]
                - Multiple values become lists [value1, value2, ...]

            Audit Implications:
                - All attribute values are normalized to string lists
                - Value type information may be lost (all become strings)
                - Empty lists preserve attribute presence (important for schema)

            Architecture:
                - Python 3.13: Uses guard-based sequence handling
                - Returns Sequence[tuple[str, Mapping[str, t.StrSequence]]] for parser compatibility
                - No network calls - processes connection.entries

            Args:
                connection: Active ldap3.Connection with search results in connection.entries.

            Returns:
                List of (dn, attributes_dict) tuples in parser format.

            """
            results: MutableSequence[tuple[str, Mapping[str, t.StrSequence]]] = []
            entries_list: Sequence[p.Ldap.Ldap3Entry] = getattr(
                connection,
                "entries",
                [],
            )
            entries_raw: Sequence[p.Ldap.Ldap3Entry] = entries_list
            for entry in entries_raw:
                if not isinstance(entry, p.Ldap.Ldap3Entry):
                    dn = str(entry) if entry else ""
                    results.append((dn, {}))
                    continue
                try:
                    dn_raw = entry.entry_dn
                except AttributeError:
                    dn = str(entry) if entry else ""
                    results.append((dn, {}))
                    continue
                dn = str(dn_raw) if dn_raw is not None else ""
                attrs_dict = (
                    FlextLdapLdap3Adapter.ResultConverter.process_entry_attributes(
                        entry,
                    )
                )
                results.append((dn, attrs_dict))
            return results

        @staticmethod
        def convert_parsed_entries(
            parse_response: m.Ldif.ParseResponse | p.Ldap.Ldap3ParseResponse,
        ) -> r[Sequence[m.Ldif.Entry]]:
            """Convert ParseResponse from FlextLdifParser to list of Entry models.

            Business Rules:
                - Transforms ParseResponse from FlextLdifParser into validated Entry list
                - Handles properly typed entries from parser (direct conversion)
                - Defensively converts invalid structures for edge cases (tests, manual)
                - Empty list returned when parse_response has no entries
                - All entries validated as m.Ldif.Entry instances
                - Delegates to extract_dn(), extract_attributes(), extract_metadata()

            Audit Implications:
                - This is the main entry point for LDAP search result processing
                - All entries returned are validated m.Ldif.Entry instances
                - Defensive conversion handles edge cases (tests, manual construction)
                - Empty list returned when parse_response has no entries
                - Uses r pattern for consistent error handling

            Architecture:
                - Input: m.Ldif.ParseResponse from FlextLdifParser
                - Output: r[Sequence[m.Ldif.Entry]] (railway pattern)
                - Delegates to extract_dn(), extract_attributes(), extract_metadata()
                - No network calls - processes pre-fetched LDAP results

            Remote Operation Context:
                - Called after FlextLdifParser.parse_ldap3_results() processes raw LDAP data
                - Search results were already fetched from remote LDAP server
                - This method performs local transformation only

            """
            entries_raw = parse_response.entries
            if not entries_raw:
                return r[Sequence[m.Ldif.Entry]].ok([])
            entries: MutableSequence[m.Ldif.Entry] = []
            for entry_raw in entries_raw:
                if isinstance(entry_raw, m.Ldif.Entry):
                    entries.append(entry_raw)
                    continue
                protocol_entry: p.Ldap.Ldap3Entry = entry_raw
                dn_obj = FlextLdapLdap3Adapter.ResultConverter.extract_dn(
                    protocol_entry,
                )
                attrs_obj = FlextLdapLdap3Adapter.ResultConverter.extract_attributes(
                    protocol_entry,
                )
                metadata_obj = FlextLdapLdap3Adapter.ResultConverter.extract_metadata(
                    protocol_entry,
                )
                entry = m.Ldif.Entry(
                    dn=dn_obj,
                    attributes=attrs_obj,
                    changetype=None,
                    metadata=metadata_obj,
                    validation_metadata=None,
                )
                entries.append(entry)
                continue
            return r[Sequence[m.Ldif.Entry]].ok(entries)

        @staticmethod
        def extract_attributes(
            parsed: m.Ldif.Entry | p.Ldap.Ldap3Entry | t.ContainerValue,
        ) -> m.Ldif.Attributes:
            """Extract LDAP attributes as m.Ldif.Attributes.

            Business Rules:
                - Extracts attributes from m.Ldif.Entry or protocol entries
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
            attrs_raw: (
                m.Ldif.DN | m.Ldif.Attributes | m.Ldif.QuirkMetadata | str | None
            ) = None
            if isinstance(parsed, m.Ldif.Entry):
                attrs_raw = parsed.attributes
            else:
                attrs_raw = FlextLdapLdap3Adapter.ResultConverter.get_dynamic_attribute(
                    parsed,
                    "attributes",
                )
            if attrs_raw is None:
                return m.Ldif.Attributes(
                    attributes={},
                    attribute_metadata={},
                    metadata=None,
                )
            if isinstance(attrs_raw, m.Ldif.Attributes):
                return attrs_raw
            attrs_dict = FlextLdapLdap3Adapter.ResultConverter.extract_attrs_dict(
                attrs_raw,
            )
            return m.Ldif.Attributes.model_validate({
                "attributes": attrs_dict,
                "attribute_metadata": {},
                "metadata": None,
            })

        @staticmethod
        def extract_attrs_dict(
            attrs: p.Ldap.HasAttributesProperty
            | Mapping[str, t.ContainerValue | t.StrSequence]
            | p.Ldap.HasItemsMethod
            | m.Ldif.Attributes
            | BaseModel
            | t.ContainerValue,
        ) -> t.Ldap.OperationAttributeDict:
            """Extract LDAP attributes as dictionary from various input formats.

            Business Rules:
                - Handles objects with 'attributes' property (ldap3 Entry, Pydantic models)
                - Handles Pydantic BaseModel via model_dump() for safe serialization
                - Handles Mapping types (dict, dict-like objects) directly
                - All attribute values normalized to t.StrSequence format
                - Empty dict {} returned on extraction failure (no exception raised)
                - Python 3.13: Uses guard-based sequence handling

            Audit Implications:
                - Attribute extraction affects data written to/read from LDAP directory
                - All values converted to strings - numeric/boolean type info may be lost
                - Empty dict {} returned on extraction failure - no exception raised
                - Uses Pydantic's model_dump() for safe model serialization

            Architecture:
                - Handles: objects with 'attributes' property, Pydantic BaseModel, Mapping
                - Returns t.Ldap.OperationAttributeDict (Mapping[str, t.StrSequence])
                - No network calls - pure data transformation

            """
            if isinstance(attrs, p.Ldap.HasAttributesProperty):
                return FlextLdapLdap3Adapter.ResultConverter.normalize_attr_values(
                    attrs.attributes,
                )
            if isinstance(attrs, BaseModel):
                model_attrs: Mapping[str, t.Ldap.Ldap3EntryValue] | None = getattr(
                    attrs,
                    "attributes",
                    None,
                )
                if model_attrs is not None:
                    return FlextLdapLdap3Adapter.ResultConverter.normalize_attr_values(
                        model_attrs,
                    )
                return {}
            if isinstance(attrs, Mapping):
                return FlextLdapLdap3Adapter.ResultConverter.normalize_attr_values(
                    attrs,
                )
            return {}

        @staticmethod
        def extract_dn(
            parsed: m.Ldif.Entry | p.Ldap.Ldap3Entry | t.NormalizedValue,
        ) -> m.Ldif.DN:
            """Extract Distinguished Name from LDAP entry.

            Business Rules:
                - Extracts DN from m.Ldif.Entry instances directly
                - Handles protocol-based entries via dynamic attribute access
                - Uses u.Ldif.get_dn_value() for normalization
                - Returns empty DN("") when extraction fails (no exception)
                - DN normalization ensures consistent format across server types

            Audit Implications:
                - DN extraction is critical for LDAP operations targeting specific entries
                - Empty DN ("") returned when extraction fails - caller must validate
                - Uses m.Ldif.DN for type-safe DN handling
                - Remote LDAP operations depend on correct DN for targeting entries

            Architecture:
                - Delegates to u.Ldif.get_dn_value() for normalization
                - Returns m.Ldif.DN (Pydantic model)
                - No network calls - pure data extraction from local objects

            Args:
                parsed: Entry from LDAP search or protocol-based entry structure.

            Returns:
                DN instance with extracted or empty value.

            """
            default_metadata = m.Ldif.EntryMetadata()
            if isinstance(parsed, m.Ldif.Entry):
                if parsed.dn is not None:
                    return m.Ldif.DN(value=parsed.dn.value, metadata=parsed.dn.metadata)
                return m.Ldif.DN(value="", metadata=default_metadata)
            dn_raw: (
                m.Ldif.DN | m.Ldif.Attributes | m.Ldif.QuirkMetadata | str | None
            ) = None
            if isinstance(parsed, p.Ldap.Ldap3Entry):
                dn_raw = parsed.entry_dn
            else:
                dn_raw = FlextLdapLdap3Adapter.ResultConverter.get_dynamic_attribute(
                    parsed,
                    "dn",
                )
            if dn_raw is None:
                return m.Ldif.DN(value="", metadata=default_metadata)
            if isinstance(dn_raw, m.Ldif.DN):
                return dn_raw
            if isinstance(dn_raw, p.Ldap.DN):
                return m.Ldif.DN(
                    value=dn_raw.value or "",
                    metadata=default_metadata,
                )
            dn_str_val = str(dn_raw)
            dn_value: str = u.Ldif.get_dn_value(dn_str_val)
            return m.Ldif.DN(value=dn_value, metadata=default_metadata)

        @staticmethod
        def extract_metadata(
            parsed: m.Ldif.Entry | p.Ldap.Ldap3Entry | t.NormalizedValue,
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
            metadata_raw: Mapping[str, t.Scalar | None] | None = None
            if isinstance(parsed, m.Ldif.Entry):
                if parsed.metadata is None:
                    return None
                return parsed.metadata
            dynamic_attr = FlextLdapLdap3Adapter.ResultConverter.get_dynamic_attribute(
                parsed,
                "metadata",
            )
            if dynamic_attr is None:
                return None
            if isinstance(dynamic_attr, m.Ldif.QuirkMetadata):
                return dynamic_attr
            if isinstance(dynamic_attr, Mapping):
                metadata_raw = dynamic_attr
            if not metadata_raw:
                return None
            normalized = FlextLdapLdap3Adapter.ResultConverter.normalize_metadata(
                metadata_raw,
            )
            if normalized:
                quirk_type_raw = normalized.get("quirk_type")
                if not isinstance(quirk_type_raw, str):
                    return None
                return m.Ldif.QuirkMetadata.model_validate({
                    "quirk_type": quirk_type_raw,
                })
            return None

        @staticmethod
        def get_dynamic_attribute(
            obj: p.Ldap.Ldap3Entry | m.Ldif.Entry | t.NormalizedValue,
            attr_name: str,
        ) -> m.Ldif.DN | m.Ldif.Attributes | m.Ldif.QuirkMetadata | str | None:
            """Get dynamic attribute with type safety.

            Args:
                obj: Object to access
                attr_name: Attribute name

            Returns:
                Attribute value or None

            """
            if attr_name == "dn" and isinstance(obj, m.Ldif.Entry):
                return obj.dn
            if attr_name == "attributes" and isinstance(obj, m.Ldif.Entry):
                return obj.attributes
            if attr_name == "metadata" and isinstance(obj, m.Ldif.Entry):
                return obj.metadata
            if attr_name == "entry_dn" and isinstance(obj, p.Ldap.Ldap3Entry):
                return obj.entry_dn
            return None

        @staticmethod
        def normalize_attr_values(
            attrs_dict: Mapping[
                str,
                t.Ldap.Ldap3EntryValue | t.ContainerValue | t.StrSequence,
            ]
            | None,
        ) -> t.Ldap.OperationAttributeDict:
            """Normalize attribute values to t.StrSequence format.

            Args:
                attrs_dict: Dictionary or Mapping with attribute values (or None)

            Returns:
                Normalized Mapping[str, t.StrSequence]

            """
            if attrs_dict is None:
                return {}
            result: MutableMapping[str, MutableSequence[str]] = {}
            for k in attrs_dict:
                v = attrs_dict[k]
                if isinstance(v, str):
                    result[k] = [v]
                elif isinstance(v, (int, float, bool, bytes, datetime)):
                    result[k] = [str(v)]
                elif hasattr(v, "__len__") and hasattr(v, "__getitem__"):
                    result[k] = FlextLdapLdap3Wrappers.value_to_str_list(v)
                elif v is not None:
                    result[k] = [str(v)]
                else:
                    result[k] = list[str]()
            return result

        @staticmethod
        def normalize_metadata(
            metadata: Mapping[str, t.Scalar | None] | None,
        ) -> Mapping[str, t.Scalar | t.ScalarList] | None:
            """Normalize metadata for Entry model validation.

            Business Rules:
                - Filters to types accepted by QuirkMetadata: t.Primitives | None
                - String keys are required (filters out non-string keys)
                - Invalid value types are filtered out (preserves valid entries)
                - Handles dict, Mapping, and Pydantic models with model_dump()
                - Returns None if metadata is empty or invalid

            Audit Implications:
                - Metadata normalization ensures type safety for QuirkMetadata
                - Invalid values are silently filtered (no errors raised)
                - Preserves valid metadata entries for server quirk tracking

            Architecture:
                - Uses guard-based type filtering
                - Uses Pydantic model_dump() for model serialization
                - Returns Mapping[str, t.Primitives] or None

            Args:
                metadata: Raw metadata from entry (dict, Mapping, Pydantic model, or None).

            Returns:
                Normalized metadata dict or None if empty/invalid.

            """
            if not metadata:
                return None
            metadata_dict: t.MutableContainerMapping = {}
            for raw_key, raw_value in metadata.items():
                if raw_value is None or isinstance(
                    raw_value,
                    (str, int, float, bool),
                ):
                    metadata_dict[raw_key] = raw_value
            if not metadata_dict:
                return None
            filtered: MutableMapping[str, t.Scalar | t.ScalarList] = {}
            for key, val in metadata_dict.items():
                if u.is_primitive(val):
                    filtered[str(key)] = val
            return filtered or None

        @staticmethod
        def process_entry_attributes(
            entry: p.Ldap.Ldap3Entry,
        ) -> Mapping[str, t.StrSequence]:
            """Convert LDAP entry attributes to string-list mapping."""
            attrs_dict: MutableMapping[str, MutableSequence[str]] = {}
            for attr, attr_values in entry.entry_attributes_as_dict.items():
                attrs_dict[attr] = [str(v) for v in attr_values]
            return attrs_dict

    class OperationExecutor:
        """LDAP operation execution logic (SRP)."""

        def __init__(self, adapter: FlextLdapLdap3Adapter) -> None:
            """Initialize with adapter instance."""
            super().__init__()
            self._adapter = adapter

        @staticmethod
        def _add_entry_to_ldap(
            connection: Connection,
            dn_str: str,
            attrs_dict: Mapping[str, t.StrSequence],
        ) -> bool:
            """Add entry to LDAP directory.

            This typed wrapper handles the untyped ldap3 add() call.

            Args:
                connection: Active ldap3 Connection t.NormalizedValue.
                dn_str: Distinguished name string.
                attrs_dict: Attributes dictionary (str -> t.StrSequence).

            Returns:
                True if add succeeded, False otherwise.

            """
            return FlextLdapLdap3Wrappers.add(connection, dn_str, None, attrs_dict)

        @staticmethod
        def _delete_entry_from_ldap(connection: Connection, dn_str: str) -> bool:
            """Delete entry from LDAP directory.

            This typed wrapper handles the untyped ldap3 delete() call.

            Args:
                connection: Active ldap3 Connection t.NormalizedValue.
                dn_str: Distinguished name string.

            Returns:
                True if delete succeeded, False otherwise.

            """
            return FlextLdapLdap3Wrappers.delete(connection, dn_str)

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
                - Uses u.is_dict_like() for type-safe dict access

            Audit Implications:
                - Error messages preserve LDAP server error context
                - Description field contains server-specific error details
                - Error extraction enables proper error propagation

            Architecture:
                - Uses connection.result dict from ldap3
                - Uses u.is_dict_like() for type narrowing
                - Returns r.fail() with error message

            Args:
                connection: ldap3.Connection with error in connection.result.
                prefix: Error message prefix (e.g., "Add failed").

            Returns:
                r.fail() with extracted error message.

            """
            error_msg = f"{prefix}: LDAP operation returned failure status"
            result_dict = connection.result
            description = result_dict.get("description")
            match description:
                case str() as description_str:
                    error_msg = f"{prefix}: {description_str}"
                case _:
                    pass
            return r[m.Ldap.OperationResult].fail(error_msg)

        @staticmethod
        def _modify_entry_in_ldap(
            connection: Connection,
            dn_str: str,
            changes: t.Ldap.OperationChanges,
        ) -> bool:
            """Modify entry in LDAP directory.

            This typed wrapper handles the untyped ldap3 modify() call.

            Args:
                connection: Active ldap3 Connection t.NormalizedValue.
                dn_str: Distinguished name string.
                changes: Modification changes dict in ldap3 format.

            Returns:
                True if modify succeeded, False otherwise.

            """
            return FlextLdapLdap3Wrappers.modify(connection, dn_str, changes)

        def execute_add(
            self,
            connection: Connection,
            dn_str: str,
            ldap_attrs: t.Ldap.OperationAttributes,
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
                - Returns r pattern - no exceptions raised

            Args:
                connection: Active ldap3 Connection t.NormalizedValue
                dn_str: Distinguished name as string
                ldap_attrs: Attributes dict in ldap3 format

            Returns:
                r containing OperationResult with success status

            """
            try:
                attrs_dict: Mapping[str, t.StrSequence] = {
                    k: list(v) for k, v in ldap_attrs.items()
                }
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
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ) as e:
                error_msg = f"Add failed: {e!s}"
                return r[m.Ldap.OperationResult].fail(error_msg)

        def execute_delete(
            self,
            connection: Connection,
            dn: str | m.Ldif.DN,
        ) -> r[m.Ldap.OperationResult]:
            """Execute LDAP delete operation via ldap3 Connection.

            Business Rules:
                - DN is normalized using u.Ldif.get_dn_value()
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
                - Returns r pattern - no exceptions raised

            Args:
                connection: Active ldap3 Connection t.NormalizedValue
                dn: Distinguished name (string or DN model)

            Returns:
                r containing OperationResult with success status

            """
            try:
                dn_str = u.Ldif.get_dn_value(dn)
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
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ) as e:
                error_msg = f"Delete failed: {e!s}"
                return r[m.Ldap.OperationResult].fail(error_msg)

        def execute_modify(
            self,
            connection: Connection,
            dn: str | m.Ldif.DN,
            changes: t.Ldap.OperationChanges,
        ) -> r[m.Ldap.OperationResult]:
            """Execute LDAP modify operation via ldap3 Connection.

            Business Rules:
                - DN is normalized using u.Ldif.get_dn_value()
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
                - Returns r pattern - no exceptions raised

            Args:
                connection: Active ldap3 Connection t.NormalizedValue
                dn: Distinguished name (string or DN model)
                changes: Modification changes dict in ldap3 format

            Returns:
                r containing OperationResult with success status

            """
            try:
                dn_str = u.Ldif.get_dn_value(dn)
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
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ) as e:
                error_msg = f"Modify failed: {e!s}"
                return r[m.Ldap.OperationResult].fail(error_msg)

    class SearchExecutor:
        """Search operation execution logic (SRP)."""

        def __init__(self, adapter: FlextLdapLdap3Adapter) -> None:
            """Initialize search executor with adapter instance.

            Business Rules:
                - Adapter is REQUIRED (no default, fail-fast pattern)
                - Executor stores reference for delegation to adapter
                - No connection validation at init (validated during execute)

            Architecture:
                - Inner class encapsulates search execution logic (SRP)
                - Delegates all protocol operations to FlextLdapLdap3Adapter
                - Enables testability through dependency injection

            Args:
                adapter: FlextLdapLdap3Adapter instance for LDAP protocol operations.
                    Must have active connection for execute() to succeed.

            """
            super().__init__()
            self._adapter = adapter

        def execute(
            self,
            connection: Connection,
            params: m.Ldap.SearchParams,
            server_type: c.Ldif.ServerTypes | str,
        ) -> r[Sequence[m.Ldif.Entry]]:
            """Execute LDAP search and convert results.

            Business Rules:
                - Performs ldap3 Connection.search() with provided parameters
                - Validates LDAP result codes (allows partial success codes)
                - Parses results using FlextLdifParser.parse_ldap3_results()
                - Converts ParseResponse to Sequence[Entry] via ResultConverter
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
                - Returns r pattern - no exceptions raised

            Args:
                connection: Active ldap3.Connection instance (must be bound).
                params: SearchParams dataclass with all search parameters.
                server_type: Server type (ServerTypes enum or string) for parsing quirks.

            Returns:
                r[Sequence[Entry]]: Parsed entries or error if search/parse fails.

            """
            try:
                _ = FlextLdapLdap3Wrappers.search(
                    connection,
                    search_base=params.base_dn,
                    search_filter=params.filter_str,
                    search_scope=params.ldap_scope,
                    attributes=params.search_attributes,
                    size_limit=params.size_limit,
                    time_limit=params.time_limit,
                )
                conn_result = connection.result
                result_code = conn_result.get("result", -1)
                if result_code not in c.Ldap.LdapResultCodes.PARTIAL_SUCCESS_CODES:
                    error_msg = conn_result.get("message", "LDAP search failed")
                    error_desc = conn_result.get("description", "unknown")
                    return r[Sequence[m.Ldif.Entry]].fail(
                        f"LDAP search failed: {error_desc} - {error_msg}",
                    )
                ldap3_results = self._adapter.ResultConverter.convert_ldap3_results(
                    connection,
                )
                if isinstance(server_type, c.Ldif.ServerTypes):
                    server_type_str = server_type.value
                else:
                    server_type_str = str(server_type)
                valid_server_types = {
                    c.Ldif.ServerTypes.RFC,
                    c.Ldif.ServerTypes.OID,
                    c.Ldif.ServerTypes.OUD,
                    c.Ldif.ServerTypes.OPENLDAP,
                    c.Ldif.ServerTypes.OPENLDAP1,
                    c.Ldif.ServerTypes.APACHE,
                    c.Ldif.ServerTypes.DS389,
                    c.Ldif.ServerTypes.NOVELL,
                    c.Ldif.ServerTypes.IBM_TIVOLI,
                    c.Ldif.ServerTypes.AD,
                    c.Ldif.ServerTypes.RELAXED,
                }
                if server_type_str not in valid_server_types:
                    return r[Sequence[m.Ldif.Entry]].fail(
                        f"Unsupported server type: {server_type_str}",
                    )
                parse_result = self._adapter.parser.parse_ldap3_results(
                    ldap3_results,
                    None,
                )
                if parse_result.is_failure:
                    error_msg = str(parse_result.error) if parse_result.error else ""
                    return r[Sequence[m.Ldif.Entry]].fail(error_msg)
                parse_response = parse_result.value
                return self._adapter.ResultConverter.convert_parsed_entries(
                    parse_response,
                )
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ) as e:
                return r[Sequence[m.Ldif.Entry]].fail(f"Search failed: {e!s}")

    _connection: Connection | None
    _server: Server | None
    _parser: FlextLdifParser
    _entry_adapter: FlextLdapEntryAdapter

    def __init__(self, parser: FlextLdifParser | None = None) -> None:
        """Initialize adapter service with parser.

        Args:
            parser: Optional FlextLdifParser instance. If None, uses default from FlextLdif.

        """
        super().__init__()
        if parser is None:
            parser = FlextLdif().parser
        self._connection = None
        self._server = None
        self._parser = parser
        self._entry_adapter = FlextLdapEntryAdapter()

    @property
    def connection(self) -> Connection | None:
        """Get underlying ldap3 Connection t.NormalizedValue."""
        return self._connection

    @property
    def is_connected(self) -> bool:
        """Check if adapter has an active connection."""
        if self._connection is None:
            return False
        return FlextLdapLdap3Adapter._is_bound(self._connection)

    @property
    def parser(self) -> FlextLdifParser:
        """Get parser instance."""
        return self._parser

    @staticmethod
    def _map_scope(
        scope: c.Ldap.SearchScope | str,
    ) -> r[int]:
        """Map scope string to ldap3 scope constant.

        Uses direct StrEnum value mapping for type-safe conversion.
        """
        scope_enum: c.Ldap.SearchScope
        if isinstance(scope, c.Ldap.SearchScope):
            scope_enum = scope
        else:
            try:
                scope_enum = c.Ldap.SearchScope(str(scope).upper())
            except ValueError:
                return r[int].fail(f"Invalid LDAP scope: {scope}")
        ldap3_scope_mapping: Mapping[c.Ldap.SearchScope, int] = {
            c.Ldap.SearchScope.BASE: c.Ldap.SearchScopeValue.BASE,
            c.Ldap.SearchScope.ONELEVEL: c.Ldap.SearchScopeValue.LEVEL,
            c.Ldap.SearchScope.SUBTREE: c.Ldap.SearchScopeValue.SUBTREE,
        }
        if scope_enum in ldap3_scope_mapping:
            ldap3_value = ldap3_scope_mapping[scope_enum]
            return r[int].ok(ldap3_value)
        return r[int].fail(f"Invalid LDAP scope: {scope}")

    def add(
        self,
        entry: m.Ldif.Entry,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.OperationResult]:
        """Add LDAP entry using Entry model.

        Business Rules:
            - Entry attributes are converted from m.Ldif.Entry to ldap3 format
            - DN is extracted using u.Ldif.get_dn_value()
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
            - Returns r pattern - no exceptions raised

        Args:
            entry: Entry model to add (must include DN and required attributes)

        Returns:
            r containing OperationResult with success status and entries_affected=1

        """
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return r[m.Ldap.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )
        attrs_result = self._entry_adapter.ldif_entry_to_ldap3_attributes(entry)
        if attrs_result.is_failure:
            error_msg = str(attrs_result.error) if attrs_result.error else ""
            return r[m.Ldap.OperationResult].fail(
                f"Failed to convert entry attributes: {error_msg}",
            )
        dn_str = u.Ldif.get_dn_value(entry.dn) if entry.dn is not None else "unknown"
        return self.OperationExecutor(self).execute_add(
            connection_result.value,
            dn_str,
            attrs_result.value,
        )

    def connect(
        self,
        config: m.Ldap.ConnectionConfig,
        **_kwargs: str | float | bool | None,
    ) -> r[bool]:
        """Establish LDAP connection using ldap3 library.

        Business Rules:
            - Creates ldap3 Server t.NormalizedValue based on SSL/TLS configuration
            - Creates ldap3 Connection t.NormalizedValue with bind credentials
            - STARTTLS is handled if use_tls=True and use_ssl=False
            - Connection must be bound (authenticated) to succeed
            - Connection state is tracked internally for subsequent operations

        Audit Implications:
            - Connection attempts are logged (host/port, credentials excluded)
            - TLS/SSL configuration is logged for security audit
            - Failed connections log error messages for forensic analysis
            - Connection state changes trigger audit events

        Architecture:
            - Uses ConnectionManager.create_server() for Server t.NormalizedValue
            - Uses ConnectionManager.create_connection() for Connection t.NormalizedValue
            - Uses ConnectionManager.handle_tls() for STARTTLS if needed
            - Returns r pattern - no exceptions raised

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
            if not FlextLdapLdap3Wrappers.is_bound(self._connection):
                return r[bool].fail("Failed to bind to LDAP server")
            return r[bool].ok(value=True)
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as e:
            return r[bool].fail(f"Connection failed: {e!s}")

    def delete(
        self,
        dn: str | m.Ldif.DN,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.OperationResult]:
        """Delete LDAP entry.

        Business Rules:
            - Entry must exist before deletion (LDAP error 32 if not found)
            - Entry must not have children (LDAP error 66 if has children)
            - DN normalization is applied using u.Ldif.get_dn_value()
            - String DNs are converted to DN models for type safety
            - Connection must be established and bound before delete operation

        Audit Implications:
            - Delete operations are logged with DN for critical audit trail
            - Successful deletes log affected count (always 1)
            - Failed deletes log error messages with DN for forensic analysis

        Architecture:
            - Uses OperationExecutor.execute_delete() for protocol-level operation
            - DN conversion handled by u.Ldif
            - Returns r pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to delete (string or DN model)

        Returns:
            r containing OperationResult with success status and entries_affected=1

        """
        connection_result = self._get_connection()
        if connection_result.is_failure:
            return r[m.Ldap.OperationResult].fail(
                str(connection_result.error) if connection_result.error else "",
            )
        return self.OperationExecutor(self).execute_delete(connection_result.value, dn)

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
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ) as e:
                self.logger.debug("Error during disconnect", error=str(e))
            finally:
                self._connection = None
                self._server = None

    @override
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
            - Returns r pattern - no exceptions raised
            - ``_kwargs`` absorbs extra arguments for interface compatibility

        Args:
            **_kwargs: Absorbed keyword arguments for interface compatibility.

        Returns:
            r[bool]: Success if connected, failure with NOT_CONNECTED if not.

        """
        if not self.is_connected:
            return r[bool].fail(c.Ldap.ErrorStrings.NOT_CONNECTED)
        return r[bool].ok(value=True)

    def modify(
        self,
        dn: str | m.Ldif.DN,
        changes: t.Ldap.OperationChanges,
        **_kwargs: str | float | bool | None,
    ) -> r[m.Ldap.OperationResult]:
        """Modify LDAP entry.

        Business Rules:
            - Entry must exist before modification (LDAP error 32 if not found)
            - Changes use ldap3 format: {attr_name: [(MODIFY_ADD|MODIFY_DELETE|MODIFY_REPLACE, [values])]}
            - DN normalization is applied using u.Ldif.get_dn_value()
            - String DNs are converted to DN models for type safety
            - Connection must be established and bound before modify operation

        Audit Implications:
            - Modify operations are logged with DN and change summary
            - Successful modifies log affected count (always 1)
            - Failed modifies log error messages with DN for forensic analysis

        Architecture:
            - Uses OperationExecutor.execute_modify() for protocol-level operation
            - DN conversion handled by u.Ldif
            - Returns r pattern - no exceptions raised

        Args:
            dn: Distinguished name of entry to modify (string or DN model)
            changes: Modification changes dict in ldap3 format

        Returns:
            r containing OperationResult with success status and entries_affected=1

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

    def search(
        self,
        search_options: m.Ldap.SearchOptions,
        server_type: c.Ldif.ServerTypes | str = c.Ldif.ServerTypes.RFC,
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
            - Returns r pattern - no exceptions raised

        Args:
            search_options: Search configuration (base_dn, filter_str, scope, attributes)
            server_type: LDAP server type for parsing quirks (default: RFC)

        Returns:
            r containing SearchResult with Entry models

        """
        connection_result = self._get_connection()
        if connection_result.is_failure:
            error_msg = str(connection_result.error) if connection_result.error else ""
            return r[m.Ldap.SearchResult].fail(error_msg)
        scope_for_mapping: str | c.Ldap.SearchScope = search_options.scope
        scope_result = FlextLdapLdap3Adapter._map_scope(scope_for_mapping)
        if scope_result.is_failure:
            return r[m.Ldap.SearchResult].fail(
                str(scope_result.error) if scope_result.error else "",
            )
        search_params = m.Ldap.SearchParams(
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
        entries_raw = entries_result.value
        entries_dict: Sequence[Mapping[str, t.StrSequence]] = [
            entry.model_dump() for entry in entries_raw
        ]
        return r[m.Ldap.SearchResult].ok(
            m.Ldap.SearchResult.model_validate({
                "entries": entries_dict,
                "search_options": search_options,
            }),
        )

    def _get_connection(self) -> r[Connection]:
        """Get connection with fast fail if not available."""
        if not self.is_connected or self._connection is None:
            return r[Connection].fail(c.Ldap.ErrorStrings.NOT_CONNECTED)
        return r[Connection].ok(self._connection)

    def _unbind_connection(self) -> None:
        """Unbind and close LDAP connection.

        This typed wrapper handles the untyped ldap3 unbind() call.
        Errors are suppressed to ensure cleanup always completes.
        """
        if self._connection is not None:
            try:
                _ = FlextLdapLdap3Wrappers.unbind(self._connection)
            except (AttributeError, RuntimeError):
                _ = None
