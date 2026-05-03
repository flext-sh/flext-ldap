"""FLEXT_LDAP utilities module - Domain-specific utilities.

This module provides LDAP-specific utilities that extend FlextUtilities from flext-core.
Uses advanced builder patterns, mnemonic DSL, and parametrization for clean code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Mapping,
    MutableMapping,
)
from typing import Literal, TypeIs

import ldap3

from flext_ldap import c, m, p, t
from flext_ldif import r, u


class FlextLdapUtilities(u):
    """FlextLdap utilities - extends u with advanced builders.

    ARCHITECTURE:
    ────────────
    - Extends FlextUtilities methods via inheritance
    - Uses builder/DSL patterns for composition
    - Mnemonic short names (to_str_list, norm_join, etc.)
    - Maximizes reuse of base utilities
    - LDAP-specific overrides only where needed

    USAGE:
    ──────
        from flext_core import u

        # Builder patterns
        values = u.to_str_list(attr_value)
        normalized = u.norm_join(["A", "B"], case="lower")
        filtered = u.filter_attrs(attrs, only_list_like=True)
    """

    class Ldap:
        """LDAP-specific utility namespace.

        This namespace groups all LDAP-specific utilities for better organization
        and cross-project access. Also provides access to LDIF utilities via .Ldif.

        Example:
            from flext_core import u
            values = u.to_str_list(attr_value)
            result = u.Ldap.DN.parse("cn=test,dc=example")  # Access LDIF utilities

        """

        @staticmethod
        def resolve_get_info(
            get_info: c.Ldap.Ldap3GetInfo,
        ) -> Literal["ALL", "DSA", "NO_INFO", "SCHEMA"]:
            """Resolve Ldap3GetInfo enum to typed literal for ldap3 stubs."""
            match get_info:
                case c.Ldap.Ldap3GetInfo.DSA:
                    return "DSA"
                case c.Ldap.Ldap3GetInfo.NO_INFO:
                    return "NO_INFO"
                case c.Ldap.Ldap3GetInfo.SCHEMA:
                    return "SCHEMA"
                case _:
                    return "ALL"

        @staticmethod
        def create_server(
            host: str,
            port: int = c.Ldap.PORT,
            *,
            use_ssl: bool = False,
            get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.ALL,
        ) -> p.Ldap.Ldap3Server:
            """Create an ldap3 Server instance.

            The ONLY sanctioned way for test code outside flext-ldap/src and
            flext-ldif/src to create an LDAP server object.
            """
            scheme = "ldaps" if use_ssl else "ldap"
            server: p.Ldap.Ldap3Server = ldap3.Server(
                f"{scheme}://{host}:{port}",
                get_info=FlextLdapUtilities.Ldap.resolve_get_info(get_info),
            )
            return server

        @staticmethod
        def create_server_from_url(
            server_url: str,
            *,
            get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.ALL,
        ) -> p.Ldap.Ldap3Server:
            """Create an ldap3 Server instance from a URL string.

            Args:
                server_url: Full LDAP URL (e.g. "ldap://localhost:3390").
                get_info: Info level ("ALL", "NONE", "NO_INFO", "DSA", "SCHEMA").

            """
            server: p.Ldap.Ldap3Server = ldap3.Server(
                server_url,
                get_info=FlextLdapUtilities.Ldap.resolve_get_info(get_info),
            )
            return server

        @staticmethod
        def create_connection(
            server: p.Ldap.Ldap3Server,
            *,
            user: str,
            password: str,
            auto_bind: bool = True,
            receive_timeout: int | None = None,
        ) -> p.Ldap.Ldap3Connection:
            """Create an ldap3 Connection instance.

            The ONLY sanctioned way for test code outside flext-ldap/src and
            flext-ldif/src to create an LDAP connection object.
            """
            ldap3_server: ldap3.Server
            if isinstance(server, ldap3.Server):
                ldap3_server = server
            else:
                ldap3_server = ldap3.Server(str(server))
            return ldap3.Connection(
                ldap3_server,
                user=user,
                password=password,
                auto_bind=auto_bind,
                receive_timeout=receive_timeout,
            )

        @staticmethod
        def create_bare_server(
            host: str,
            *,
            port: int = c.Ldap.PORT,
            get_info: c.Ldap.Ldap3GetInfo = c.Ldap.Ldap3GetInfo.NO_INFO,
        ) -> p.Ldap.Ldap3Server:
            """Create an ldap3 Server with minimal info retrieval (for connectivity checks)."""
            server: p.Ldap.Ldap3Server = ldap3.Server(
                host,
                port=port,
                get_info=FlextLdapUtilities.Ldap.resolve_get_info(get_info),
            )
            return server

        class Validation:
            """LDAP validation utilities namespace.

            This namespace contains validation helper methods. Functions are not allowed
            in constants.py, so validation methods are placed here in utilities.py.
            """

            @staticmethod
            def is_valid_status(value: str | t.JsonValue) -> TypeIs[str]:
                """TypeIs narrowing - works in both if/else branches.

                Since StatusLiteral is a subtype of str, after checking enum type,
                    value, Status
                ),
                the remaining type is str | StatusLiteral. We can check membership directly
                without another isinstance check.

                Args:
                    value: Status value to validate (str, Status enum, or StatusLiteral)

                Returns:
                    TypeIs guard indicating if value is a valid StatusLiteral

                """
                if isinstance(value, c.Ldap.Status):
                    return True
                return value in c.Ldap.VALID_STATUSES

        @classmethod
        def norm_in(
            cls,
            value: str,
            collection: t.StrSequence | t.VariadicTuple[str],
            *,
            case: str | None = None,
        ) -> bool:
            """Check if normalized value is in collection (delegates to Parser.norm_in).

            Args:
                value: String to check
                collection: List or tuple of strings to check against
                case: Case normalization ("lower", "upper", None)

            Returns:
                True if normalized value is in collection

            """
            collection_list: t.StrSequence
            match collection:
                case tuple():
                    collection_list = list(collection)
                case _:
                    collection_list = collection
            normalized_value = cls.norm_str(value, case=case or "lower")
            normalized_collection = [
                cls.norm_str(item, case=case or "lower") for item in collection_list
            ]
            return normalized_value in normalized_collection

        @classmethod
        def norm_join(
            cls,
            values: t.StrSequence | t.VariadicTuple[str],
            *,
            case: str | None = None,
        ) -> str:
            """Normalize and join strings (delegates to Parser.norm_join).

            Args:
                values: List or tuple of strings to normalize and join
                case: Case normalization ("lower", "upper", None)

            Returns:
                Joined normalized string

            """
            values_list: t.StrSequence
            match values:
                case tuple():
                    values_list = list(values)
                case _:
                    values_list = values
            normalized = [cls.norm_str(v, case=case) for v in values_list if v]
            return " ".join(normalized)

        @classmethod
        def _convert_attr_value(
            cls,
            value: t.JsonValue | t.Ldap.Ldap3AttributeValue | t.StrSequence,
        ) -> t.StrSequence:
            match value:
                case None:
                    return []
                case bytes() | str() | bool() | int() | float():
                    return cls.ldap3_value_to_strings(value)
                case list() | tuple() | range():
                    return [
                        item.decode(c.Ldif.Encoding.UTF8, errors="replace")
                        if isinstance(item, bytes)
                        else str(item)
                        for item in value
                    ]
                case _:
                    return [str(value)]

        @classmethod
        def attr_to_str_list(
            cls,
            attrs: (
                t.Ldap.Ldap3AttributeDict
                | t.MappingKV[str, t.Ldap.Ldap3AttributeValue]
                | t.JsonMapping
                | t.MappingKV[str, t.StrSequence]
            ),
        ) -> t.MappingKV[str, t.StrSequence]:
            """Convert attributes to str_list (generalized: map() + ensure).

            Uses advanced DSL: map() → ensure() for fluent composition.

            Args:
                attrs: Attributes to convert

            Returns:
                t.MappingKV[str, t.StrSequence]: Converted attributes

            """
            return {k: cls._convert_attr_value(v) for k, v in (attrs or {}).items()}

        @staticmethod
        def ldap3_value_to_strings(
            value: t.Ldap.Ldap3EntryValue | t.JsonValue | None,
        ) -> t.StrSequence:
            """Convert an ldap3 attribute payload to canonical string values."""
            match value:
                case None:
                    empty_values: t.StrSequence = []
                    return empty_values
                case bytes() as value_bytes:
                    return [value_bytes.decode(c.Ldif.Encoding.UTF8, errors="replace")]
                case list() | tuple() as sequence_values:
                    return [
                        item.decode(c.Ldif.Encoding.UTF8, errors="replace")
                        if isinstance(item, bytes)
                        else str(item)
                        for item in sequence_values
                    ]
                case _:
                    return [str(value)]

        @staticmethod
        def is_base64_encoded(
            value: str,
            threshold: int = c.Ldif.ASCII_THRESHOLD,
        ) -> bool:
            """Return ``True`` when a value requires LDIF base64 encoding."""
            return value.startswith("::") or any(
                ord(char) > threshold for char in value
            )

        @classmethod
        def normalize_original_attr_value(
            cls,
            value: t.Ldap.Ldap3EntryValue | None,
        ) -> t.StrSequence:
            """Normalize original ldap3 values while preserving list semantics."""
            return cls.ldap3_value_to_strings(value)

        @staticmethod
        def build_conversion_metadata(
            removed_attrs: t.StrSequence,
            base64_attrs: t.StrSequence,
            original_attrs_dict: t.MappingKV[
                str, t.JsonValue | t.Ldap.Ldap3AttributeValue
            ],
            original_dn: str,
        ) -> m.Ldap.ConversionMetadata:
            """Create canonical conversion metadata for LDAP entry adaptation."""
            return m.Ldap.ConversionMetadata.model_validate({
                "source_attributes": list(dict(original_attrs_dict).keys()),
                "source_dn": original_dn,
                "removed_attributes": list(removed_attrs),
                "base64_encoded_attributes": list(set(base64_attrs)),
            })

        @classmethod
        def search_entry_to_ldif_entry(
            cls,
            entry: t.MappingKV[str, t.Ldap.Ldap3AttributeValue | t.JsonValue],
        ) -> p.Result[m.Ldif.Entry]:
            """Convert LDAP search-result mappings into canonical LDIF entries."""
            raw_entry = dict(entry)
            dn_raw = raw_entry.get("dn")
            dn_values = cls.ldap3_value_to_strings(dn_raw)
            if not dn_values:
                return r[m.Ldif.Entry].fail("Search entry missing DN")
            dn_value = dn_values[0]
            attributes: MutableMapping[str, t.MutableSequenceOf[str] | str] = {
                key: list(
                    cls.ldap3_value_to_strings(value),
                )
                for key, value in raw_entry.items()
                if key != "dn"
            }
            return m.Ldif.Entry.create(
                dn=dn_value,
                attributes=attributes,
            )

        @classmethod
        def track_conversion_differences(
            cls,
            conversion_metadata: m.Ldap.ConversionMetadata,
            *,
            original_dn: str,
            converted_dn: str,
            original_attrs_dict: t.Ldap.Ldap3AttributeDict,
            converted_attrs_dict: t.MappingKV[str, t.StrSequence],
        ) -> m.Ldap.ConversionMetadata:
            """Record DN and attribute changes observed during entry conversion."""
            updates: MutableMapping[str, bool | str | t.StrSequence] = {}
            if converted_dn != original_dn:
                updates["dn_changed"] = True
                updates["converted_dn"] = converted_dn
            changed_attrs = [
                attr_name
                for attr_name, original_values in original_attrs_dict.items()
                if ", ".join(cls.normalize_original_attr_value(original_values))
                != ", ".join(
                    value for value in converted_attrs_dict.get(attr_name, []) if value
                )
            ]
            if changed_attrs:
                updates["attribute_changes"] = changed_attrs
            if not updates:
                return conversion_metadata
            return conversion_metadata.model_copy(update=updates)

        @classmethod
        def extract_entry_attributes(
            cls,
            entry: p.Ldif.Entry,
        ) -> t.MappingKV[str, t.StrSequence]:
            """Normalize entry attributes to the canonical LDAP comparison mapping."""
            attrs = entry.attributes
            if attrs is None:
                return {}
            return cls.attr_to_str_list(attrs.attributes)

        @classmethod
        def find_existing_values(
            cls,
            attr_name: str,
            existing_attrs: t.MappingKV[str, t.StrSequence],
        ) -> t.StrSequence | None:
            """Resolve attribute values by case-insensitive LDAP name matching."""
            normalized_target = cls.norm_str(attr_name, case="lower")
            for key, values in existing_attrs.items():
                if cls.norm_str(key, case="lower") == normalized_target:
                    return list(values)
            return None

        @staticmethod
        def normalize_value_set(values: t.StrSequence) -> set[str]:
            """Normalize LDAP attribute values for stable comparison."""
            return {value.lower() for value in values if value}

        @classmethod
        def process_new_attributes(
            cls,
            new_attrs: t.MappingKV[str, t.StrSequence],
            existing_attrs: t.MappingKV[str, t.StrSequence],
            ignore: frozenset[str],
        ) -> t.Pair[t.Ldap.OperationChanges, set[str]]:
            """Build replacement changes for non-operational attributes."""
            changes: t.Ldap.OperationChanges = {}
            processed: set[str] = set()
            ignored = {value.lower() for value in ignore}
            for attr_name, raw_values in new_attrs.items():
                normalized_name = cls.norm_str(attr_name, case="lower")
                if normalized_name in ignored:
                    continue
                processed.add(normalized_name)
                new_values = [value for value in raw_values if value]
                existing_values = cls.find_existing_values(attr_name, existing_attrs)
                existing_set = cls.normalize_value_set(existing_values or [])
                new_set = cls.normalize_value_set(new_values)
                if existing_set != new_set:
                    changes[attr_name] = [
                        (c.Ldap.ModifyOperation.REPLACE, new_values),
                    ]
            return changes, processed

        @classmethod
        def process_deleted_attributes(
            cls,
            existing_attrs: t.MappingKV[str, t.StrSequence],
            ignore: frozenset[str],
            processed: set[str],
        ) -> t.Ldap.OperationChanges:
            """Build delete operations for attributes absent from the target entry."""
            empty_values: t.StrSequence = []
            ignored = {value.lower() for value in ignore}
            return {
                attr_name: [(c.Ldap.ModifyOperation.DELETE, empty_values)]
                for attr_name in existing_attrs
                if cls.norm_str(attr_name, case="lower") not in ignored
                and cls.norm_str(attr_name, case="lower") not in processed
            }

        @classmethod
        def compare_entries(
            cls,
            existing_entry: p.Ldif.Entry,
            new_entry: p.Ldif.Entry,
        ) -> p.Result[t.Ldap.OperationChanges]:
            """Compare canonical LDIF entries and return LDAP modify operations."""
            existing_attrs = cls.extract_entry_attributes(existing_entry)
            if not existing_attrs:
                return r[t.Ldap.OperationChanges].fail(
                    "Existing entry has no attributes to compare"
                )
            new_attrs = cls.extract_entry_attributes(new_entry)
            if not new_attrs:
                return r[t.Ldap.OperationChanges].fail(
                    "New entry has no attributes to compare"
                )
            changes, processed = cls.process_new_attributes(
                new_attrs,
                existing_attrs,
                c.Ldif.OperationalAttributes.IGNORE_SET,
            )
            changes.update(
                cls.process_deleted_attributes(
                    existing_attrs,
                    c.Ldif.OperationalAttributes.IGNORE_SET,
                    processed,
                ),
            )
            return r[t.Ldap.OperationChanges].ok(changes)

        @staticmethod
        def dn_str(
            dn: str | m.Ldif.DN | m.Ldif.Entry | None,
            *,
            default: str = c.Ldap.UNKNOWN_CATEGORY,
        ) -> str:
            """Extract DN string (builder: whn().safe().conv().str()).

            Uses advanced DSL: whn() → safe() → conv() → str() for fluent composition.

            Args:
                dn: DN t.JsonValue (can be None or have .value)
                default: Default if None

            Returns:
                str: DN string or default

            """
            if dn is None:
                return default
            if isinstance(dn, m.Ldif.DN):
                value = dn.value
                return value or default
            if isinstance(dn, str):
                return dn
            return str(dn.dn) if dn.dn else default

        @staticmethod
        def filter_truthy(
            value: t.JsonList | t.JsonMapping,
        ) -> t.JsonList | t.JsonMapping:
            """Filter truthy values from list or dict.

            Args:
                value: List or dict to filter

            Returns:
                Filtered list or dict with only truthy values

            """
            if isinstance(value, Mapping):
                return {k: v for k, v in value.items() if v}
            return [item for item in value if item]

        @staticmethod
        def map_str(
            values: t.StrSequence | t.VariadicTuple[str],
            *,
            case: str | None = None,
            join: str | None = None,
        ) -> str | t.StrSequence:
            """Map strings with normalization and optional join.

            Args:
                values: List of strings to map
                case: Case normalization ("lower", "upper", None)
                join: Join character (if provided, returns str; otherwise t.StrSequence)

            Returns:
                Joined string or list of normalized strings

            """
            normalized: t.MutableSequenceOf[str] = []
            for val in values:
                normalized_val = val
                if case == "lower":
                    normalized_val = val.lower()
                elif case == "upper":
                    normalized_val = val.upper()
                normalized.append(normalized_val)
            if join is not None:
                return join.join(normalized)
            return normalized

        @staticmethod
        def norm_str(value: str, *, case: str | None = None) -> str:
            """Normalize string (implements normalization directly).

            Args:
                value: String to normalize
                case: Case normalization ("lower", "upper", None)

            Returns:
                Normalized string

            """
            if not value:
                return ""
            if case == "lower":
                return value.lower()
            if case == "upper":
                return value.upper()
            return value

        @classmethod
        def detect_from_extensions(
            cls,
            supported_extensions: t.StrSequence,
            naming_contexts: t.StrSequence,
        ) -> str:
            """Infer server type from rootDSE extensions and naming contexts."""
            ext_str = str(cls.map_str(supported_extensions, case="lower", join=" "))
            context_str = cls.norm_join(naming_contexts, case="lower")
            for server_name in c.Ldap.ROOT_DSE_DETECTION_ORDER:
                extension_markers = c.Ldap.ROOT_DSE_EXTENSION_MARKERS.get(
                    server_name,
                    frozenset(),
                )
                context_markers = c.Ldap.ROOT_DSE_CONTEXT_MARKERS.get(
                    server_name,
                    frozenset(),
                )
                if cls._contains_marker(ext_str, extension_markers) or cls._contains_marker(
                    context_str,
                    context_markers,
                ):
                    return server_name
            return c.Ldap.DEFAULT_TYPE.value

        @staticmethod
        def _contains_marker(
            haystack: str,
            markers: t.StrSequence | frozenset[str],
        ) -> bool:
            """Return True when any configured marker is present in the input text."""
            return any(marker in haystack for marker in markers)

        @classmethod
        def _matches_vendor_rule(cls, vendor_info: str, server_name: str) -> bool:
            """Evaluate declarative vendor-detection markers for one server type."""
            required_markers = c.Ldap.ROOT_DSE_VENDOR_REQUIRED_MARKERS.get(
                server_name,
                frozenset(),
            )
            if any(marker not in vendor_info for marker in required_markers):
                return False
            excluded_markers = c.Ldap.ROOT_DSE_VENDOR_EXCLUDED_MARKERS.get(
                server_name,
                frozenset(),
            )
            if cls._contains_marker(vendor_info, excluded_markers):
                return False
            any_markers = c.Ldap.ROOT_DSE_VENDOR_ANY_MARKERS.get(
                server_name,
                frozenset(),
            )
            if any_markers and cls._contains_marker(vendor_info, any_markers):
                return True
            max_tokens = c.Ldap.ROOT_DSE_VENDOR_MAX_TOKENS.get(server_name)
            if max_tokens is not None and len(vendor_info.split()) <= max_tokens:
                return True
            return not any_markers and max_tokens is None

        @classmethod
        def detect_from_vendor(
            cls,
            vendor_name: str | None,
            vendor_version: str | None,
        ) -> str | None:
            """Infer server type from vendor metadata when available."""
            vendor_parts = [
                u.to_str(value)
                for value in (vendor_name, vendor_version)
                if value is not None
            ]
            vendor_info = " ".join(
                str(value) for value in cls.filter_truthy(vendor_parts)
            ).lower()
            if not vendor_info:
                return None
            for detected_type in c.Ldap.ROOT_DSE_DETECTION_ORDER:
                if cls._matches_vendor_rule(vendor_info, detected_type):
                    return detected_type
            return None

        @classmethod
        def detect_server_type(
            cls,
            *,
            vendor_name: str | None,
            vendor_version: str | None,
            naming_contexts: t.StrSequence,
            supported_extensions: t.StrSequence,
        ) -> str:
            """Resolve the effective server type from rootDSE metadata."""
            return cls.detect_from_vendor(
                vendor_name,
                vendor_version,
            ) or cls.detect_from_extensions(supported_extensions, naming_contexts)

        @staticmethod
        def get_first_attribute_value(
            attrs: t.Ldap.OperationAttributes,
            key: str,
        ) -> str | None:
            """Return the first normalized value for a rootDSE attribute."""
            values = attrs.get(key)
            if values is None:
                return None
            return next((value for value in values if value), None)

        @classmethod
        def query_root_dse(
            cls,
            connection: p.Ldap.Ldap3Connection,
        ) -> p.Result[t.Ldap.OperationAttributes]:
            """Read rootDSE data from a bound ldap3 connection."""
            result: p.Result[t.Ldap.OperationAttributes]
            search_method = getattr(connection, "search", None)
            if not callable(search_method):
                result = r[t.Ldap.OperationAttributes].fail(
                    "rootDSE query failed: search unavailable",
                )
            else:
                try:
                    search_ok = search_method(
                        search_base="",
                        search_filter=str(c.Ldap.ALL_ENTRIES_FILTER),
                        search_scope=c.Ldap.SearchScopeValue.BASE,
                        attributes=str(c.Ldap.AttributeName.ALL_ATTRIBUTES),
                    )
                except (
                    ValueError,
                    TypeError,
                    AttributeError,
                    OSError,
                    RuntimeError,
                    ImportError,
                    KeyError,
                    t.Ldap.LDAPException,
                ) as exc:
                    result = r[t.Ldap.OperationAttributes].fail_op("rootDSE query", exc)
                else:
                    if not search_ok:
                        result = r[t.Ldap.OperationAttributes].fail_op(
                            "rootDSE query", connection.result
                        )
                    elif not getattr(connection, "entries", []):
                        result = r[t.Ldap.OperationAttributes].fail(
                            "rootDSE query returned no entries",
                        )
                    elif not isinstance(connection.entries[0], p.Ldap.Ldap3Entry):
                        result = r[t.Ldap.OperationAttributes].fail(
                            "rootDSE query returned invalid entry payload",
                        )
                    else:
                        result = r[t.Ldap.OperationAttributes].ok(
                            cls.attr_to_str_list(
                                connection.entries[0].entry_attributes_as_dict
                            ),
                        )
            return result

        @classmethod
        def detect_from_connection(
            cls,
            connection: p.Ldap.Ldap3Connection,
        ) -> p.Result[str]:
            """Detect LDAP server type from rootDSE on an active connection."""
            root_dse_result = cls.query_root_dse(connection)
            if root_dse_result.failure:
                return r[str].fail(f"Failed to query rootDSE: {root_dse_result.error}")
            root_dse_attrs = root_dse_result.value
            return r[str].ok(
                cls.detect_server_type(
                    vendor_name=cls.get_first_attribute_value(
                        root_dse_attrs,
                        c.Ldap.RootDseAttribute.VENDOR_NAME,
                    ),
                    vendor_version=cls.get_first_attribute_value(
                        root_dse_attrs,
                        c.Ldap.RootDseAttribute.VENDOR_VERSION,
                    ),
                    naming_contexts=root_dse_attrs.get(
                        c.Ldap.RootDseAttribute.NAMING_CONTEXTS,
                        [],
                    ),
                    supported_extensions=root_dse_attrs.get(
                        c.Ldap.RootDseAttribute.SUPPORTED_EXTENSIONS,
                        [],
                    ),
                ),
            )

        @staticmethod
        def when_safe(
            *,
            condition: bool,
            then_value: str | float | bool | None,
            else_value: str | float | bool | None = None,
            safe_then: bool = False,
        ) -> t.Primitives | None:
            """Safe conditional (builder: whn().safe().or_().build()).

            Uses advanced DSL: whn() → safe() → or_() for safe composition.

            Args:
                condition: Boolean condition
                then_value: Value if True
                else_value: Value if False
                safe_then: Return else_value if then_value is None

            Returns:
                then_value or else_value

            """
            if condition:
                if safe_then and then_value is None:
                    return else_value
                return then_value if then_value is not None else else_value
            return else_value


u = FlextLdapUtilities

__all__: list[str] = ["FlextLdapUtilities", "u"]
