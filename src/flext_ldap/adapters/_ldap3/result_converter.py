"""LDAP3 adapter — ResultConverter.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from datetime import datetime

from flext_ldap import m, p, t, u
from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
from flext_ldif import r


class ResultConverter:
    """Result conversion logic (SRP)."""

    @staticmethod
    def convert_ldap3_results(
        connection: p.Ldap.Ldap3Connection,
    ) -> t.SequenceOf[t.Pair[str, t.MappingKV[str, t.StrSequence]]]:
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
            - Returns t.SequenceOf[tuple[str, t.MappingKV[str, t.StrSequence]]] for parser compatibility
            - No network calls - processes connection.entries

        Args:
            connection: Active ldap3.Connection with search results in connection.entries.

        Returns:
            List of (dn, attributes_dict) tuples in parser format.

        """
        results: t.MutableSequenceOf[t.Pair[str, t.MappingKV[str, t.StrSequence]]] = []
        entries_list: t.SequenceOf[p.Ldap.Ldap3Entry] = getattr(
            connection,
            "entries",
            [],
        )
        entries_raw: t.SequenceOf[p.Ldap.Ldap3Entry] = entries_list
        for entry in entries_raw:
            if not isinstance(entry, p.Ldap.Ldap3Entry):
                error_msg = (
                    f"Expected Ldap3Entry, got {type(entry).__name__}: {entry!r}"
                )
                raise TypeError(error_msg)
            dn_raw = entry.entry_dn
            dn = dn_raw if dn_raw is not None else ""
            attrs_dict = ResultConverter.process_entry_attributes(
                entry,
            )
            results.append((dn, attrs_dict))
        return results

    @staticmethod
    def convert_parsed_entries(
        parse_response: m.Ldif.ParseResponse | p.Ldap.Ldap3ParseResponse,
    ) -> p.Result[t.SequenceOf[m.Ldif.Entry]]:
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
            - Output: p.Result[t.SequenceOf[m.Ldif.Entry]] (railway pattern)
            - Delegates to extract_dn(), extract_attributes(), extract_metadata()
            - No network calls - processes pre-fetched LDAP results

        Remote Operation Context:
            - Called after FlextLdifParser.parse_ldap3_results() processes raw LDAP data
            - Search results were already fetched from remote LDAP server
            - This method performs local transformation only

        """
        entries_raw = parse_response.entries
        if not entries_raw:
            return r[t.SequenceOf[m.Ldif.Entry]].ok([])
        entries: t.MutableSequenceOf[m.Ldif.Entry] = []
        for entry_raw in entries_raw:
            if isinstance(entry_raw, m.Ldif.Entry):
                entries.append(entry_raw)
                continue
            protocol_entry: p.Ldap.Ldap3Entry = entry_raw
            dn_obj = ResultConverter.extract_dn(
                protocol_entry,
            )
            attrs_obj = ResultConverter.extract_attributes(
                protocol_entry,
            )
            metadata_obj = ResultConverter.extract_metadata(
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
        return r[t.SequenceOf[m.Ldif.Entry]].ok(entries)

    @staticmethod
    def extract_attributes(
        parsed: m.Ldif.Entry | p.Ldap.Ldap3Entry | t.JsonValue,
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
            m.Ldif.DN | m.Ldif.Attributes | m.Ldif.ServerMetadata | str | None
        ) = None
        if isinstance(parsed, m.Ldif.Entry):
            attrs_raw = parsed.attributes
        else:
            attrs_raw = ResultConverter.get_dynamic_attribute(
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
        attrs_dict = ResultConverter.extract_attrs_dict(
            attrs_raw,
        )
        validated: m.Ldif.Attributes = m.Ldif.Attributes.model_validate({
            "attributes": attrs_dict,
            "attribute_metadata": {},
            "metadata": None,
        })
        return validated

    @staticmethod
    def extract_attrs_dict(
        attrs: p.Ldap.HasAttributesProperty
        | t.MappingKV[str, t.JsonValue | t.StrSequence]
        | p.Ldap.HasItemsMethod
        | m.Ldif.Attributes
        | m.BaseModel
        | t.JsonValue,
    ) -> t.Ldap.OperationAttributes:
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
            - Handless with 'attributes' property, Pydantic BaseModel, Mapping
            - Returns t.Ldap.OperationAttributes (t.MappingKV[str, t.StrSequence])
            - No network calls - pure data transformation

        """
        if isinstance(attrs, p.Ldap.HasAttributesProperty):
            return ResultConverter.normalize_attr_values(
                attrs.attributes,
            )
        if isinstance(attrs, m.BaseModel):
            model_attrs: t.MappingKV[str, t.Ldap.Ldap3EntryValue] | None = getattr(
                attrs,
                "attributes",
                None,
            )
            if model_attrs is not None:
                return ResultConverter.normalize_attr_values(
                    model_attrs,
                )
            empty_attrs_model: t.Ldap.OperationAttributes = {}
            return empty_attrs_model
        if isinstance(attrs, Mapping):
            return ResultConverter.normalize_attr_values(
                attrs,
            )
        empty_attrs: t.Ldap.OperationAttributes = {}
        return empty_attrs

    @staticmethod
    def extract_dn(
        parsed: m.Ldif.Entry | p.Ldap.Ldap3Entry | t.JsonValue,
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
        empty_dn = m.Ldif.DN(value="", metadata=m.Ldif.EntryMetadata())
        dn_raw: m.Ldif.DN | m.Ldif.Attributes | m.Ldif.ServerMetadata | str | None = (
            None
        )
        resolved_dn = empty_dn
        match parsed:
            case None:
                dn_raw = None
            case m.Ldif.Entry() if parsed.dn is not None:
                resolved_dn = parsed.dn
            case m.Ldif.Entry():
                dn_raw = None
            case _ if isinstance(parsed, p.Ldap.Ldap3Entry):
                dn_raw = parsed.entry_dn
            case _:
                dn_raw = ResultConverter.get_dynamic_attribute(
                    parsed,
                    "dn",
                )
        if resolved_dn is empty_dn:
            match dn_raw:
                case None:
                    resolved_dn = empty_dn
                case m.Ldif.DN():
                    resolved_dn = dn_raw
                case _ if isinstance(dn_raw, p.Ldif.DN):
                    resolved_dn = empty_dn.model_copy(
                        update={"value": dn_raw.value or ""},
                    )
                case _:
                    resolved_dn = empty_dn.model_copy(
                        update={"value": u.Ldif.get_dn_value(str(dn_raw))},
                    )
        return resolved_dn

    @staticmethod
    def extract_metadata(
        parsed: m.Ldif.Entry | p.Ldap.Ldap3Entry | t.JsonValue,
    ) -> m.Ldif.ServerMetadata | None:
        """Extract server-specific server metadata from LDAP entry.

        Business Rules:
            - Extracts server metadata from entry attributes or metadata property
            - Metadata indicates server-specific behaviors (OpenLDAP, OID, OUD servers)
            - Delegates to normalize_metadata() for safe value filtering
            - None returned when no metadata present (normal, not an error)
            - Used by flext-ldif to apply server-specific transformations

        Audit Implications:
            - Server metadata affects how entries are processed for different LDAP servers
            - None returned when no metadata present - this is normal, not an error
            - Metadata filtering removes invalid/non-string values via normalize_metadata()
            - Server detection relies on this metadata for proper server application

        Architecture:
            - Delegates to normalize_metadata() for safe value filtering
            - Returns m.Ldif.ServerMetadata (Pydantic model) or None
            - No network calls - pure data extraction

        Returns:
            ServerMetadata instance or None if no metadata available.

        """
        metadata_raw: t.MappingKV[str, t.Scalar | None] | None = None
        if parsed is None:
            return None
        if isinstance(parsed, m.Ldif.Entry):
            if parsed.metadata is None:
                return None
            return parsed.metadata
        dynamic_attr = ResultConverter.get_dynamic_attribute(
            parsed,
            "metadata",
        )
        if dynamic_attr is None:
            return None
        if isinstance(dynamic_attr, m.Ldif.ServerMetadata):
            return dynamic_attr
        if isinstance(dynamic_attr, Mapping):
            metadata_raw = dynamic_attr
        if not metadata_raw:
            return None
        normalized = ResultConverter.normalize_metadata(
            metadata_raw,
        )
        if normalized:
            server_type_raw = normalized.get("server_type")
            if not isinstance(server_type_raw, str):
                return None
            server: m.Ldif.ServerMetadata = m.Ldif.ServerMetadata.model_validate({
                "server_type": server_type_raw,
            })
            return server
        return None

    @staticmethod
    def get_dynamic_attribute(
        obj: p.Ldap.Ldap3Entry | m.Ldif.Entry | t.JsonValue,
        attr_name: str,
    ) -> m.Ldif.DN | m.Ldif.Attributes | m.Ldif.ServerMetadata | str | None:
        """Get dynamic attribute with type safety.

        Args:
            obj: Object to access
            attr_name: Attribute name

        Returns:
            Attribute value or None

        """
        if obj is None:
            return None
        if attr_name == "dn" and isinstance(obj, m.Ldif.Entry):
            return obj.dn
        if attr_name == "attributes" and isinstance(obj, m.Ldif.Entry):
            return obj.attributes
        if attr_name == "metadata" and isinstance(obj, m.Ldif.Entry):
            return obj.metadata
        if attr_name == "entry_dn" and isinstance(obj, p.Ldap.Ldap3Entry):
            return str(obj.entry_dn)
        return None

    @staticmethod
    def normalize_attr_values(
        attrs_dict: t.MappingKV[
            str,
            t.Ldap.Ldap3EntryValue | t.JsonValue | t.StrSequence,
        ]
        | None,
    ) -> t.Ldap.OperationAttributes:
        """Normalize attribute values to t.StrSequence format.

        Args:
            attrs_dict: Dictionary or Mapping with attribute values (or None)

        Returns:
            Normalized t.MappingKV[str, t.StrSequence]

        """
        if attrs_dict is None:
            empty_attrs: t.Ldap.OperationAttributes = {}
            return empty_attrs
        result: t.MutableStrSequenceMapping = {}
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
                empty_values: t.MutableSequenceOf[str] = []
                result[k] = empty_values
        return result

    @staticmethod
    def normalize_metadata(
        metadata: t.MappingKV[str, t.Scalar | None] | None,
    ) -> t.MappingKV[str, t.Scalar | t.ScalarList] | None:
        """Normalize metadata for Entry model validation.

        Business Rules:
            - Filters to types accepted by ServerMetadata: t.Primitives | None
            - String keys are required (filters out non-string keys)
            - Invalid value types are filtered out (preserves valid entries)
            - Handles dict, Mapping, and Pydantic models with model_dump()
            - Returns None if metadata is empty or invalid

        Audit Implications:
            - Metadata normalization ensures type safety for ServerMetadata
            - Invalid values are silently filtered (no errors raised)
            - Preserves valid metadata entries for server server tracking

        Architecture:
            - Uses guard-based type filtering
            - Uses Pydantic model_dump() for model serialization
            - Returns t.MappingKV[str, t.Primitives] or None

        Args:
            metadata: Raw metadata from entry (dict, Mapping, Pydantic model, or None).

        Returns:
            Normalized metadata dict or None if empty/invalid.

        """
        if not metadata:
            return None
        metadata_dict: t.MutableJsonMapping = {}
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
            if u.primitive(val):
                filtered[key] = val
        return filtered or None

    @staticmethod
    def process_entry_attributes(
        entry: p.Ldap.Ldap3Entry,
    ) -> t.MappingKV[str, t.StrSequence]:
        """Convert LDAP entry attributes to string-list mapping."""
        attrs_dict: t.MutableStrSequenceMapping = {}
        for attr, attr_values in entry.entry_attributes_as_dict.items():
            attrs_dict[attr] = [str(v) for v in attr_values]
        return attrs_dict


__all__: list[str] = ["ResultConverter"]
