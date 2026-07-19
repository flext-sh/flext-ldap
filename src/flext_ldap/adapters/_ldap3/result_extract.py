"""LDAP3 adapter — ResultConverter extract helpers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from flext_ldap import c, m, p, t
from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers


class ResultConverterExtractMixin:
    """Extraction helpers for DN, attributes, and metadata from LDAP entries."""

    @staticmethod
    def extract_dn(
        parsed: p.Ldif.Entry | p.Ldap.Ldap3Entry | t.JsonValue,
    ) -> p.Ldif.DN:
        """Extract Distinguished Name from LDAP entry.

        Delegates to ``u.Ldif.get_dn_value()`` for normalization. Returns
        canonical empty DN via ``m.Ldif.DN.empty()`` when extraction fails.
        """
        if parsed is None:
            return m.Ldif.DN.empty()
        if isinstance(parsed, m.Ldif.Entry):
            return parsed.dn if parsed.dn is not None else m.Ldif.DN.empty()
        if isinstance(parsed, p.Ldap.Ldap3Entry):
            entry_dn = parsed.entry_dn
            if entry_dn is None:
                return m.Ldif.DN.empty()
            dn_with_value: p.Ldif.DN = m.Ldif.DN.empty().model_copy(
                update={"value": entry_dn},
            )
            return dn_with_value
        return m.Ldif.DN.empty()

    @staticmethod
    def extract_attributes(
        parsed: p.Ldif.Entry | p.Ldap.Ldap3Entry | t.JsonValue,
    ) -> p.Ldif.Attributes:
        """Extract LDAP attributes as ``m.Ldif.Attributes`` Pydantic model."""
        empty = m.Ldif.Attributes(
            attributes={},
            attribute_metadata={},
            metadata=None,
        )
        if parsed is None:
            return empty
        if isinstance(parsed, m.Ldif.Entry):
            return parsed.attributes if parsed.attributes is not None else empty
        if isinstance(parsed, p.Ldap.Ldap3Entry):
            attrs_dict = ResultConverterExtractMixin.extract_attrs_dict(
                parsed.entry_attributes_as_dict,
            )
            return m.Ldif.Attributes(
                attributes=attrs_dict,
                attribute_metadata={},
                metadata=None,
            )
        return empty

    @staticmethod
    def extract_attrs_dict(
        attrs: p.Ldap.HasAttributesProperty
        | t.MappingKV[str, t.Ldap.Ldap3EntryValue | t.JsonValue | t.StrSequence]
        | p.Ldap.HasItemsMethod
        | p.Ldif.Attributes
        | p.BaseModel
        | t.JsonValue,
    ) -> t.Ldap.OperationAttributes:
        """Normalize input formats to ``t.Ldap.OperationAttributes``."""
        if isinstance(attrs, p.Ldap.HasAttributesProperty):
            return ResultConverterExtractMixin._normalize_attr_values(attrs.attributes)
        if isinstance(attrs, m.BaseModel):
            model_attrs: t.MappingKV[str, t.Ldap.Ldap3EntryValue] | None = getattr(
                attrs,
                "attributes",
                None,
            )
            if model_attrs is not None:
                return ResultConverterExtractMixin._normalize_attr_values(model_attrs)
            return {}
        if isinstance(attrs, Mapping):
            return ResultConverterExtractMixin._normalize_attr_values(attrs)
        return {}

    @staticmethod
    def extract_metadata(
        parsed: p.Ldif.Entry | p.Ldap.Ldap3Entry | t.JsonValue,
    ) -> p.Ldif.ServerMetadata | None:
        """Extract server metadata from LDAP entry, returning ``None`` when absent."""
        match parsed:
            case None:
                result = None
            case m.Ldif.Entry():
                result = parsed.metadata
            case _:
                metadata_attr = getattr(parsed, "metadata", None)
                match metadata_attr:
                    case None:
                        result = None
                    case m.Ldif.ServerMetadata():
                        result = metadata_attr
                    case Mapping():
                        normalized = ResultConverterExtractMixin._normalize_metadata(
                            metadata_attr,
                        )
                        if normalized and isinstance(
                            normalized.get("server_type"),
                            str,
                        ):
                            result = m.Ldif.ServerMetadata(
                                server_type=c.Ldif.ServerTypes(
                                    str(normalized["server_type"])
                                ),
                            )
                        else:
                            result = None
                    case _:
                        result = None
        return result

    @staticmethod
    def _normalize_attr_values(
        attrs_dict: t.MappingKV[
            str,
            t.Ldap.Ldap3EntryValue | t.JsonValue | t.StrSequence,
        ]
        | None,
    ) -> t.Ldap.OperationAttributes:
        """Normalize attribute values to ``t.StrSequence`` format."""
        if attrs_dict is None:
            return {}
        result: t.MutableStrSequenceMapping = {}
        for k, v in attrs_dict.items():
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
    def _normalize_metadata(
        metadata: t.MappingKV[str, t.Scalar | None] | None,
    ) -> t.MappingKV[str, t.Scalar | t.ScalarList] | None:
        """Filter metadata to ``ServerMetadata``-compatible primitive values."""
        if not metadata:
            return None
        metadata_dict: t.MutableMappingKV[str, t.Scalar | t.ScalarList] = {}
        for raw_key, raw_value in metadata.items():
            if isinstance(raw_value, t.PRIMITIVES_TYPES):
                metadata_dict[raw_key] = raw_value
        return metadata_dict or None


__all__: list[str] = ["ResultConverterExtractMixin"]
