"""LDAP normalization utility methods."""

from __future__ import annotations

from collections.abc import Mapping

from flext_ldap import c, m, t


class FlextLdapUtilitiesNormalization:
    """LDAP string, DN, and attribute normalization helpers."""

    @classmethod
    def norm_in(
        cls,
        value: str,
        collection: t.StrSequence | t.VariadicTuple[str],
        *,
        case: str | None = None,
    ) -> bool:
        """Check whether a normalized value is present in a collection."""
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
        """Normalize and join string values."""
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
        value: (
            t.JsonValue
            | t.Ldap.Ldap3AttributeValue
            | t.Ldap.Ldap3EntryValue
            | t.StrSequence
        ),
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
            | t.MappingKV[str, t.Ldap.Ldap3EntryValue]
            | t.JsonMapping
            | t.MappingKV[str, t.StrSequence]
        ),
    ) -> t.MappingKV[str, t.StrSequence]:
        """Convert LDAP attributes into string sequences."""
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
        """Return True when a value requires LDIF base64 encoding."""
        return value.startswith("::") or any(ord(char) > threshold for char in value)

    @classmethod
    def normalize_original_attr_value(
        cls,
        value: t.Ldap.Ldap3EntryValue | None,
    ) -> t.StrSequence:
        """Normalize original ldap3 values while preserving list semantics."""
        return cls.ldap3_value_to_strings(value)

    @staticmethod
    def dn_str(
        dn: str | m.Ldif.DN | m.Ldif.Entry | None,
        *,
        default: str = c.Ldap.UNKNOWN_CATEGORY,
    ) -> str:
        """Extract a DN string from supported LDIF inputs."""
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
        """Filter truthy values from a list or mapping."""
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
        """Normalize a string collection and optionally join it."""
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
        """Normalize a string by the requested case."""
        if not value:
            return ""
        if case == "lower":
            return value.lower()
        if case == "upper":
            return value.upper()
        return value

    @staticmethod
    def when_safe(
        *,
        condition: bool,
        then_value: str | float | bool | None,
        else_value: str | float | bool | None = None,
        safe_then: bool = False,
    ) -> t.Primitives | None:
        """Return a safe conditional primitive value."""
        if condition:
            if safe_then and then_value is None:
                return else_value
            return then_value if then_value is not None else else_value
        return else_value


__all__: list[str] = ["FlextLdapUtilitiesNormalization"]
