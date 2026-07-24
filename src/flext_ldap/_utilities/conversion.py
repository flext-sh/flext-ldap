"""LDAP conversion utility methods."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldap import c, m, p, t
from flext_ldap._utilities.normalization import FlextLdapUtilitiesNormalization
from flext_ldif import r

if TYPE_CHECKING:
    from collections.abc import MutableMapping


class FlextLdapUtilitiesConversion(FlextLdapUtilitiesNormalization):
    """LDAP conversion metadata and entry conversion helpers."""

    @staticmethod
    def build_conversion_metadata(
        removed_attrs: t.StrSequence,
        base64_attrs: t.StrSequence,
        original_attrs_dict: t.MappingKV[str, t.JsonValue | t.Ldap.Ldap3AttributeValue],
        original_dn: str,
    ) -> p.Ldap.ConversionMetadata:
        """Create canonical conversion metadata for LDAP entry adaptation."""
        return m.Ldap.ConversionMetadata(
            source_attributes=list(dict(original_attrs_dict).keys()),
            source_dn=original_dn,
            removed_attributes=list(removed_attrs),
            base64_encoded_attributes=list(set(base64_attrs)),
        )

    @classmethod
    def search_entry_to_ldif_entry(
        cls, entry: t.MappingKV[str, t.Ldap.Ldap3AttributeValue | t.JsonValue]
    ) -> p.Result[p.Ldif.Entry]:
        """Convert LDAP search-result mappings into canonical LDIF entries."""
        raw_entry = dict(entry)
        dn_raw = raw_entry.get("dn")
        dn_values = cls.ldap3_value_to_strings(dn_raw)
        if not dn_values:
            return r[p.Ldif.Entry].fail("Search entry missing DN")
        dn_value = dn_values[0]
        attributes: MutableMapping[str, t.MutableSequenceOf[str] | str] = {
            key: list(cls.ldap3_value_to_strings(value))
            for key, value in raw_entry.items()
            if key != "dn"
        }
        return m.Ldif.Entry.create(dn=dn_value, attributes=attributes)

    @classmethod
    def track_conversion_differences(
        cls,
        conversion_metadata: p.Ldap.ConversionMetadata,
        *,
        original_dn: str,
        converted_dn: str,
        original_attrs_dict: t.Ldap.Ldap3AttributeDict,
        converted_attrs_dict: t.MappingKV[str, t.StrSequence],
    ) -> p.Ldap.ConversionMetadata:
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

    # NOTE (multi-agent): mro-wgwh.2 — entry attribute/category behavior moved here
    # from m.Ldap.SearchResult (models facet is declaration-only); get_entry_category
    # composes the two extractions, killing the duplicated objectClass logic.
    @staticmethod
    def extract_attrs_dict_from_entry(
        entry: p.Ldif.Entry,
    ) -> t.MutableStrSequenceMapping:
        """Extract the plain attributes mapping from an LDIF entry."""
        attributes = entry.attributes
        if attributes is None:
            return {}
        return attributes.attributes

    @staticmethod
    def extract_objectclass_category(attrs: t.AttributeMapping) -> str:
        """Extract the lowercase objectclass category from an attribute mapping."""
        unknown: str = c.Ldap.UNKNOWN_CATEGORY
        if not attrs:
            return unknown
        oc_list = attrs.get("objectClass", attrs.get("objectclass", []))
        if isinstance(oc_list, list) and oc_list:
            return str(oc_list[0]).lower()
        return unknown

    @classmethod
    def get_entry_category(cls, entry: p.Ldif.Entry) -> str:
        """Get the category (first objectclass, lowercased) of an LDIF entry."""
        return cls.extract_objectclass_category(
            cls.extract_attrs_dict_from_entry(entry)
        )

    @classmethod
    def group_entries_by_objectclass(
        cls, entries: t.SequenceOf[p.Ldif.Entry]
    ) -> p.Ldif.FlexibleCategories:
        """Group LDIF entries by their objectclass category."""
        result = m.Ldif.FlexibleCategories()
        for entry in entries:
            result[cls.get_entry_category(entry)].append(entry)
        return result


__all__: list[str] = ["FlextLdapUtilitiesConversion"]
