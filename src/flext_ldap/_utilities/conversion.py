"""LDAP conversion utility methods."""

from __future__ import annotations

from collections.abc import MutableMapping

from flext_ldap import m, p, t
from flext_ldap._utilities.normalization import FlextLdapUtilitiesNormalization
from flext_ldif import r


class FlextLdapUtilitiesConversion(FlextLdapUtilitiesNormalization):
    """LDAP conversion metadata and entry conversion helpers."""

    @staticmethod
    def build_conversion_metadata(
        removed_attrs: t.StrSequence,
        base64_attrs: t.StrSequence,
        original_attrs_dict: t.MappingKV[str, t.JsonValue | t.Ldap.Ldap3AttributeValue],
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
            key: list(cls.ldap3_value_to_strings(value))
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


__all__: list[str] = ["FlextLdapUtilitiesConversion"]
