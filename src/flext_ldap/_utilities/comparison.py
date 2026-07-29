"""LDAP entry comparison utility methods."""

from __future__ import annotations

from flext_ldap import c, p, t
from flext_ldap._utilities.normalization import FlextLdapUtilitiesNormalization
from flext_ldif import r


class FlextLdapUtilitiesComparison(FlextLdapUtilitiesNormalization):
    """LDAP entry comparison helpers."""

    @classmethod
    def extract_entry_attributes(
        cls, entry: p.Ldif.Entry
    ) -> t.MappingKV[str, t.StrSequence]:
        """Normalize entry attributes to the canonical LDAP comparison mapping."""
        attrs = entry.attributes
        if attrs is None:
            return {}
        return cls.attr_to_str_list(attrs.attributes)

    @classmethod
    def find_existing_values(
        cls, attr_name: str, existing_attrs: t.MappingKV[str, t.StrSequence]
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
                changes[attr_name] = [(c.Ldap.ModifyOperation.REPLACE, new_values)]
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
        cls, existing_entry: p.Ldif.Entry, new_entry: p.Ldif.Entry
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
            new_attrs, existing_attrs, c.Ldif.OperationalAttributes.IGNORE_SET
        )
        changes.update(
            cls.process_deleted_attributes(
                existing_attrs, c.Ldif.OperationalAttributes.IGNORE_SET, processed
            )
        )
        return r[t.Ldap.OperationChanges].ok(changes)


__all__: list[str] = ["FlextLdapUtilitiesComparison"]
