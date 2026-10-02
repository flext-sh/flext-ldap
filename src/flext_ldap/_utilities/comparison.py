"""LDAP entry comparison utility methods.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import FlextLdifUtilities, r

from flext_ldap import c, t

if TYPE_CHECKING:
    # Reverse import: protocols are annotation-only here. A runtime import
    # re-enters the lazy ``p`` resolution (p -> utilities -> p) and breaks
    # every import of the api facade.
    from flext_ldap import p

from flext_ldap._utilities.normalization import FlextLdapUtilitiesNormalization


class FlextLdapUtilitiesComparison(FlextLdapUtilitiesNormalization):
    """LDAP entry comparison helpers."""

    @classmethod
    def extract_entry_attributes(
        cls,
        entry: p.Ldif.Entry,
    ) -> t.MappingKV[str, t.StrSequence]:
        """Normalize entry attributes to the canonical LDAP comparison mapping.

        Returns:
            The resulting ``t.MappingKV[str, t.StrSequence]`` value.

        """
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
        """Resolve attribute values by case-insensitive LDAP name matching.

        Returns:
            The resulting ``t.StrSequence | None`` value.

        """
        normalized_target = cls.norm_str(attr_name, case="lower")
        for key, values in existing_attrs.items():
            if cls.norm_str(key, case="lower") == normalized_target:
                return list(values)
        return None

    @staticmethod
    def normalize_value_set(values: t.StrSequence) -> set[str]:
        """Normalize LDAP attribute values for stable comparison.

        Returns:
            The resulting ``set[str]`` value.

        """
        return {value.lower() for value in values if value}

    @classmethod
    def process_new_attributes(
        cls,
        new_attrs: t.MappingKV[str, t.StrSequence],
        existing_attrs: t.MappingKV[str, t.StrSequence],
        ignore: frozenset[str],
    ) -> t.Pair[t.Ldap.OperationChanges, set[str]]:
        """Build replacement changes for non-operational attributes.

        Returns:
            The resulting ``t.Pair[t.Ldap.OperationChanges, set[str]]`` value.

        """
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
        """Build delete operations for attributes absent from the target entry.

        Returns:
            The resulting ``t.Ldap.OperationChanges`` value.

        """
        empty_values: t.StrSequence = []
        ignored = {value.lower() for value in ignore}
        return {
            attr_name: [(c.Ldap.ModifyOperation.DELETE, empty_values)]
            for attr_name in existing_attrs
            if cls.norm_str(attr_name, case="lower") not in ignored
            and cls.norm_str(attr_name, case="lower") not in processed
        }

    @classmethod
    def rdn_attribute_names(cls, entry: p.Ldif.Entry) -> p.Result[frozenset[str]]:
        """Lowercased attribute names of the entry DN's leading RDN (RFC 4514).

        Returns:
            The resulting ``p.Result[frozenset[str]]`` value.

        """
        if entry.dn is None:
            return r[frozenset[str]].fail("Entry has no DN")
        components = FlextLdifUtilities.Ldif.split(entry.dn.value)
        if not components:
            return r[frozenset[str]].fail(
                f"Entry DN has no RDN components: '{entry.dn.value}'",
            )
        parsed = FlextLdifUtilities.Ldif.parse_rdn(components[0])
        if parsed.failure:
            return r[frozenset[str]].fail_op("Entry DN RDN parse", parsed.error)
        return parsed.map(
            lambda pairs: frozenset(
                cls.norm_str(attr_name, case="lower") for attr_name, _value in pairs
            ),
        )

    @classmethod
    def compare_entries(
        cls,
        existing_entry: p.Ldif.Entry,
        new_entry: p.Ldif.Entry,
    ) -> p.Result[t.Ldap.OperationChanges]:
        """Compare canonical LDIF entries and return LDAP modify operations.

        RDN attributes derived from the entry DN are excluded from the change
        set: LDAP modify can never change an entry's RDN (notAllowedOnRDN).

        Returns:
            The resulting ``p.Result[t.Ldap.OperationChanges]`` value.

        """
        existing_rdn_result = cls.rdn_attribute_names(existing_entry)
        if existing_rdn_result.failure:
            return r[t.Ldap.OperationChanges].fail_op(
                "Existing entry DN RDN parse",
                existing_rdn_result.error,
            )
        new_rdn_result = cls.rdn_attribute_names(new_entry)
        if new_rdn_result.failure:
            return r[t.Ldap.OperationChanges].fail_op(
                "New entry DN RDN parse",
                new_rdn_result.error,
            )
        ignore = (
            c.Ldif.OperationalAttributes.IGNORE_SET
            | existing_rdn_result.value
            | new_rdn_result.value
        )
        existing_attrs = cls.extract_entry_attributes(existing_entry)
        if not existing_attrs:
            return r[t.Ldap.OperationChanges].fail(
                "Existing entry has no attributes to compare",
            )
        new_attrs = cls.extract_entry_attributes(new_entry)
        if not new_attrs:
            return r[t.Ldap.OperationChanges].fail(
                "New entry has no attributes to compare",
            )
        changes, processed = cls.process_new_attributes(
            new_attrs,
            existing_attrs,
            ignore,
        )
        changes.update(
            cls.process_deleted_attributes(existing_attrs, ignore, processed),
        )
        return r[t.Ldap.OperationChanges].ok(changes)


__all__: list[str] = ["FlextLdapUtilitiesComparison"]
