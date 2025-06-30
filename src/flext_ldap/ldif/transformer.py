from __future__ import annotations

from flext_ldap.utils.constants import DEFAULT_MAX_ITEMS

"""LDIF Transformer - Advanced entry transformation and filtering."""


import logging
import re
from typing import TYPE_CHECKING, Any

from flext_ldapsor import LDIFEntry
from pydantic import BaseModel, ConfigDict, Field

# Constants for magic values

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


class TransformationRule(BaseModel):
    """Rule for transforming LDIF entries and attributes."""

    model_config = ConfigDict(strict=True, extra="forbid")

    name: str = Field(..., description="Rule name")
    description: str = Field(default="", description="Rule description")
    enabled: bool = Field(default=True, description="Whether rule is enabled")
    priority: int = Field(
        default=DEFAULT_MAX_ITEMS,
        description="Rule priority (lower = higher priority)",
    )


class AttributeTransformRule(TransformationRule):
    """Rule for transforming attribute values."""

    source_attribute: str = Field(..., description="Source attribute name")
    target_attribute: str | None = Field(
        default=None,
        description="Target attribute name (None = same as source)",
    )
    transformation_type: str = Field(..., description="Type of transformation")
    transformation_params: dict[str, Any] = Field(
        default_factory=dict,
        description="Transformation parameters",
    )


class EntryFilterRule(TransformationRule):
    """Rule for filtering entries."""

    filter_type: str = Field(..., description="Type of filter")
    filter_params: dict[str, Any] = Field(
        default_factory=dict,
        description="Filter parameters",
    )
    include_matches: bool = Field(
        default=True,
        description="Include matching entries (True) or exclude them (False)",
    )


class LDIFTransformer:
    """Advanced LDIF transformer for entry and attribute manipulation."""

    def __init__(self) -> None:
        """Initialize LDIF transformer."""
        self._attribute_rules: list[AttributeTransformRule] = []
        self._filter_rules: list[EntryFilterRule] = []

    def add_attribute_rule(self, rule: AttributeTransformRule) -> None:
        """Add attribute transformation rule."""
        self._attribute_rules.append(rule)
        self._attribute_rules.sort(key=lambda r: r.priority)

    def add_filter_rule(self, rule: EntryFilterRule) -> None:
        """Add entry filter rule."""
        self._filter_rules.append(rule)
        self._filter_rules.sort(key=lambda r: r.priority)

    def transform_entries(
        self,
        entries: list[LDIFEntry],
    ) -> LDAPOperationResult[list[LDIFEntry]]:
        """Transform list of LDIF entries according to configured rules.

        Args:
            entries: List of entries to transform

        Returns:
            Operation result with transformed entries
        """
        try:
            transformed_entries = []

            for entry in entries:
                # Apply filters first
                if self._should_include_entry(entry):
                    # Apply attribute transformations
                    transformed_entry = self._transform_entry_attributes(entry)
                    transformed_entries.append(transformed_entry)

            return LDAPOperationResult[list[LDIFEntry]](
                success=True,
                data=transformed_entries,
                operation="transform_entries",
                metadata={
                    "input_count": len(entries),
                    "output_count": len(transformed_entries),
                    "filtered_count": len(entries) - len(transformed_entries),
                },
            )

        except Exception as e:
            logger.exception("Failed to transform entries")
            return LDAPOperationResult[list[LDIFEntry]](
                success=False,
                error_message=f"Transformation failed: {e!s}",
                operation="transform_entries",
            )

    def filter_entries_by_dn_pattern(
        self,
        entries: list[LDIFEntry],
        pattern: str,
        include_matches: bool = True,
    ) -> list[LDIFEntry]:
        """Filter entries by DN pattern.

        Args:
            entries: List of entries to filter
            pattern: Regex pattern to match against DNs
            include_matches: Include matching entries (True) or exclude them (False)

        Returns:
            Filtered list of entries
        """
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            filtered = []

            for entry in entries:
                matches = bool(compiled_pattern.search(entry.dn))
                if matches == include_matches:
                    filtered.append(entry)

            return filtered

        except re.error:
            logger.exception("Invalid regex pattern '{pattern}': {e}")
            return entries

    def filter_entries_by_object_class(
        self,
        entries: list[LDIFEntry],
        object_classes: list[str],
        include_matches: bool = True,
    ) -> list[LDIFEntry]:
        """Filter entries by object class.

        Args:
            entries: List of entries to filter
            object_classes: List of object classes to match
            include_matches: Include matching entries (True) or exclude them (False)

        Returns:
            Filtered list of entries
        """
        oc_set = {oc.lower() for oc in object_classes}
        filtered = []

        for entry in entries:
            entry_ocs = {oc.lower() for oc in entry.get_object_classes()}
            has_match = bool(oc_set.intersection(entry_ocs))

            if has_match == include_matches:
                filtered.append(entry)

        return filtered

    def transform_attribute_values(
        self,
        entries: list[LDIFEntry],
        attribute_name: str,
        transformer: Callable[[str], str],
    ) -> list[LDIFEntry]:
        """Transform values of specific attribute across all entries.

        Args:
            entries: List of entries to transform
            attribute_name: Name of attribute to transform
            transformer: Function to transform attribute values

        Returns:
            List of entries with transformed attributes
        """
        transformed = []

        for entry in entries:
            new_attributes = entry.attributes.copy()

            # Find attribute (case-insensitive)
            for attr_key in list(new_attributes.keys()):
                if attr_key.lower() == attribute_name.lower():
                    try:
                        new_values = [transformer(value) for value in new_attributes[attr_key]]
                        new_attributes[attr_key] = new_values
                    except Exception as e:
                        logger.warning(
                            "Failed to transform attribute %s in %s: %s",
                            attr_key,
                            entry.dn,
                            e,
                        )

            transformed.append(
                LDIFEntry(
                    dn=entry.dn,
                    attributes=new_attributes,
                    changetype=entry.changetype,
                    controls=entry.controls,
                ),
            )

        return transformed

    def rename_attribute(
        self,
        entries: list[LDIFEntry],
        old_name: str,
        new_name: str,
    ) -> list[LDIFEntry]:
        """Rename attribute across all entries.

        Args:
            entries: List of entries to modify
            old_name: Current attribute name
            new_name: New attribute name

        Returns:
            List of entries with renamed attributes
        """
        transformed = []

        for entry in entries:
            new_attributes = {}

            for attr_key, attr_values in entry.attributes.items():
                if attr_key.lower() == old_name.lower():
                    new_attributes[new_name] = attr_values
                else:
                    new_attributes[attr_key] = attr_values

            transformed.append(
                LDIFEntry(
                    dn=entry.dn,
                    attributes=new_attributes,
                    changetype=entry.changetype,
                    controls=entry.controls,
                ),
            )

        return transformed

    def remove_attributes(
        self,
        entries: list[LDIFEntry],
        attribute_names: list[str],
    ) -> list[LDIFEntry]:
        """Remove specified attributes from all entries.

        Args:
            entries: List of entries to modify
            attribute_names: List of attribute names to remove

        Returns:
            List of entries with attributes removed
        """
        remove_set = {name.lower() for name in attribute_names}
        transformed = []

        for entry in entries:
            new_attributes = {
                attr_key: attr_values
                for attr_key, attr_values in entry.attributes.items()
                if attr_key.lower() not in remove_set
            }

            transformed.append(
                LDIFEntry(
                    dn=entry.dn,
                    attributes=new_attributes,
                    changetype=entry.changetype,
                    controls=entry.controls,
                ),
            )

        return transformed

    def normalize_dns(
        self,
        entries: list[LDIFEntry],
        base_dn: str | None = None,
    ) -> list[LDIFEntry]:
        """Normalize DN formatting and optionally rebase DNs.

        Args:
            entries: List of entries to normalize
            base_dn: New base DN (optional)

        Returns:
            List of entries with normalized DNs
        """
        transformed = []

        for entry in entries:
            normalized_dn = self._normalize_dn(entry.dn)

            if base_dn:
                # Replace base DN
                dn_parts = normalized_dn.split(",")
                if len(dn_parts) > 1:
                    rdn = dn_parts[0]
                    normalized_dn = f"{rdn},{base_dn}"

            transformed.append(
                LDIFEntry(
                    dn=normalized_dn,
                    attributes=entry.attributes,
                    changetype=entry.changetype,
                    controls=entry.controls,
                ),
            )

        return transformed

    def _should_include_entry(self, entry: LDIFEntry) -> bool:
        """Check if entry should be included based on filter rules."""
        for rule in self._filter_rules:
            if not rule.enabled:
                continue

            matches = self._apply_filter_rule(entry, rule)
            if matches is not None:
                return matches == rule.include_matches

        return True

    def _apply_filter_rule(
        self,
        entry: LDIFEntry,
        rule: EntryFilterRule,
    ) -> bool | None:
        """Apply single filter rule to entry."""
        try:
            if rule.filter_type == "dn_pattern":
                pattern = rule.filter_params.get("pattern", "")
                return bool(re.search(pattern, entry.dn, re.IGNORECASE))

            if rule.filter_type == "object_class":
                required_ocs = rule.filter_params.get("object_classes", [])
                entry_ocs = {oc.lower() for oc in entry.get_object_classes()}
                required_set = {oc.lower() for oc in required_ocs}
                return bool(required_set.intersection(entry_ocs))

            if rule.filter_type == "attribute_exists":
                attr_name = rule.filter_params.get("attribute_name", "")
                return entry.has_attribute(attr_name)

            if rule.filter_type == "attribute_value":
                attr_name = rule.filter_params.get("attribute_name", "")
                pattern = rule.filter_params.get("value_pattern", "")
                values = entry.get_attribute_values(attr_name)
                return any(re.search(pattern, value, re.IGNORECASE) for value in values)

        except Exception:
            logger.warning("Failed to apply filter rule {rule.name}: {e}")

        return None

    def _transform_entry_attributes(self, entry: LDIFEntry) -> LDIFEntry:
        """Apply attribute transformation rules to entry."""
        new_attributes = entry.attributes.copy()

        for rule in self._attribute_rules:
            if not rule.enabled:
                continue

            try:
                new_attributes = self._apply_attribute_rule(new_attributes, rule)
            except Exception as e:
                logger.warning(
                    "Failed to apply attribute rule %s to %s: %s",
                    rule.name,
                    entry.dn,
                    e,
                )

        return LDIFEntry(
            dn=entry.dn,
            attributes=new_attributes,
            changetype=entry.changetype,
            controls=entry.controls,
        )

    def _apply_attribute_rule(
        self,
        attributes: dict[str, list[str]],
        rule: AttributeTransformRule,
    ) -> dict[str, list[str]]:
        """Apply single attribute transformation rule."""
        source_attr = rule.source_attribute.lower()
        target_attr = (rule.target_attribute or rule.source_attribute).lower()

        # Find source attribute (case-insensitive)
        source_values = None
        source_key = None
        for attr_key, attr_values in attributes.items():
            if attr_key.lower() == source_attr:
                source_values = attr_values
                source_key = attr_key
                break

        if source_values is None:
            return attributes

        # Apply transformation
        if rule.transformation_type == "uppercase":
            new_values = [value.upper() for value in source_values]
        elif rule.transformation_type == "lowercase":
            new_values = [value.lower() for value in source_values]
        elif rule.transformation_type == "regex_replace":
            pattern = rule.transformation_params.get("pattern", "")
            replacement = rule.transformation_params.get("replacement", "")
            new_values = [re.sub(pattern, replacement, value) for value in source_values]
        elif rule.transformation_type == "prefix":
            prefix = rule.transformation_params.get("prefix", "")
            new_values = [f"{prefix}{value}" for value in source_values]
        elif rule.transformation_type == "suffix":
            suffix = rule.transformation_params.get("suffix", "")
            new_values = [f"{value}{suffix}" for value in source_values]
        else:
            return attributes

        # Update attributes
        new_attributes = attributes.copy()
        if source_key and target_attr != source_attr:
            # Rename attribute
            del new_attributes[source_key]
        new_attributes[target_attr] = new_values

        return new_attributes

    def _normalize_dn(self, dn: str) -> str:
        """Normalize DN format."""
        # Basic DN normalization - remove extra spaces
        parts = [part.strip() for part in dn.split(",")]
        return ",".join(parts)
