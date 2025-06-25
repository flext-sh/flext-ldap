"""LDIF Validator - Comprehensive LDIF validation and verification.

This module provides enterprise-grade LDIF validation capabilities including
format validation, content verification, and schema compliance checking.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.domain.results import LDAPValidationResult

if TYPE_CHECKING:
    from pathlib import Path

    from ldap_core_shared.ldif.processor import LDIFEntry

logger = logging.getLogger(__name__)


class LDIFValidationConfig(BaseModel):
    """Configuration for LDIF validation operations."""

    model_config = ConfigDict(strict=True, extra="forbid")

    validate_dn_format: bool = Field(default=True, description="Validate DN format")
    validate_attribute_syntax: bool = Field(
        default=True,
        description="Validate attribute syntax",
    )
    validate_object_classes: bool = Field(
        default=True,
        description="Validate object class consistency",
    )
    validate_required_attributes: bool = Field(
        default=True,
        description="Check required attributes",
    )
    allow_binary_attributes: bool = Field(
        default=True,
        description="Allow binary attribute values",
    )
    max_dn_length: int = Field(default=8192, ge=1, description="Maximum DN length")
    max_attribute_length: int = Field(
        default=65536,
        ge=1,
        description="Maximum attribute value length",
    )


class LDIFValidator:
    """Enterprise-grade LDIF validator with comprehensive checks."""

    def __init__(self, config: LDIFValidationConfig | None = None) -> None:
        """Initialize LDIF validator with configuration."""
        self.config = config or LDIFValidationConfig()

    def validate_file(self, file_path: Path | str) -> LDAPValidationResult:
        """Validate complete LDIF file."""
        try:
            from ldap_core_shared.ldif.processor import LDIFProcessor

            processor = LDIFProcessor()
            result = processor.parse_file(file_path)

            if not result.success:
                return LDAPValidationResult(
                    is_valid=False,
                    error_count=1,
                    errors=[f"Parse failed: {result.error_message}"],
                )

            return self.validate_entries(result.data or [])

        except Exception as e:
            logger.exception(f"File validation failed: {file_path}")
            return LDAPValidationResult(
                is_valid=False,
                error_count=1,
                errors=[f"Validation error: {e!s}"],
            )

    def validate_entries(self, entries: list[LDIFEntry]) -> LDAPValidationResult:
        """Validate list of LDIF entries."""
        errors = []
        warnings = []

        for i, entry in enumerate(entries):
            entry_result = self.validate_entry(entry)
            if not entry_result.is_valid:
                for error in entry_result.errors:
                    errors.append(f"Entry {i} ({entry.dn}): {error}")
            warnings.extend(
                [f"Entry {i} ({entry.dn}): {w}" for w in entry_result.warnings],
            )

        return LDAPValidationResult(
            is_valid=len(errors) == 0,
            error_count=len(errors),
            warning_count=len(warnings),
            errors=errors,
            warnings=warnings,
        )

    def validate_entry(self, entry: LDIFEntry) -> LDAPValidationResult:
        """Validate single LDIF entry."""
        errors = []
        warnings = []

        # Validate DN
        if self.config.validate_dn_format:
            dn_errors = self._validate_dn(entry.dn)
            errors.extend(dn_errors)

        # Validate attributes
        if self.config.validate_attribute_syntax:
            attr_errors, attr_warnings = self._validate_attributes(entry.attributes)
            errors.extend(attr_errors)
            warnings.extend(attr_warnings)

        # Validate object classes
        if self.config.validate_object_classes:
            oc_errors = self._validate_object_classes(entry)
            errors.extend(oc_errors)

        return LDAPValidationResult(
            is_valid=len(errors) == 0,
            error_count=len(errors),
            warning_count=len(warnings),
            errors=errors,
            warnings=warnings,
        )

    def _validate_dn(self, dn: str) -> list[str]:
        """Validate DN format according to RFC 2253."""
        errors = []

        if not dn:
            errors.append("DN is empty")
            return errors

        if len(dn) > self.config.max_dn_length:
            errors.append(
                f"DN exceeds maximum length: {len(dn)} > {self.config.max_dn_length}",
            )

        # Check basic DN format
        if "=" not in dn:
            errors.append("DN must contain at least one attribute=value pair")

        # Validate RDN components
        rdns = [rdn.strip() for rdn in dn.split(",")]
        for i, rdn in enumerate(rdns):
            if not rdn:
                errors.append(f"Empty RDN component at position {i}")
                continue

            if "=" not in rdn:
                errors.append(f"RDN component missing '=' at position {i}: {rdn}")

            # Basic attribute name validation
            parts = rdn.split("=", 1)
            if len(parts) == 2:
                attr_name = parts[0].strip()
                if not attr_name:
                    errors.append(f"Empty attribute name in RDN at position {i}")
                elif not re.match(r"^[a-zA-Z][a-zA-Z0-9-]*$", attr_name):
                    errors.append(f"Invalid attribute name format in RDN: {attr_name}")

        return errors

    def _validate_attributes(
        self,
        attributes: dict[str, list[str]],
    ) -> tuple[list[str], list[str]]:
        """Validate entry attributes."""
        errors = []
        warnings = []

        for attr_name, attr_values in attributes.items():
            # Validate attribute name
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9-]*$", attr_name):
                errors.append(f"Invalid attribute name format: {attr_name}")

            # Validate attribute values
            for value in attr_values:
                if len(value) > self.config.max_attribute_length:
                    errors.append(
                        f"Attribute '{attr_name}' value exceeds maximum length: "
                        f"{len(value)} > {self.config.max_attribute_length}",
                    )

                # Check for potential binary content
                if not self.config.allow_binary_attributes:
                    try:
                        value.encode("ascii")
                    except UnicodeEncodeError:
                        errors.append(
                            f"Binary content not allowed in attribute '{attr_name}'",
                        )

        return errors, warnings

    def _validate_object_classes(self, entry: LDIFEntry) -> list[str]:
        """Validate object class consistency."""
        errors = []

        object_classes = entry.get_object_classes()
        if not object_classes:
            errors.append("Entry must have at least one objectClass")
            return errors

        # Check for common object class validation rules
        # (This would be expanded with actual schema validation)

        return errors
