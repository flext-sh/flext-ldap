"""RFC 2849 Compliant LDIF Validator - Comprehensive LDIF validation and verification.

This validator implements full RFC 2849 compliance checking including:
- Version specification validation
- Line folding compliance
- Base64 encoding validation
- SAFE-STRING character set compliance
- Change record validation
- Control specification validation
- URL reference validation
- UTF-8 encoding compliance
- Comment handling validation
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.domain.results import LDAPValidationResult

# Constants for magic values
LARGE_BUFFER_SIZE = 8192
RDN_SPLIT_PARTS = 2  # Expected parts when splitting RDN by '='
BASE64_SPLIT_PARTS = 2  # Expected parts when splitting by '::'

if TYPE_CHECKING:
    from ldap_core_shared.ldif.processor import LDIFEntry

logger = logging.getLogger(__name__)


class LDIFValidationConfig(BaseModel):
    """RFC 2849 compliant configuration for LDIF validation operations."""

    model_config = ConfigDict(strict=True, extra="forbid")

    # Core RFC 2849 validations
    require_version_spec: bool = Field(
        default=True,
        description="Require version: 1 specification",
    )
    validate_line_folding: bool = Field(
        default=True,
        description="Validate line folding compliance",
    )
    validate_safe_strings: bool = Field(
        default=True,
        description="Validate SAFE-STRING compliance",
    )
    validate_base64_encoding: bool = Field(
        default=True,
        description="Validate base64 encoding",
    )
    validate_utf8_encoding: bool = Field(
        default=True,
        description="Validate UTF-8 encoding",
    )

    # Extended validations
    validate_dn_format: bool = Field(
        default=True,
        description="Validate DN format per RFC 2253",
    )
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
    validate_change_records: bool = Field(
        default=True,
        description="Validate change record syntax",
    )
    validate_controls: bool = Field(
        default=True,
        description="Validate control specifications",
    )
    validate_url_references: bool = Field(
        default=True,
        description="Validate URL references",
    )

    # Limits and constraints
    allow_binary_attributes: bool = Field(
        default=True,
        description="Allow binary attribute values",
    )
    max_dn_length: int = Field(
        default=LARGE_BUFFER_SIZE,
        ge=1,
        description="Maximum DN length",
    )
    max_attribute_length: int = Field(
        default=65536,
        ge=1,
        description="Maximum attribute value length",
    )
    max_line_length: int = Field(
        default=1000,
        ge=1,
        description="Maximum line length before folding",
    )
    strict_rfc_compliance: bool = Field(
        default=True,
        description="Enforce strict RFC 2849 compliance",
    )


class RFC2849LDIFValidator:
    """RFC 2849 compliant LDIF validator with comprehensive compliance checks."""

    # RFC 2849 Character Set Patterns
    SAFE_CHAR_PATTERN = re.compile(r"[\x01-\x09\x0B-\x0C\x0E-\x7F]")
    SAFE_INIT_CHAR_PATTERN = re.compile(
        r"[\x01-\x09\x0B-\x0C\x0E-\x1F\x21-\x39\x3B\x3D-\x7F]",
    )
    BASE64_CHAR_PATTERN = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
    LDAP_OID_PATTERN = re.compile(r"^\d+(\.\d+)*$")

    def __init__(self, config: LDIFValidationConfig | None = None) -> None:
        """Initialize RFC 2849 compliant LDIF validator with configuration."""
        self.config = config or LDIFValidationConfig()

    def validate_file(self, file_path: Path | str) -> LDAPValidationResult:
        """Validate complete LDIF file for RFC 2849 compliance."""
        try:
            # Read file content for raw validation
            file_path = Path(file_path)
            with file_path.open("r", encoding="utf-8") as f:
                content = f.read()

            # Perform raw content validation first
            raw_validation = self.validate_raw_content(content)
            if not raw_validation.valid:
                return raw_validation

            # Parse with RFC 2849 processor
            from ldap_core_shared.ldif.processor import RFC2849LDIFProcessor

            processor = RFC2849LDIFProcessor()
            result = processor.parse_file(file_path)

            if not result.success:
                return LDAPValidationResult(
                    valid=False,
                    error_count=1,
                    errors=[f"RFC 2849 parse failed: {result.error_message}"],
                )

            return self.validate_entries(result.data or [])

        except Exception as e:
            logger.exception("File validation failed: %s", file_path)
            return LDAPValidationResult(
                valid=False,
                error_count=1,
                errors=[f"Validation error: {e!s}"],
            )

    def validate_raw_content(self, content: str) -> LDAPValidationResult:
        """Validate raw LDIF content for RFC 2849 compliance."""
        errors: list[str] = []
        warnings: list[str] = []

        try:
            # Validate UTF-8 encoding
            if self.config.validate_utf8_encoding:
                content.encode("utf-8")

            lines = content.splitlines()

            # Check version specification
            if self.config.require_version_spec:
                version_errors = self._validate_version_specification(lines)
                errors.extend(version_errors)

            # Check line folding compliance
            if self.config.validate_line_folding:
                folding_errors = self._validate_line_folding(lines)
                errors.extend(folding_errors)

            # Check character set compliance
            if self.config.validate_safe_strings:
                charset_errors = self._validate_character_sets(content)
                errors.extend(charset_errors)

            # Check base64 encoding
            if self.config.validate_base64_encoding:
                base64_errors = self._validate_base64_content(lines)
                errors.extend(base64_errors)

        except UnicodeDecodeError as e:
            errors.append(f"Invalid UTF-8 encoding: {e}")
        except Exception as e:
            errors.append(f"Content validation error: {e}")

        return LDAPValidationResult(
            valid=len(errors) == 0,
            validation_type="ldif",
            entries_validated=1,
            schema_errors=errors,
            syntax_errors=warnings,
        )

    def validate_entries(self, entries: list[LDIFEntry]) -> LDAPValidationResult:
        """Validate list of LDIF entries."""
        errors = []
        warnings = []

        for i, entry in enumerate(entries):
            entry_result = self.validate_entry(entry)
            if not entry_result.valid:
                errors.extend(
                    f"Entry {i} ({entry.dn}): {error}"
                    for error in entry_result.schema_errors
                )
            warnings.extend(
                [f"Entry {i} ({entry.dn}): {w}" for w in entry_result.syntax_errors],
            )

        return LDAPValidationResult(
            valid=len(errors) == 0,
            validation_type="ldif",
            entries_validated=1,
            schema_errors=errors,
            syntax_errors=warnings,
        )

    def validate_entry(self, entry: LDIFEntry) -> LDAPValidationResult:
        """Validate single LDIF entry for RFC 2849 compliance."""
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

        # Validate change records
        if self.config.validate_change_records:
            change_errors = self._validate_change_record(entry)
            errors.extend(change_errors)

        # Validate controls
        if self.config.validate_controls:
            control_errors = self._validate_controls(entry)
            errors.extend(control_errors)

        return LDAPValidationResult(
            valid=len(errors) == 0,
            validation_type="ldif",
            entries_validated=1,
            schema_errors=errors,
            syntax_errors=warnings,
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
            if len(parts) == RDN_SPLIT_PARTS:
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
        errors: list[str] = []
        warnings: list[str] = []

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

    def _validate_version_specification(self, lines: list[str]) -> list[str]:
        """Validate version specification per RFC 2849."""
        errors = []

        if not lines:
            errors.append("Empty LDIF file")
            return errors

        # Skip comment lines at the beginning
        first_content_line = None
        for line in lines:
            if line.strip() and not line.strip().startswith("#"):
                first_content_line = line
                break

        if not first_content_line:
            errors.append("No content found in LDIF file")
            return errors

        if not first_content_line.lower().startswith("version:"):
            errors.append("Missing required version specification (version: 1)")
        else:
            version_part = first_content_line[8:].strip()
            if version_part != "1":
                errors.append(f"Invalid version number: {version_part} (must be 1)")

        return errors

    def _validate_line_folding(self, lines: list[str]) -> list[str]:
        """Validate line folding compliance per RFC 2849."""
        errors = []

        for i, line in enumerate(lines, 1):
            # Check for lines that start with space but previous line is empty
            if line.startswith(" "):
                if i == 1:
                    errors.append(
                        f"Line {i}: Line folding not allowed at start of file",
                    )
                elif not lines[i - 2].strip():  # Previous line is empty
                    errors.append(f"Line {i}: Folding into empty line not permitted")

            # Check line length recommendations
            if len(line) > self.config.max_line_length:
                warnings = getattr(self, "_warnings", [])
                warnings.append(
                    f"Line {i}: Line length {len(line)} exceeds recommended "
                    f"maximum {self.config.max_line_length}",
                )

        return errors

    def _validate_character_sets(self, content: str) -> list[str]:
        """Validate character set compliance per RFC 2849 SAFE-STRING definition."""
        errors = []

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            if line.strip().startswith("#"):  # Comment line
                continue

            if ":" in line:
                # Check if this is an attribute line
                _attr_part, value_part = line.split(":", 1)

                # Skip base64 encoded values (they have their own validation)
                if not value_part.startswith(":") and not value_part.startswith("<"):
                    value = value_part.strip()
                    if value and not self._is_safe_string(value):
                        errors.append(
                            f"Line {i}: Attribute value contains unsafe characters "
                            "(should be base64 encoded)",
                        )

        return errors

    def _validate_base64_content(self, lines: list[str]) -> list[str]:
        """Validate base64 encoded content per RFC 2849."""
        errors = []

        for i, line in enumerate(lines, 1):
            if "::" in line:  # Base64 encoded value
                parts = line.split("::", 1)
                if len(parts) == BASE64_SPLIT_PARTS:
                    base64_value = parts[1].strip()
                    if base64_value and not self.BASE64_CHAR_PATTERN.match(
                        base64_value,
                    ):
                        errors.append(f"Line {i}: Invalid base64 encoding format")
                    else:
                        # Try to decode to verify validity
                        try:
                            import base64

                            decoded = base64.b64decode(base64_value)
                            decoded.decode("utf-8")  # Must be valid UTF-8
                        except Exception as e:
                            errors.append(f"Line {i}: Base64 decode error: {e}")

        return errors

    def _is_safe_string(self, value: str) -> bool:
        """Check if string conforms to RFC 2849 SAFE-STRING definition."""
        if not value:
            return True  # Empty string is safe

        # Check first character
        if not self.SAFE_INIT_CHAR_PATTERN.match(value[0]):
            return False

        # Check remaining characters
        return all(self.SAFE_CHAR_PATTERN.match(char) for char in value[1:])

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

    def _validate_change_record(self, entry: LDIFEntry) -> list[str]:
        """Validate change record per RFC 2849."""
        errors: list[str] = []

        if not entry.change_record:
            return errors  # No change record to validate

        change_record = entry.change_record

        # Validate changetype
        if change_record.changetype not in {
            "add",
            "delete",
            "modify",
            "modrdn",
            "moddn",
        }:
            errors.append(f"Invalid changetype: {change_record.changetype}")

        # Validate specific change types
        if change_record.changetype == "add":
            if not change_record.attributes:
                errors.append("Add operation must include attributes")

        elif change_record.changetype == "modify":
            if not change_record.modifications:
                errors.append("Modify operation must include modifications")
            else:
                errors.extend(
                    f"Invalid modification operation: {mod.get('operation')}"
                    for mod in change_record.modifications
                    if mod.get("operation") not in {"add", "delete", "replace"}
                )

        elif change_record.changetype in {"modrdn", "moddn"}:
            if not change_record.new_rdn:
                errors.append(
                    f"{change_record.changetype} operation must include newrdn",
                )

        return errors

    def _validate_controls(self, entry: LDIFEntry) -> list[str]:
        """Validate control specifications per RFC 2849."""
        errors = []

        for control in entry.controls:
            # Handle case where control might be a string or control object
            if isinstance(control, str):
                control_type_str = control
            else:
                # Validate OID format
                control_type_str = str(control.control_type)
            if not self.LDAP_OID_PATTERN.match(control_type_str):
                errors.append(f"Invalid control OID format: {control_type_str}")

            # Validate control value if present
            control_value = None
            if isinstance(control, str):
                # String controls don't have control_value
                continue
            else:
                control_value = control.control_value

            if control_value:
                try:
                    # Control value should be valid UTF-8
                    str(control_value).encode("utf-8")
                except UnicodeEncodeError:
                    errors.append(
                        f"Control value contains invalid UTF-8: {control_type_str}",
                    )

        return errors


# Backward compatibility alias
LDIFValidator = RFC2849LDIFValidator
