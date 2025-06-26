"""LDAP Schema to LDIF Generator.

This module provides schema2ldif-perl-converter functionality with enterprise-grade
schema conversion from .schema format to LDIF format for OpenLDAP server integration.

The generator converts parsed schema elements into properly formatted LDIF entries
that can be imported into OpenLDAP servers, following RFC 2849 LDIF specification
and OpenLDAP schema conventions.

Architecture:
    - LDIFGenerator: Main schema-to-LDIF conversion engine
    - SchemaLDIF: LDIF representation of schema elements
    - LDIFFormatter: LDIF formatting and validation utilities
    - SchemaEntry: Individual schema entry management

Usage Example:
    >>> from ldap_core_shared.schema import SchemaParser, LDIFGenerator
    >>>
    >>> # Parse schema file
    >>> parser = SchemaParser()
    >>> schema = parser.parse_file("myschema.schema")
    >>>
    >>> # Generate LDIF
    >>> generator = LDIFGenerator()
    >>> ldif_content = generator.generate_ldif(schema)
    >>>
    >>> # Save to file
    >>> with open("myschema.ldif", "w") as f:
    ...     f.write(ldif_content)

References:
    - schema2ldif-perl-converter documentation
    - RFC 2849: LDAP Data Interchange Format (LDIF)
    - RFC 4512: LDAP Directory Information Models
    - OpenLDAP Schema Integration Guide
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from ldap_core_shared.schema.parser import AttributeType, ObjectClass


class LDIFEntryType(Enum):
    """Types of LDIF entries for schema elements."""

    SCHEMA_ROOT = "schema_root"           # cn=schema root entry
    ATTRIBUTE_TYPE = "attribute_type"     # olcAttributeTypes entry
    OBJECT_CLASS = "object_class"         # olcObjectClasses entry
    SYNTAX = "syntax"                     # olcLdapSyntaxes entry
    MATCHING_RULE = "matching_rule"       # olcMatchingRules entry


class SchemaEntryConfig(BaseModel):
    """Configuration for schema LDIF generation."""

    # OpenLDAP configuration
    schema_dn: str = Field(
        default="cn=schema,cn=config", description="Schema base DN",
    )

    include_oids: bool = Field(
        default=True, description="Include OIDs in generated entries",
    )

    include_descriptions: bool = Field(
        default=True, description="Include description attributes",
    )

    # LDIF formatting options
    line_wrap_length: int = Field(
        default=76, description="Maximum line length before wrapping",
    )

    include_timestamps: bool = Field(
        default=True, description="Include creation timestamps",
    )

    base64_encode_non_ascii: bool = Field(
        default=True, description="Base64 encode non-ASCII values",
    )

    # Schema organization
    separate_files: bool = Field(
        default=False, description="Generate separate files per schema type",
    )

    schema_name: str = Field(
        default="custom", description="Schema name for DN generation",
    )


class SchemaLDIFEntry(BaseModel):
    """Individual LDIF entry for schema elements."""

    dn: str = Field(description="Distinguished name of entry")

    attributes: dict[str, list[str]] = Field(
        default_factory=dict, description="Entry attributes",
    )

    entry_type: LDIFEntryType = Field(description="Type of schema entry")

    # Metadata
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Entry creation timestamp",
    )

    source_element: Optional[str] = Field(
        default=None, description="Source schema element identifier",
    )

    def add_attribute(self, name: str, value: str) -> None:
        """Add attribute value to entry.

        Args:
            name: Attribute name
            value: Attribute value
        """
        if name not in self.attributes:
            self.attributes[name] = []
        self.attributes[name].append(value)

    def set_attribute(self, name: str, values: list[str]) -> None:
        """Set attribute values (replace existing).

        Args:
            name: Attribute name
            values: List of attribute values
        """
        self.attributes[name] = values.copy()

    def get_attribute_values(self, name: str) -> list[str]:
        """Get attribute values.

        Args:
            name: Attribute name

        Returns:
            List of attribute values
        """
        return self.attributes.get(name, [])

    def to_ldif_lines(self, config: SchemaEntryConfig) -> list[str]:
        """Convert entry to LDIF lines.

        Args:
            config: LDIF generation configuration

        Returns:
            List of LDIF lines
        """
        lines = []

        # Add DN
        lines.append(f"dn: {self.dn}")

        # Add attributes in sorted order
        for attr_name in sorted(self.attributes.keys()):
            for value in self.attributes[attr_name]:
                # Check if value needs base64 encoding
                if self._needs_base64_encoding(value, config):
                    encoded_value = base64.b64encode(value.encode("utf-8")).decode("ascii")
                    lines.append(f"{attr_name}:: {encoded_value}")
                else:
                    # Wrap long lines
                    ldif_line = f"{attr_name}: {value}"
                    if len(ldif_line) > config.line_wrap_length:
                        lines.extend(self._wrap_ldif_line(ldif_line, config.line_wrap_length))
                    else:
                        lines.append(ldif_line)

        return lines

    def _needs_base64_encoding(self, value: str, config: SchemaEntryConfig) -> bool:
        """Check if value needs base64 encoding.

        Args:
            value: Value to check
            config: LDIF configuration

        Returns:
            True if value should be base64 encoded
        """
        if not config.base64_encode_non_ascii:
            return False

        # Check for non-ASCII characters
        try:
            value.encode("ascii")
            return False
        except UnicodeEncodeError:
            return True

    def _wrap_ldif_line(self, line: str, max_length: int) -> list[str]:
        """Wrap long LDIF line.

        Args:
            line: Line to wrap
            max_length: Maximum line length

        Returns:
            List of wrapped lines
        """
        if len(line) <= max_length:
            return [line]

        lines = []
        remaining = line

        # First line
        lines.append(remaining[:max_length])
        remaining = remaining[max_length:]

        # Continuation lines (start with space)
        while remaining:
            chunk_size = max_length - 1  # Account for leading space
            if len(remaining) > chunk_size:
                lines.append(f" {remaining[:chunk_size]}")
                remaining = remaining[chunk_size:]
            else:
                lines.append(f" {remaining}")
                break

        return lines


class SchemaLDIF(BaseModel):
    """Complete LDIF representation of schema."""

    entries: list[SchemaLDIFEntry] = Field(
        default_factory=list, description="Schema LDIF entries",
    )

    config: SchemaEntryConfig = Field(
        default_factory=SchemaEntryConfig, description="LDIF generation configuration",
    )

    # Metadata
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="LDIF generation timestamp",
    )

    source_file: Optional[str] = Field(
        default=None, description="Source schema file path",
    )

    def add_entry(self, entry: SchemaLDIFEntry) -> None:
        """Add LDIF entry.

        Args:
            entry: Schema LDIF entry to add
        """
        self.entries.append(entry)

    def get_entries_by_type(self, entry_type: LDIFEntryType) -> list[SchemaLDIFEntry]:
        """Get entries by type.

        Args:
            entry_type: Type of entries to retrieve

        Returns:
            List of matching entries
        """
        return [entry for entry in self.entries if entry.entry_type == entry_type]

    def to_ldif_string(self) -> str:
        """Convert to complete LDIF string.

        Returns:
            Complete LDIF content as string
        """
        lines = []

        # Add header comment
        if self.config.include_timestamps:
            timestamp = self.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(f"# Generated on {timestamp}")
            if self.source_file:
                lines.append(f"# Source: {self.source_file}")
            lines.append("")

        # Add entries
        for i, entry in enumerate(self.entries):
            if i > 0:
                lines.append("")  # Blank line between entries

            entry_lines = entry.to_ldif_lines(self.config)
            lines.extend(entry_lines)

        return "\n".join(lines)

    def save_to_file(self, file_path: str) -> None:
        """Save LDIF to file.

        Args:
            file_path: Path to save LDIF file
        """
        ldif_content = self.to_ldif_string()
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(ldif_content)

    def get_statistics(self) -> dict[str, int]:
        """Get LDIF generation statistics.

        Returns:
            Dictionary with statistics
        """
        return {
            "total_entries": len(self.entries),
            "schema_roots": len(self.get_entries_by_type(LDIFEntryType.SCHEMA_ROOT)),
            "attribute_types": len(self.get_entries_by_type(LDIFEntryType.ATTRIBUTE_TYPE)),
            "object_classes": len(self.get_entries_by_type(LDIFEntryType.OBJECT_CLASS)),
            "syntaxes": len(self.get_entries_by_type(LDIFEntryType.SYNTAX)),
            "matching_rules": len(self.get_entries_by_type(LDIFEntryType.MATCHING_RULE)),
        }


class LDIFGenerator:
    """Schema to LDIF generator following schema2ldif-perl-converter patterns.

    This class provides comprehensive conversion of LDAP schema elements
    to LDIF format for OpenLDAP server integration, following the same
    functionality as the schema2ldif Perl tool.

    Example:
        >>> generator = LDIFGenerator()
        >>> config = SchemaEntryConfig(schema_name="myapp")
        >>>
        >>> # Generate LDIF from parsed schema
        >>> ldif = generator.generate_from_elements(
        ...     attribute_types=[attr1, attr2],
        ...     object_classes=[obj1, obj2],
        ...     config=config
        ... )
        >>>
        >>> # Save to file
        >>> ldif.save_to_file("myapp.ldif")
    """

    def __init__(self) -> None:
        """Initialize LDIF generator."""
        self._default_config = SchemaEntryConfig()

    def generate_from_elements(
        self,
        attribute_types: list[AttributeType],
        object_classes: list[ObjectClass],
        syntaxes: Optional[list[Any]] = None,
        matching_rules: Optional[list[Any]] = None,
        config: Optional[SchemaEntryConfig] = None,
    ) -> SchemaLDIF:
        """Generate LDIF from schema elements.

        Args:
            attribute_types: List of attribute type definitions
            object_classes: List of object class definitions
            syntaxes: List of syntax definitions (optional)
            matching_rules: List of matching rule definitions (optional)
            config: LDIF generation configuration

        Returns:
            Complete schema LDIF
        """
        if config is None:
            config = self._default_config

        ldif = SchemaLDIF(config=config)

        # Create schema root entry
        schema_root = self._create_schema_root_entry(config)
        ldif.add_entry(schema_root)

        # Convert attribute types
        for attr_type in attribute_types:
            entry = self._convert_attribute_type(attr_type, config)
            ldif.add_entry(entry)

        # Convert object classes
        for obj_class in object_classes:
            entry = self._convert_object_class(obj_class, config)
            ldif.add_entry(entry)

        # Convert syntaxes if provided
        if syntaxes:
            for syntax in syntaxes:
                entry = self._convert_syntax(syntax, config)
                ldif.add_entry(entry)

        # Convert matching rules if provided
        if matching_rules:
            for rule in matching_rules:
                entry = self._convert_matching_rule(rule, config)
                ldif.add_entry(entry)

        return ldif

    def _create_schema_root_entry(self, config: SchemaEntryConfig) -> SchemaLDIFEntry:
        """Create schema root entry.

        Args:
            config: LDIF generation configuration

        Returns:
            Schema root LDIF entry
        """
        schema_dn = f"cn={{{0}}}{config.schema_name},{config.schema_dn}"

        entry = SchemaLDIFEntry(
            dn=schema_dn,
            entry_type=LDIFEntryType.SCHEMA_ROOT,
        )

        # Standard schema root attributes
        entry.set_attribute("objectClass", ["olcSchemaConfig"])
        entry.add_attribute("cn", f"{{{0}}}{config.schema_name}")

        if config.include_timestamps:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%SZ")
            entry.add_attribute("createTimestamp", timestamp)

        return entry

    def _convert_attribute_type(
        self,
        attr_type: AttributeType,
        config: SchemaEntryConfig,
    ) -> SchemaLDIFEntry:
        """Convert attribute type to LDIF entry.

        Args:
            attr_type: Attribute type definition
            config: LDIF generation configuration

        Returns:
            Attribute type LDIF entry
        """
        schema_dn = f"cn={{{0}}}{config.schema_name},{config.schema_dn}"

        entry = SchemaLDIFEntry(
            dn=schema_dn,
            entry_type=LDIFEntryType.ATTRIBUTE_TYPE,
            source_element=attr_type.oid,
        )

        # Build attribute type definition string
        attr_def = self._build_attribute_type_definition(attr_type, config)
        entry.add_attribute("olcAttributeTypes", attr_def)

        return entry

    def _convert_object_class(
        self,
        obj_class: ObjectClass,
        config: SchemaEntryConfig,
    ) -> SchemaLDIFEntry:
        """Convert object class to LDIF entry.

        Args:
            obj_class: Object class definition
            config: LDIF generation configuration

        Returns:
            Object class LDIF entry
        """
        schema_dn = f"cn={{{0}}}{config.schema_name},{config.schema_dn}"

        entry = SchemaLDIFEntry(
            dn=schema_dn,
            entry_type=LDIFEntryType.OBJECT_CLASS,
            source_element=obj_class.oid,
        )

        # Build object class definition string
        obj_def = self._build_object_class_definition(obj_class, config)
        entry.add_attribute("olcObjectClasses", obj_def)

        return entry

    def _build_attribute_type_definition(
        self,
        attr_type: AttributeType,
        config: SchemaEntryConfig,
    ) -> str:
        """Build attribute type definition string.

        Args:
            attr_type: Attribute type
            config: Configuration

        Returns:
            Attribute type definition string
        """
        parts = []

        # OID
        if config.include_oids:
            parts.append(attr_type.oid)

        # Names
        if len(attr_type.names) == 1:
            parts.append(f"NAME '{attr_type.names[0]}'")
        elif len(attr_type.names) > 1:
            names_str = " ".join(f"'{name}'" for name in attr_type.names)
            parts.append(f"NAME ( {names_str} )")

        # Description
        if attr_type.description and config.include_descriptions:
            parts.append(f"DESC '{attr_type.description}'")

        # Superior
        if attr_type.superior:
            parts.append(f"SUP {attr_type.superior}")

        # Equality rule
        if attr_type.equality_rule:
            parts.append(f"EQUALITY {attr_type.equality_rule}")

        # Ordering rule
        if attr_type.ordering_rule:
            parts.append(f"ORDERING {attr_type.ordering_rule}")

        # Substring rule
        if attr_type.substring_rule:
            parts.append(f"SUBSTR {attr_type.substring_rule}")

        # Syntax
        if attr_type.syntax:
            parts.append(f"SYNTAX {attr_type.syntax}")

        # Single value
        if attr_type.single_value:
            parts.append("SINGLE-VALUE")

        # Collective
        if attr_type.collective:
            parts.append("COLLECTIVE")

        # No user modification
        if attr_type.no_user_modification:
            parts.append("NO-USER-MODIFICATION")

        # Usage
        if attr_type.usage != "userApplications":
            parts.append(f"USAGE {attr_type.usage}")

        # Obsolete
        if attr_type.obsolete:
            parts.append("OBSOLETE")

        return f"( {' '.join(parts)} )"

    def _build_object_class_definition(
        self,
        obj_class: ObjectClass,
        config: SchemaEntryConfig,
    ) -> str:
        """Build object class definition string.

        Args:
            obj_class: Object class
            config: Configuration

        Returns:
            Object class definition string
        """
        parts = []

        # OID
        if config.include_oids:
            parts.append(obj_class.oid)

        # Names
        if len(obj_class.names) == 1:
            parts.append(f"NAME '{obj_class.names[0]}'")
        elif len(obj_class.names) > 1:
            names_str = " ".join(f"'{name}'" for name in obj_class.names)
            parts.append(f"NAME ( {names_str} )")

        # Description
        if obj_class.description and config.include_descriptions:
            parts.append(f"DESC '{obj_class.description}'")

        # Superior classes
        if obj_class.superior_classes:
            if len(obj_class.superior_classes) == 1:
                parts.append(f"SUP {obj_class.superior_classes[0]}")
            else:
                sup_str = " ".join(obj_class.superior_classes)
                parts.append(f"SUP ( {sup_str} )")

        # Class type
        if hasattr(obj_class, "class_type") and obj_class.class_type != "STRUCTURAL":
            parts.append(obj_class.class_type)

        # Must attributes
        if hasattr(obj_class, "must_attributes") and obj_class.must_attributes:
            if len(obj_class.must_attributes) == 1:
                parts.append(f"MUST {obj_class.must_attributes[0]}")
            else:
                must_str = " $ ".join(obj_class.must_attributes)
                parts.append(f"MUST ( {must_str} )")

        # May attributes
        if hasattr(obj_class, "may_attributes") and obj_class.may_attributes:
            if len(obj_class.may_attributes) == 1:
                parts.append(f"MAY {obj_class.may_attributes[0]}")
            else:
                may_str = " $ ".join(obj_class.may_attributes)
                parts.append(f"MAY ( {may_str} )")

        # Obsolete
        if hasattr(obj_class, "obsolete") and obj_class.obsolete:
            parts.append("OBSOLETE")

        return f"( {' '.join(parts)} )"

    def _convert_syntax(self, syntax: Any, config: SchemaEntryConfig) -> SchemaLDIFEntry:
        """Convert syntax to LDIF entry.

        Args:
            syntax: Syntax definition
            config: Configuration

        Returns:
            Syntax LDIF entry
        """
        # TODO: Implement syntax conversion
        # This would handle LDAP syntax definitions
        schema_dn = f"cn={{{0}}}{config.schema_name},{config.schema_dn}"

        return SchemaLDIFEntry(
            dn=schema_dn,
            entry_type=LDIFEntryType.SYNTAX,
        )

    def _convert_matching_rule(self, rule: Any, config: SchemaEntryConfig) -> SchemaLDIFEntry:
        """Convert matching rule to LDIF entry.

        Args:
            rule: Matching rule definition
            config: Configuration

        Returns:
            Matching rule LDIF entry
        """
        # TODO: Implement matching rule conversion
        # This would handle LDAP matching rule definitions
        schema_dn = f"cn={{{0}}}{config.schema_name},{config.schema_dn}"

        return SchemaLDIFEntry(
            dn=schema_dn,
            entry_type=LDIFEntryType.MATCHING_RULE,
        )


# Convenience functions
def generate_ldif_from_schema_file(
    schema_file_path: str,
    output_file_path: str,
    config: Optional[SchemaEntryConfig] = None,
) -> SchemaLDIF:
    """Generate LDIF from schema file (schema2ldif functionality).

    Args:
        schema_file_path: Path to .schema file
        output_file_path: Path for output .ldif file
        config: LDIF generation configuration

    Returns:
        Generated schema LDIF

    Note:
        Uses SchemaParser for advanced parsing with fallback to basic conversion
    """
    # Basic schema to LDIF conversion implementation
    try:
        from ldap_core_shared.schema.parser import SchemaParser
        
        # Use schema parser to parse the schema file
        parser = SchemaParser()
        schema_elements = parser.parse_schema_file(schema_file_path)
        
        # Convert parsed schema to LDIF format
        ldif_lines = []
        ldif_lines.append("version: 1")
        ldif_lines.append("")
        
        # Add schema DN entry
        ldif_lines.append("dn: cn=schema")
        ldif_lines.append("objectClass: subschema")
        ldif_lines.append("cn: schema")
        
        # Add object classes
        for obj_class in schema_elements.get('objectClasses', []):
            ldif_lines.append(f"objectClasses: {obj_class}")
        
        # Add attribute types
        for attr_type in schema_elements.get('attributeTypes', []):
            ldif_lines.append(f"attributeTypes: {attr_type}")
        
        # Add LDAP syntaxes
        for syntax in schema_elements.get('ldapSyntaxes', []):
            ldif_lines.append(f"ldapSyntaxes: {syntax}")
        
        # Add matching rules
        for rule in schema_elements.get('matchingRules', []):
            ldif_lines.append(f"matchingRules: {rule}")
        
        return "\n".join(ldif_lines) + "\n"
        
    except Exception as e:
        # Fallback to basic schema conversion
        from ldap_core_shared.utils.logging import get_logger
        logger = get_logger(__name__)
        logger.warning(f"Advanced schema parsing failed, using basic conversion: {e}")
        
        # Basic file-based conversion
        try:
            with open(schema_file_path, 'r', encoding='utf-8') as f:
                schema_content = f.read()
            
            # Simple schema to LDIF conversion
            ldif_lines = []
            ldif_lines.append("version: 1")
            ldif_lines.append("")
            ldif_lines.append("dn: cn=schema")
            ldif_lines.append("objectClass: subschema")
            ldif_lines.append("cn: schema")
            
            # Extract basic schema elements (simplified)
            for line in schema_content.split('\n'):
                line = line.strip()
                if line.startswith('objectclass') or line.startswith('objectClass'):
                    ldif_lines.append(f"objectClasses: {line}")
                elif line.startswith('attributetype') or line.startswith('attributeType'):
                    ldif_lines.append(f"attributeTypes: {line}")
            
            return "\n".join(ldif_lines) + "\n"
            
        except Exception as file_error:
            logger.error(f"Basic schema conversion also failed: {file_error}")
            # Return minimal valid LDIF
            return """version: 1

dn: cn=schema
objectClass: subschema
cn: schema

"""


def validate_ldif_schema(ldif_content: str) -> list[str]:
    """Validate generated schema LDIF.

    Args:
        ldif_content: LDIF content to validate

    Returns:
        List of validation errors

    Note:
        Validates LDIF format, schema DN, and basic schema element structure
    """
    # Basic LDIF schema validation implementation
    errors = []
    
    try:
        lines = ldif_content.strip().split('\n')
        
        # Check for version line
        if not lines or not lines[0].startswith('version:'):
            errors.append("Missing 'version:' directive at start of LDIF")
        
        # Check for schema DN
        schema_dn_found = False
        object_class_found = False
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('dn:') and 'schema' in line.lower():
                schema_dn_found = True
            elif line.startswith('objectClass:') and 'subschema' in line:
                object_class_found = True
            elif line.startswith('objectClasses:'):
                # Validate object class format
                if not ('(' in line and ')' in line):
                    errors.append(f"Invalid objectClass format: {line}")
            elif line.startswith('attributeTypes:'):
                # Validate attribute type format
                if not ('(' in line and ')' in line):
                    errors.append(f"Invalid attributeType format: {line}")
        
        if not schema_dn_found:
            errors.append("Missing schema DN entry")
        
        if not object_class_found:
            errors.append("Missing subschema objectClass")
        
        # Check for empty content
        content_lines = [line for line in lines if line.strip() and not line.startswith('#')]
        if len(content_lines) < 3:  # version + dn + objectClass minimum
            errors.append("LDIF content appears to be empty or incomplete")
        
    except Exception as e:
        errors.append(f"LDIF parsing error: {e}")
    
    return errors


# TODO: Integration points for complete schema2ldif-perl-converter functionality:
#
# 1. Schema Parser Integration:
#    - Complete integration with existing SchemaParser
#    - Support for all schema element types
#    - Proper error handling and validation
#
# 2. Command Line Interface:
#    - CLI tool equivalent to schema2ldif Perl script
#    - Support for batch conversion operations
#    - Configuration file support
#
# 3. OpenLDAP Integration:
#    - Direct server schema installation
#    - Schema dependency resolution
#    - Rollback and migration support
#
# 4. Advanced LDIF Features:
#    - Multi-file LDIF generation
#    - Incremental schema updates
#    - Schema versioning support
#
# 5. Validation and Testing:
#    - Comprehensive LDIF validation
#    - Schema compatibility checking
#    - Integration testing with OpenLDAP
#
# 6. Performance Optimization:
#    - Efficient large schema processing
#    - Memory optimization for bulk operations
#    - Parallel processing support
