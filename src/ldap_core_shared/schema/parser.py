"""Schema Parser - Parse LDAP schema definitions according to RFC 2252.

This module provides comprehensive parsing of LDAP schema elements including
attribute types, object classes, syntax definitions, and matching rules.
"""

from __future__ import annotations

import logging
import re

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.domain.results import LDAPOperationResult

logger = logging.getLogger(__name__)


class AttributeType(BaseModel):
    """LDAP Attribute Type definition."""

    model_config = ConfigDict(strict=True, extra="forbid")

    oid: str = Field(..., description="Object identifier")
    names: list[str] = Field(default_factory=list, description="Attribute names")
    description: str = Field(default="", description="Attribute description")
    syntax: str = Field(default="", description="Syntax OID")
    equality_rule: str = Field(default="", description="Equality matching rule")
    ordering_rule: str = Field(default="", description="Ordering matching rule")
    substring_rule: str = Field(default="", description="Substring matching rule")
    superior: str = Field(default="", description="Superior attribute type")
    usage: str = Field(default="userApplications", description="Attribute usage")
    single_value: bool = Field(default=False, description="Single-valued attribute")
    collective: bool = Field(default=False, description="Collective attribute")
    no_user_modification: bool = Field(
        default=False,
        description="No user modification",
    )
    obsolete: bool = Field(default=False, description="Obsolete attribute")


class ObjectClass(BaseModel):
    """LDAP Object Class definition."""

    model_config = ConfigDict(strict=True, extra="forbid")

    oid: str = Field(..., description="Object identifier")
    names: list[str] = Field(default_factory=list, description="Object class names")
    description: str = Field(default="", description="Object class description")
    superior_classes: list[str] = Field(
        default_factory=list,
        description="Superior object classes",
    )
    class_type: str = Field(default="STRUCTURAL", description="Object class type")
    must_attributes: list[str] = Field(
        default_factory=list,
        description="Required attributes",
    )
    may_attributes: list[str] = Field(
        default_factory=list,
        description="Optional attributes",
    )
    obsolete: bool = Field(default=False, description="Obsolete object class")


class SyntaxDefinition(BaseModel):
    """LDAP Syntax definition."""

    model_config = ConfigDict(strict=True, extra="forbid")

    oid: str = Field(..., description="Syntax OID")
    description: str = Field(default="", description="Syntax description")


class MatchingRule(BaseModel):
    """LDAP Matching Rule definition."""

    model_config = ConfigDict(strict=True, extra="forbid")

    oid: str = Field(..., description="Matching rule OID")
    names: list[str] = Field(default_factory=list, description="Matching rule names")
    description: str = Field(default="", description="Matching rule description")
    syntax: str = Field(default="", description="Syntax OID")
    obsolete: bool = Field(default=False, description="Obsolete matching rule")


class ParsedSchema(BaseModel):
    """Complete parsed schema with all elements."""

    model_config = ConfigDict(strict=True, extra="forbid")

    attribute_types: dict[str, AttributeType] = Field(
        default_factory=dict,
        description="Attribute types by OID",
    )
    object_classes: dict[str, ObjectClass] = Field(
        default_factory=dict,
        description="Object classes by OID",
    )
    syntax_definitions: dict[str, SyntaxDefinition] = Field(
        default_factory=dict,
        description="Syntax definitions by OID",
    )
    matching_rules: dict[str, MatchingRule] = Field(
        default_factory=dict,
        description="Matching rules by OID",
    )


class SchemaParser:
    """RFC 2252 compliant LDAP schema parser."""

    def __init__(self) -> None:
        """Initialize schema parser."""
        # Compiled regex patterns for parsing
        self._oid_pattern = re.compile(r"^\s*\(\s*([0-9.]+)\s*")
        self._name_pattern = re.compile(
            r"NAME\s+(?:'([^']+)'|\(([^)]+)\))",
            re.IGNORECASE,
        )
        self._desc_pattern = re.compile(r"DESC\s+'([^']*)'", re.IGNORECASE)
        self._syntax_pattern = re.compile(
            r"SYNTAX\s+([0-9.]+)(?:\{(\d+)\})?",
            re.IGNORECASE,
        )
        self._equality_pattern = re.compile(
            r"EQUALITY\s+([a-zA-Z0-9-]+)",
            re.IGNORECASE,
        )
        self._ordering_pattern = re.compile(
            r"ORDERING\s+([a-zA-Z0-9-]+)",
            re.IGNORECASE,
        )
        self._substr_pattern = re.compile(r"SUBSTR\s+([a-zA-Z0-9-]+)", re.IGNORECASE)
        self._sup_pattern = re.compile(r"SUP\s+([a-zA-Z0-9-]+)", re.IGNORECASE)
        self._usage_pattern = re.compile(r"USAGE\s+([a-zA-Z]+)", re.IGNORECASE)

    def parse_schema_definitions(
        self,
        attribute_types: list[str] | None = None,
        object_classes: list[str] | None = None,
        syntax_definitions: list[str] | None = None,
        matching_rules: list[str] | None = None,
    ) -> LDAPOperationResult[ParsedSchema]:
        """Parse complete schema definitions.

        Args:
            attribute_types: List of attribute type definitions
            object_classes: List of object class definitions
            syntax_definitions: List of syntax definitions
            matching_rules: List of matching rule definitions

        Returns:
            Operation result with parsed schema
        """
        try:
            schema = ParsedSchema()

            # Parse attribute types
            if attribute_types:
                for attr_def in attribute_types:
                    result = self.parse_attribute_type(attr_def)
                    if result.success and result.data:
                        schema.attribute_types[result.data.oid] = result.data

            # Parse object classes
            if object_classes:
                for oc_def in object_classes:
                    result = self.parse_object_class(oc_def)
                    if result.success and result.data:
                        schema.object_classes[result.data.oid] = result.data

            # Parse syntax definitions
            if syntax_definitions:
                for syntax_def in syntax_definitions:
                    result = self.parse_syntax_definition(syntax_def)
                    if result.success and result.data:
                        schema.syntax_definitions[result.data.oid] = result.data

            # Parse matching rules
            if matching_rules:
                for mr_def in matching_rules:
                    result = self.parse_matching_rule(mr_def)
                    if result.success and result.data:
                        schema.matching_rules[result.data.oid] = result.data

            return LDAPOperationResult[ParsedSchema](
                success=True,
                data=schema,
                operation="parse_schema_definitions",
            )

        except Exception as e:
            logger.exception("Failed to parse schema definitions")
            return LDAPOperationResult[ParsedSchema](
                success=False,
                error_message=f"Parse failed: {e!s}",
                operation="parse_schema_definitions",
            )

    def parse_attribute_type(
        self,
        definition: str,
    ) -> LDAPOperationResult[AttributeType]:
        """Parse single attribute type definition.

        Args:
            definition: Attribute type definition string

        Returns:
            Operation result with parsed attribute type
        """
        try:
            # Extract OID
            oid_match = self._oid_pattern.match(definition)
            if not oid_match:
                return LDAPOperationResult[AttributeType](
                    success=False,
                    error_message="No OID found in attribute type definition",
                    operation="parse_attribute_type",
                )

            oid = oid_match.group(1)

            # Extract names
            names = self._extract_names(definition)

            # Extract other properties
            description = self._extract_description(definition)
            syntax = self._extract_syntax(definition)
            equality_rule = self._extract_equality_rule(definition)
            ordering_rule = self._extract_ordering_rule(definition)
            substring_rule = self._extract_substring_rule(definition)
            superior = self._extract_superior(definition)
            usage = self._extract_usage(definition)

            # Check flags
            single_value = "SINGLE-VALUE" in definition.upper()
            collective = "COLLECTIVE" in definition.upper()
            no_user_modification = "NO-USER-MODIFICATION" in definition.upper()
            obsolete = "OBSOLETE" in definition.upper()

            attr_type = AttributeType(
                oid=oid,
                names=names,
                description=description,
                syntax=syntax,
                equality_rule=equality_rule,
                ordering_rule=ordering_rule,
                substring_rule=substring_rule,
                superior=superior,
                usage=usage,
                single_value=single_value,
                collective=collective,
                no_user_modification=no_user_modification,
                obsolete=obsolete,
            )

            return LDAPOperationResult[AttributeType](
                success=True,
                data=attr_type,
                operation="parse_attribute_type",
            )

        except Exception as e:
            logger.exception(f"Failed to parse attribute type: {definition}")
            return LDAPOperationResult[AttributeType](
                success=False,
                error_message=f"Parse failed: {e!s}",
                operation="parse_attribute_type",
            )

    def parse_object_class(self, definition: str) -> LDAPOperationResult[ObjectClass]:
        """Parse single object class definition.

        Args:
            definition: Object class definition string

        Returns:
            Operation result with parsed object class
        """
        try:
            # Extract OID
            oid_match = self._oid_pattern.match(definition)
            if not oid_match:
                return LDAPOperationResult[ObjectClass](
                    success=False,
                    error_message="No OID found in object class definition",
                    operation="parse_object_class",
                )

            oid = oid_match.group(1)

            # Extract names
            names = self._extract_names(definition)

            # Extract other properties
            description = self._extract_description(definition)
            superior_classes = self._extract_superior_classes(definition)
            class_type = self._extract_class_type(definition)
            must_attributes = self._extract_must_attributes(definition)
            may_attributes = self._extract_may_attributes(definition)

            # Check flags
            obsolete = "OBSOLETE" in definition.upper()

            obj_class = ObjectClass(
                oid=oid,
                names=names,
                description=description,
                superior_classes=superior_classes,
                class_type=class_type,
                must_attributes=must_attributes,
                may_attributes=may_attributes,
                obsolete=obsolete,
            )

            return LDAPOperationResult[ObjectClass](
                success=True,
                data=obj_class,
                operation="parse_object_class",
            )

        except Exception as e:
            logger.exception(f"Failed to parse object class: {definition}")
            return LDAPOperationResult[ObjectClass](
                success=False,
                error_message=f"Parse failed: {e!s}",
                operation="parse_object_class",
            )

    def parse_syntax_definition(
        self,
        definition: str,
    ) -> LDAPOperationResult[SyntaxDefinition]:
        """Parse syntax definition."""
        try:
            oid_match = self._oid_pattern.match(definition)
            if not oid_match:
                return LDAPOperationResult[SyntaxDefinition](
                    success=False,
                    error_message="No OID found in syntax definition",
                    operation="parse_syntax_definition",
                )

            oid = oid_match.group(1)
            description = self._extract_description(definition)

            syntax_def = SyntaxDefinition(oid=oid, description=description)

            return LDAPOperationResult[SyntaxDefinition](
                success=True,
                data=syntax_def,
                operation="parse_syntax_definition",
            )

        except Exception as e:
            return LDAPOperationResult[SyntaxDefinition](
                success=False,
                error_message=f"Parse failed: {e!s}",
                operation="parse_syntax_definition",
            )

    def parse_matching_rule(self, definition: str) -> LDAPOperationResult[MatchingRule]:
        """Parse matching rule definition."""
        try:
            oid_match = self._oid_pattern.match(definition)
            if not oid_match:
                return LDAPOperationResult[MatchingRule](
                    success=False,
                    error_message="No OID found in matching rule definition",
                    operation="parse_matching_rule",
                )

            oid = oid_match.group(1)
            names = self._extract_names(definition)
            description = self._extract_description(definition)
            syntax = self._extract_syntax(definition)
            obsolete = "OBSOLETE" in definition.upper()

            mr = MatchingRule(
                oid=oid,
                names=names,
                description=description,
                syntax=syntax,
                obsolete=obsolete,
            )

            return LDAPOperationResult[MatchingRule](
                success=True,
                data=mr,
                operation="parse_matching_rule",
            )

        except Exception as e:
            return LDAPOperationResult[MatchingRule](
                success=False,
                error_message=f"Parse failed: {e!s}",
                operation="parse_matching_rule",
            )

    def _extract_names(self, definition: str) -> list[str]:
        """Extract names from schema definition."""
        match = self._name_pattern.search(definition)
        if not match:
            return []

        if match.group(1):
            # Single name in quotes
            return [match.group(1)]
        if match.group(2):
            # Multiple names in parentheses
            names_str = match.group(2)
            return [name.strip().strip("'\"") for name in names_str.split()]

        return []

    def _extract_description(self, definition: str) -> str:
        """Extract description from schema definition."""
        match = self._desc_pattern.search(definition)
        return match.group(1) if match else ""

    def _extract_syntax(self, definition: str) -> str:
        """Extract syntax OID from schema definition."""
        match = self._syntax_pattern.search(definition)
        return match.group(1) if match else ""

    def _extract_equality_rule(self, definition: str) -> str:
        """Extract equality matching rule."""
        match = self._equality_pattern.search(definition)
        return match.group(1) if match else ""

    def _extract_ordering_rule(self, definition: str) -> str:
        """Extract ordering matching rule."""
        match = self._ordering_pattern.search(definition)
        return match.group(1) if match else ""

    def _extract_substring_rule(self, definition: str) -> str:
        """Extract substring matching rule."""
        match = self._substr_pattern.search(definition)
        return match.group(1) if match else ""

    def _extract_superior(self, definition: str) -> str:
        """Extract superior attribute type."""
        match = self._sup_pattern.search(definition)
        return match.group(1) if match else ""

    def _extract_usage(self, definition: str) -> str:
        """Extract attribute usage."""
        match = self._usage_pattern.search(definition)
        return match.group(1) if match else "userApplications"

    def _extract_superior_classes(self, definition: str) -> list[str]:
        """Extract superior object classes."""
        match = re.search(
            r"SUP\s+(?:([a-zA-Z0-9-]+)|\(([^)]+)\))",
            definition,
            re.IGNORECASE,
        )
        if not match:
            return []

        if match.group(1):
            return [match.group(1)]
        if match.group(2):
            return [name.strip() for name in match.group(2).split("$")]

        return []

    def _extract_class_type(self, definition: str) -> str:
        """Extract object class type."""
        if "ABSTRACT" in definition.upper():
            return "ABSTRACT"
        if "AUXILIARY" in definition.upper():
            return "AUXILIARY"
        return "STRUCTURAL"

    def _extract_must_attributes(self, definition: str) -> list[str]:
        """Extract required attributes."""
        return self._extract_attribute_list(definition, "MUST")

    def _extract_may_attributes(self, definition: str) -> list[str]:
        """Extract optional attributes."""
        return self._extract_attribute_list(definition, "MAY")

    def _extract_attribute_list(self, definition: str, keyword: str) -> list[str]:
        """Extract attribute list for MUST or MAY."""
        pattern = rf"{keyword}\s+(?:([a-zA-Z0-9-]+)|\(([^)]+)\))"
        match = re.search(pattern, definition, re.IGNORECASE)
        if not match:
            return []

        if match.group(1):
            return [match.group(1)]
        if match.group(2):
            return [attr.strip() for attr in match.group(2).split("$")]

        return []
