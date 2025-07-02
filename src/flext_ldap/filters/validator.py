from __future__ import annotations

from flext_ldap.utils.constants import (
    DEFAULT_LARGE_LIMIT,
    DEFAULT_TIMEOUT_SECONDS,
)

# Constants for filter performance and security validation
SUBSTRING_WILDCARD_LIMIT = (
    2  # Maximum wildcards in substring filters for good performance
)
EXCELLENT_COMPLEXITY_THRESHOLD = 5  # Complexity threshold for excellent rating
GOOD_COMPLEXITY_THRESHOLD = 15  # Complexity threshold for good rating
MAX_PERFORMANCE_ISSUES_GOOD = 1  # Maximum performance issues for good rating
MAX_SECURITY_ISSUES_WARNING = 1  # Maximum security issues for warning rating
MAX_SECURITY_ISSUES_FAIR = 3  # Maximum security issues for fair rating

"""LDAP Filter Validator Implementation.

# Constants for magic values

This module provides comprehensive LDAP filter validation functionality
following RFC 4515 specification with enterprise-grade validation rules.
Based on perl-ldap validation patterns with enhanced security and
performance analysis.

The FilterValidator ensures filter correctness, security, and performance
characteristics before execution against LDAP directories.

Architecture:
    - FilterValidator: Main validation engine
    - FilterValidationResult: Comprehensive validation results
    - ValidationRule: Individual validation rules and policies
    - SecurityValidator: Security-focused validation rules

Usage Example:
    >>> from flext_ldapidator import FilterValidator
    >>>
    >>> # Basic validation
    >>> validator = FilterValidator()
    >>> result = validator.validate("(cn=John Doe)")
    >>> print(result.is_valid)  # True
    >>> print(result.warnings)  # []
    >>>
    >>> # Validation with schema
    >>> validator_with_schema = FilterValidator(schema_aware=True)
    >>> result = validator_with_schema.validate("(invalidAttr=value)")
    >>> print(result.errors)  # ["Unknown attribute: invalidAttr"]

References:
    - perl-ldap: lib/Net/LDAP/Filter.pm validation methods
    - RFC 4515: LDAP String Representation of Search Filters
    - RFC 4511: LDAP Protocol Specification
"""


import re
from enum import Enum
from typing import Any

from flext_ldapser import (
    FilterParser,
    FilterSyntaxError,
    FilterType,
    ParsedFilter,
)
from pydantic import BaseModel, Field


class ValidationLevel(Enum):
    """Validation strictness levels."""

    BASIC = "basic"  # Syntax validation only
    STANDARD = "standard"  # Syntax + basic semantic validation
    STRICT = "strict"  # Standard + security checks
    ENTERPRISE = "enterprise"  # Strict + performance analysis


class ValidationSeverity(Enum):
    """Validation issue severity levels."""

    ERROR = "error"  # Critical issues that prevent filter execution
    WARNING = "warning"  # Issues that may cause problems
    INFO = "info"  # Informational suggestions
    HINT = "hint"  # Performance or optimization hints


class ValidationIssue(BaseModel):
    """Individual validation issue."""

    severity: ValidationSeverity = Field(description="Severity level of the issue")

    code: str = Field(description="Unique issue code for programmatic handling")

    message: str = Field(description="Human-readable issue description")

    position: int | None = Field(
        default=None,
        description="Character position where issue occurs",
    )

    attribute: str | None = Field(
        default=None,
        description="Attribute name related to the issue",
    )

    suggestion: str | None = Field(
        default=None,
        description="Suggested fix for the issue",
    )

    def __str__(self) -> str:
        """String representation of validation issue."""
        parts = [f"{self.severity.value.upper()}: {self.message}"]

        if self.position is not None:
            parts.append(f"(position {self.position})")

        if self.attribute:
            parts.append(f"(attribute: {self.attribute})")

        if self.suggestion:
            parts.append(f"Suggestion: {self.suggestion}")

        return " ".join(parts)


class FilterValidationResult(BaseModel):
    """Comprehensive filter validation result."""

    is_valid: bool = Field(description="Whether filter passed all validation checks")

    filter_string: str = Field(description="Original filter string that was validated")

    parsed_filter: ParsedFilter | None = Field(
        default=None,
        description="Parsed filter structure (if syntax is valid)",
    )

    issues: list[ValidationIssue] = Field(
        default_factory=list,
        description="All validation issues found",
    )

    complexity_score: int = Field(default=0, description="Filter complexity score")

    performance_rating: str = Field(
        default="unknown",
        description="Performance rating (excellent, good, fair, poor)",
    )

    security_rating: str = Field(
        default="unknown",
        description="Security rating (secure, warning, risk, danger)",
    )

    @property
    def errors(self) -> list[ValidationIssue]:
        """Get all error-level issues."""
        return [
            issue for issue in self.issues if issue.severity == ValidationSeverity.ERROR
        ]

    @property
    def warnings(self) -> list[ValidationIssue]:
        """Get all warning-level issues."""
        return [
            issue
            for issue in self.issues
            if issue.severity == ValidationSeverity.WARNING
        ]

    @property
    def infos(self) -> list[ValidationIssue]:
        """Get all info-level issues."""
        return [
            issue for issue in self.issues if issue.severity == ValidationSeverity.INFO
        ]

    @property
    def hints(self) -> list[ValidationIssue]:
        """Get all hint-level issues."""
        return [
            issue for issue in self.issues if issue.severity == ValidationSeverity.HINT
        ]

    def has_errors(self) -> bool:
        """Check if validation found any errors."""
        return len(self.errors) > 0

    def has_warnings(self) -> bool:
        """Check if validation found any warnings."""
        return len(self.warnings) > 0

    def get_summary(self) -> str:
        """Get validation summary."""
        status = "VALID" if self.is_valid else "INVALID"

        issue_counts = []
        if self.errors:
            issue_counts.append(f"{len(self.errors)} errors")
        if self.warnings:
            issue_counts.append(f"{len(self.warnings)} warnings")
        if self.infos:
            issue_counts.append(f"{len(self.infos)} infos")
        if self.hints:
            issue_counts.append(f"{len(self.hints)} hints")

        if issue_counts:
            return f"{status} ({', '.join(issue_counts)})"
        return status

    def __str__(self) -> str:
        """String representation of validation result."""
        return self.get_summary()


class ValidationRule:
    """Base class for validation rules."""

    def __init__(
        self,
        name: str,
        description: str,
        severity: ValidationSeverity = ValidationSeverity.ERROR,
    ) -> None:
        """Initialize validation rule.

        Args:
            name: Rule name/identifier
            description: Rule description
            severity: Default severity for rule violations

        """
        self.name = name
        self.description = description
        self.severity = severity

    def validate(
        self,
        parsed_filter: ParsedFilter,
        context: dict[str, Any],
    ) -> list[ValidationIssue]:
        """Validate filter against this rule.

        Args:
            parsed_filter: Parsed filter to validate
            context: Validation context (schema, settings, etc.)

        Returns:
            List of validation issues found

        """
        msg = "Subclasses must implement validate method"
        raise NotImplementedError(msg)


class SyntaxRule(ValidationRule):
    """Rule for basic syntax validation."""

    def __init__(self) -> None:
        super().__init__(
            name="syntax",
            description="Basic filter syntax validation",
            severity=ValidationSeverity.ERROR,
        )

    def validate(
        self,
        parsed_filter: ParsedFilter,
        context: dict[str, Any],
    ) -> list[ValidationIssue]:
        """Validate basic syntax - already handled by parser."""
        # If we have a parsed filter, syntax is valid
        return []


class AttributeNameRule(ValidationRule):
    """Rule for validating attribute names."""

    def __init__(self) -> None:
        super().__init__(
            name="attribute_name",
            description="Attribute name format validation",
            severity=ValidationSeverity.ERROR,
        )

        # RFC 4512 attribute name pattern
        self._attr_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9\-]*$")

    def validate(
        self,
        parsed_filter: ParsedFilter,
        context: dict[str, Any],
    ) -> list[ValidationIssue]:
        """Validate attribute names."""
        issues = []

        def check_attribute(filter_node: ParsedFilter) -> None:
            if filter_node.attribute:
                if not self._attr_pattern.match(filter_node.attribute):
                    issues.append(
                        ValidationIssue(
                            severity=self.severity,
                            code="INVALID_ATTRIBUTE_NAME",
                            message=(
                                f"Invalid attribute name format: "
                                f"{filter_node.attribute}"
                            ),
                            attribute=filter_node.attribute,
                            suggestion=(
                                "Attribute names must start with a letter and "
                                "contain only letters, numbers, and hyphens"
                            ),
                        ),
                    )

            # Recursively check children
            for child in filter_node.children:
                check_attribute(child)

        check_attribute(parsed_filter)
        return issues


class ComplexityRule(ValidationRule):
    """Rule for validating filter complexity."""

    def __init__(self, max_complexity: int = 50) -> None:
        super().__init__(
            name="complexity",
            description="Filter complexity validation",
            severity=ValidationSeverity.WARNING,
        )
        self.max_complexity = max_complexity

    def validate(
        self,
        parsed_filter: ParsedFilter,
        context: dict[str, Any],
    ) -> list[ValidationIssue]:
        """Validate filter complexity."""
        issues = []
        complexity = parsed_filter.get_complexity_score()

        if complexity > self.max_complexity:
            issues.append(
                ValidationIssue(
                    severity=self.severity,
                    code="HIGH_COMPLEXITY",
                    message=(
                        f"Filter complexity ({complexity}) exceeds "
                        f"recommended maximum ({self.max_complexity})"
                    ),
                    suggestion=(
                        "Consider simplifying the filter or breaking it "
                        "into multiple operations"
                    ),
                ),
            )

        return issues


class SecurityRule(ValidationRule):
    """Rule for security-related validation."""

    def __init__(self) -> None:
        super().__init__(
            name="security",
            description="Security validation for potential attacks",
            severity=ValidationSeverity.WARNING,
        )

        # Patterns that might indicate injection attempts
        self._suspicious_patterns = [
            r"\(\s*\*\s*\)",  # (*)
            r"\(\s*\|\s*\)",  # (|)
            r"\(\s*&\s*\)",  # (&)
            r"\(\s*!\s*\)",  # (!)
        ]

    def validate(
        self,
        parsed_filter: ParsedFilter,
        context: dict[str, Any],
    ) -> list[ValidationIssue]:
        """Validate security aspects."""
        issues = []

        def check_security(filter_node: ParsedFilter) -> None:
            if filter_node.value:
                # Check for suspicious patterns in values
                issues.extend(
                    ValidationIssue(
                        severity=self.severity,
                        code="SUSPICIOUS_PATTERN",
                        message=(
                            f"Potentially suspicious pattern in filter value: "
                            f"{filter_node.value}"
                        ),
                        attribute=filter_node.attribute,
                        suggestion=(
                            "Ensure filter values are properly escaped and validated"
                        ),
                    )
                    for pattern in self._suspicious_patterns
                    if re.search(pattern, filter_node.value)
                )

                # Check for excessively long values (potential DoS)
                if len(filter_node.value) > DEFAULT_LARGE_LIMIT:
                    issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.WARNING,
                            code="LONG_VALUE",
                            message=(
                                f"Very long filter value "
                                f"({len(filter_node.value)} characters) "
                                f"may impact performance"
                            ),
                            attribute=filter_node.attribute,
                            suggestion="Consider limiting filter value length",
                        ),
                    )

            # Recursively check children
            for child in filter_node.children:
                check_security(child)

        check_security(parsed_filter)

        # Check for overly broad filters
        if self._is_overly_broad(parsed_filter):
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="OVERLY_BROAD",
                    message="Filter may return excessive results",
                    suggestion="Add more specific constraints to limit result set",
                ),
            )

        return issues

    def _is_overly_broad(self, parsed_filter: ParsedFilter) -> bool:
        """Check if filter is overly broad."""
        # Simplified heuristic - can be enhanced
        if parsed_filter.filter_type == FilterType.PRESENT:
            return True

        return bool(
            parsed_filter.filter_type == FilterType.SUBSTRING
            and parsed_filter.value
            and parsed_filter.value.count("*") > SUBSTRING_WILDCARD_LIMIT,
        )


class PerformanceRule(ValidationRule):
    """Rule for performance-related validation."""

    def __init__(self) -> None:
        super().__init__(
            name="performance",
            description="Performance impact validation",
            severity=ValidationSeverity.HINT,
        )

    def validate(
        self,
        parsed_filter: ParsedFilter,
        context: dict[str, Any],
    ) -> list[ValidationIssue]:
        """Validate performance characteristics."""
        issues = []

        def check_performance(filter_node: ParsedFilter) -> None:
            # Check for substring filters
            if filter_node.filter_type == FilterType.SUBSTRING:
                if filter_node.value and filter_node.value.startswith("*"):
                    issues.append(
                        ValidationIssue(
                            severity=ValidationSeverity.HINT,
                            code="LEADING_WILDCARD",
                            message=(
                                f"Leading wildcard in substring filter may be slow: "
                                f"{filter_node.attribute}={filter_node.value}"
                            ),
                            attribute=filter_node.attribute,
                            suggestion=(
                                "Consider using indexed attributes or "
                                "avoiding leading wildcards"
                            ),
                        ),
                    )

            # Check for presence filters
            if filter_node.filter_type == FilterType.PRESENT:
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.INFO,
                        code="PRESENCE_FILTER",
                        message=f"Presence filter may be slow on large directories: {filter_node.attribute}=*",
                        attribute=filter_node.attribute,
                        suggestion="Ensure attribute is indexed for better performance",
                    ),
                )

            # Recursively check children
            for child in filter_node.children:
                check_performance(child)

        check_performance(parsed_filter)
        return issues


class SchemaRule(ValidationRule):
    """Rule for schema-aware validation."""

    def __init__(self, schema: dict[str, Any] | None = None) -> None:
        super().__init__(
            name="schema",
            description="LDAP schema validation",
            severity=ValidationSeverity.WARNING,
        )
        self.schema = schema or {}

    def validate(
        self,
        parsed_filter: ParsedFilter,
        context: dict[str, Any],
    ) -> list[ValidationIssue]:
        """Validate against LDAP schema."""
        issues: list[ValidationIssue] = []

        if not self.schema:
            return issues

        def check_schema(filter_node: ParsedFilter) -> None:
            if filter_node.attribute:
                # Check if attribute exists in schema
                if filter_node.attribute not in self.schema:
                    issues.append(
                        ValidationIssue(
                            severity=self.severity,
                            code="UNKNOWN_ATTRIBUTE",
                            message=f"Unknown attribute: {filter_node.attribute}",
                            attribute=filter_node.attribute,
                            suggestion="Verify attribute name or add to schema",
                        ),
                    )
                else:
                    # Validate operator compatibility
                    attr_info = self.schema[filter_node.attribute]
                    syntax = attr_info.get("syntax", "")

                    if (
                        filter_node.operator in {">=", "<="}
                        and "numeric" not in syntax.lower()
                        and "time" not in syntax.lower()
                    ):
                        issues.append(
                            ValidationIssue(
                                severity=ValidationSeverity.WARNING,
                                code="INCOMPATIBLE_OPERATOR",
                                message=f"Ordering operator {filter_node.operator} may not work with attribute {filter_node.attribute}",
                                attribute=filter_node.attribute,
                                suggestion="Use equality or substring filters for non-numeric attributes",
                            ),
                        )

            # Recursively check children
            for child in filter_node.children:
                check_schema(child)

        check_schema(parsed_filter)
        return issues


class FilterValidator:
    """Comprehensive LDAP filter validator.

    This class provides multi-level validation of LDAP filters including
    syntax, semantics, security, and performance analysis.

    Example:
        >>> validator = FilterValidator(level=ValidationLevel.ENTERPRISE)
        >>> result = validator.validate("(&(cn=john)(mail=*admin*)")
        >>> print(result.is_valid)
        >>> for issue in result.warnings:
        ...     print(issue)

    """

    def __init__(
        self,
        level: ValidationLevel = ValidationLevel.STANDARD,
        schema: dict[str, Any] | None = None,
        custom_rules: list[ValidationRule] | None = None,
        schema_aware: bool = False,
    ) -> None:
        """Initialize filter validator.

        Args:
            level: Validation strictness level
            schema: Optional LDAP schema for validation
            custom_rules: Additional custom validation rules
            schema_aware: Enable schema-aware validation

        """
        self.level = level
        self.schema = schema
        self.schema_aware = schema_aware
        self._parser = FilterParser()

        # Initialize validation rules based on level
        self._rules = self._initialize_rules(custom_rules or [])

    def validate(self, filter_string: str) -> FilterValidationResult:
        """Validate LDAP filter string.

        Args:
            filter_string: LDAP filter to validate

        Returns:
            Comprehensive validation result

        """
        issues = []
        parsed_filter = None

        # Step 1: Syntax validation
        try:
            parsed_filter = self._parser.parse(filter_string)
        except FilterSyntaxError as e:
            issues.append(
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="SYNTAX_ERROR",
                    message=str(e),
                    position=getattr(e, "position", None),
                    suggestion="Check filter syntax and parentheses balance",
                ),
            )

            # Return early for syntax errors
            return FilterValidationResult(
                is_valid=False,
                filter_string=filter_string,
                issues=issues,
            )

        # Step 2: Apply validation rules
        context = {
            "schema": self.schema,
            "level": self.level,
            "schema_aware": self.schema_aware,
        }

        for rule in self._rules:
            try:
                rule_issues = rule.validate(parsed_filter, context)
                issues.extend(rule_issues)
            except Exception as e:
                # Log rule validation errors but don't fail validation
                issues.append(
                    ValidationIssue(
                        severity=ValidationSeverity.WARNING,
                        code="RULE_ERROR",
                        message=f"Validation rule '{rule.name}' failed: {e}",
                        suggestion="Contact administrator about validation rule configuration",
                    ),
                )

        # Step 3: Calculate ratings
        complexity_score = parsed_filter.get_complexity_score()
        performance_rating = self._calculate_performance_rating(parsed_filter, issues)
        security_rating = self._calculate_security_rating(issues)

        # Step 4: Determine overall validity
        has_errors = any(issue.severity == ValidationSeverity.ERROR for issue in issues)
        is_valid = not has_errors

        return FilterValidationResult(
            is_valid=is_valid,
            filter_string=filter_string,
            parsed_filter=parsed_filter,
            issues=issues,
            complexity_score=complexity_score,
            performance_rating=performance_rating,
            security_rating=security_rating,
        )

    def _initialize_rules(
        self,
        custom_rules: list[ValidationRule],
    ) -> list[ValidationRule]:
        """Initialize validation rules based on validation level."""
        rules = []

        # Basic level: syntax only (handled by parser)
        rules.extend((SyntaxRule(), AttributeNameRule()))

        if self.level in {
            ValidationLevel.STANDARD,
            ValidationLevel.STRICT,
            ValidationLevel.ENTERPRISE,
        }:
            # Add semantic validation
            rules.append(ComplexityRule())

            if self.schema_aware and self.schema:
                rules.append(SchemaRule(self.schema))

        if self.level in {ValidationLevel.STRICT, ValidationLevel.ENTERPRISE}:
            # Add security validation
            rules.append(SecurityRule())

        if self.level == ValidationLevel.ENTERPRISE:
            # Add performance validation
            rules.append(PerformanceRule())

        # Add custom rules
        rules.extend(custom_rules)

        return rules

    def _calculate_performance_rating(
        self,
        parsed_filter: ParsedFilter,
        issues: list[ValidationIssue],
    ) -> str:
        """Calculate performance rating based on filter and issues."""
        performance_issues = [
            issue
            for issue in issues
            if issue.code in {"LEADING_WILDCARD", "PRESENCE_FILTER", "HIGH_COMPLEXITY"}
        ]

        complexity = parsed_filter.get_complexity_score()

        if complexity <= EXCELLENT_COMPLEXITY_THRESHOLD and not performance_issues:
            return "excellent"
        if (
            complexity <= GOOD_COMPLEXITY_THRESHOLD
            and len(performance_issues) <= MAX_PERFORMANCE_ISSUES_GOOD
        ):
            return "good"
        if (
            complexity <= DEFAULT_TIMEOUT_SECONDS
            and len(performance_issues) <= MAX_SECURITY_ISSUES_FAIR
        ):
            return "fair"
        return "poor"

    def _calculate_security_rating(self, issues: list[ValidationIssue]) -> str:
        """Calculate security rating based on security issues."""
        security_issues = [
            issue
            for issue in issues
            if issue.code in {"SUSPICIOUS_PATTERN", "OVERLY_BROAD", "LONG_VALUE"}
        ]

        if not security_issues:
            return "secure"
        if len(security_issues) <= MAX_SECURITY_ISSUES_WARNING:
            return "warning"
        if len(security_issues) <= MAX_SECURITY_ISSUES_FAIR:
            return "risk"
        return "danger"


# Convenience functions
def validate_filter(
    filter_string: str,
    level: ValidationLevel = ValidationLevel.STANDARD,
) -> FilterValidationResult:
    """Validate LDAP filter with specified level.

    Args:
        filter_string: LDAP filter to validate
        level: Validation strictness level

    Returns:
        Validation result

    """
    validator = FilterValidator(level=level)
    return validator.validate(filter_string)


def is_filter_secure(filter_string: str) -> bool:
    """Quick security check for LDAP filter.

    Args:
        filter_string: LDAP filter to check

    Returns:
        True if filter appears secure, False otherwise

    """
    result = validate_filter(filter_string, ValidationLevel.STRICT)
    security_issues = [
        issue
        for issue in result.issues
        if issue.severity in {ValidationSeverity.ERROR, ValidationSeverity.WARNING}
        and issue.code in {"SUSPICIOUS_PATTERN", "OVERLY_BROAD", "LONG_VALUE"}
    ]
    return len(security_issues) == 0


def get_filter_performance_rating(filter_string: str) -> str:
    """Get performance rating for LDAP filter.

    Args:
        filter_string: LDAP filter to analyze

    Returns:
        Performance rating (excellent, good, fair, poor)

    """
    result = validate_filter(filter_string, ValidationLevel.ENTERPRISE)
    return result.performance_rating


# TODO: Integration points for implementation:
#
# 1. Schema Integration:
#    - Real LDAP schema loading and validation
#    - Schema change detection and cache invalidation
#    - Multi-schema support for different directory types
#
# 2. Performance Integration:
#    - Integration with LDAP server statistics
#    - Query execution plan analysis
#    - Index usage recommendations
#
# 3. Security Integration:
#    - Advanced injection detection algorithms
#    - Integration with security monitoring systems
#    - Threat intelligence for suspicious patterns
#
# 4. Configuration Management:
#    - Externalized validation rules configuration
#    - Environment-specific validation policies
#    - Dynamic rule loading and updates
#
# 5. Monitoring and Reporting:
#    - Validation metrics collection
#    - Performance trending analysis
#    - Security incident reporting
#
# 6. Testing Framework:
#    - Comprehensive test suite for all validation rules
#    - Performance testing for large filter sets
#    - Security testing for known attack patterns
#    - Regression testing for validation accuracy
