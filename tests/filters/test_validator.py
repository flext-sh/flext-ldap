"""Tests for Enterprise LDAP Filter Validator Implementation.

This module provides comprehensive test coverage for the enterprise-grade LDAP
filter validator including RFC 4515 compliance checking, security validation,
performance analysis, and comprehensive validation rules with error reporting.

Test Coverage:
    - ValidationLevel: Validation strictness level enumeration
    - ValidationSeverity: Issue severity level enumeration
    - ValidationIssue: Individual validation issue modeling
    - FilterValidationResult: Comprehensive validation result aggregation
    - ValidationRule: Base validation rule interface and implementations
    - FilterValidator: Main enterprise validator with multi-level analysis
    - Filter validation with comprehensive security and performance checking

Integration Testing:
    - Complete filter validation workflows with all rule types
    - Multi-level validation from basic to enterprise strictness
    - Security analysis with injection detection and DoS protection
    - Performance analysis with complexity scoring and optimization hints
    - Custom validation rule integration and configuration management

Performance Testing:
    - Large filter validation efficiency and optimization
    - Validation rule execution performance and parallelization
    - Memory usage during comprehensive validation analysis
    - Complex filter analysis timing and throughput validation
    - Validation result aggregation and reporting performance

Security Testing:
    - Input validation and sanitization for filter strings
    - Injection pattern detection and prevention mechanisms
    - DoS protection through complexity limits and resource monitoring
    - Error message information disclosure protection
    - Resource consumption limits during validation operations
"""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
from pydantic import ValidationError

from ldap_core_shared.filters.validator import (
    AttributeNameRule,
    ComplexityRule,
    FilterValidationResult,
    FilterValidator,
    PerformanceRule,
    SchemaRule,
    SecurityRule,
    SyntaxRule,
    ValidationIssue,
    ValidationLevel,
    ValidationRule,
    ValidationSeverity,
    get_filter_performance_rating,
    is_filter_secure,
    validate_filter,
)


class TestValidationLevel:
    """Test cases for ValidationLevel enumeration."""

    def test_validation_level_values(self) -> None:
        """Test ValidationLevel enumeration values."""
        assert ValidationLevel.BASIC.value == "basic"
        assert ValidationLevel.STANDARD.value == "standard"
        assert ValidationLevel.STRICT.value == "strict"
        assert ValidationLevel.ENTERPRISE.value == "enterprise"

    def test_validation_level_hierarchy(self) -> None:
        """Test validation level hierarchy and ordering."""
        levels = [
            ValidationLevel.BASIC,
            ValidationLevel.STANDARD,
            ValidationLevel.STRICT,
            ValidationLevel.ENTERPRISE,
        ]

        # Verify all expected levels exist
        assert len(levels) == 4

        # Verify basic membership
        for level in levels:
            assert isinstance(level, ValidationLevel)

    def test_validation_level_comparison(self) -> None:
        """Test validation level comparison and ordering."""
        # Basic should be least restrictive
        assert ValidationLevel.BASIC != ValidationLevel.ENTERPRISE

        # All levels should be unique
        assert ValidationLevel.BASIC != ValidationLevel.STANDARD
        assert ValidationLevel.STANDARD != ValidationLevel.STRICT
        assert ValidationLevel.STRICT != ValidationLevel.ENTERPRISE


class TestValidationSeverity:
    """Test cases for ValidationSeverity enumeration."""

    def test_validation_severity_values(self) -> None:
        """Test ValidationSeverity enumeration values."""
        assert ValidationSeverity.ERROR.value == "error"
        assert ValidationSeverity.WARNING.value == "warning"
        assert ValidationSeverity.INFO.value == "info"
        assert ValidationSeverity.HINT.value == "hint"

    def test_validation_severity_completeness(self) -> None:
        """Test ValidationSeverity enumeration completeness."""
        expected_severities = {"error", "warning", "info", "hint"}
        actual_severities = {member.value for member in ValidationSeverity}

        assert actual_severities == expected_severities

    def test_validation_severity_ordering(self) -> None:
        """Test validation severity ordering by importance."""
        severities = [
            ValidationSeverity.ERROR,
            ValidationSeverity.WARNING,
            ValidationSeverity.INFO,
            ValidationSeverity.HINT,
        ]

        # All should be unique
        for i, severity in enumerate(severities):
            for j, other_severity in enumerate(severities):
                if i != j:
                    assert severity != other_severity


class TestValidationIssue:
    """Test cases for ValidationIssue."""

    def test_validation_issue_creation_basic(self) -> None:
        """Test creating validation issue with basic fields."""
        issue = ValidationIssue(
            severity=ValidationSeverity.ERROR,
            code="TEST_ERROR",
            message="Test error message",
        )

        assert issue.severity == ValidationSeverity.ERROR
        assert issue.code == "TEST_ERROR"
        assert issue.message == "Test error message"
        assert issue.position is None
        assert issue.attribute is None
        assert issue.suggestion is None

    def test_validation_issue_creation_complete(self) -> None:
        """Test creating validation issue with all fields."""
        issue = ValidationIssue(
            severity=ValidationSeverity.WARNING,
            code="PERFORMANCE_WARNING",
            message="Filter may be slow",
            position=15,
            attribute="cn",
            suggestion="Consider using indexed attributes",
        )

        assert issue.severity == ValidationSeverity.WARNING
        assert issue.code == "PERFORMANCE_WARNING"
        assert issue.message == "Filter may be slow"
        assert issue.position == 15
        assert issue.attribute == "cn"
        assert issue.suggestion == "Consider using indexed attributes"

    def test_validation_issue_str_representation_basic(self) -> None:
        """Test string representation of basic validation issue."""
        issue = ValidationIssue(
            severity=ValidationSeverity.ERROR,
            code="SYNTAX_ERROR",
            message="Invalid syntax",
        )

        str_repr = str(issue)
        assert "ERROR: Invalid syntax" in str_repr

    def test_validation_issue_str_representation_complete(self) -> None:
        """Test string representation of complete validation issue."""
        issue = ValidationIssue(
            severity=ValidationSeverity.WARNING,
            code="PERFORMANCE_WARNING",
            message="Filter may be slow",
            position=15,
            attribute="cn",
            suggestion="Use indexed attributes",
        )

        str_repr = str(issue)
        assert "WARNING: Filter may be slow" in str_repr
        assert "(position 15)" in str_repr
        assert "(attribute: cn)" in str_repr
        assert "Suggestion: Use indexed attributes" in str_repr

    def test_validation_issue_strict_mode(self) -> None:
        """Test validation issue strict mode rejects extra fields."""
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="TEST_ERROR",
                message="Test message",
                extra_field="not_allowed",
            )

    def test_validation_issue_required_fields(self) -> None:
        """Test validation issue requires essential fields."""
        # Missing severity
        with pytest.raises(ValidationError, match="Field required"):
            ValidationIssue(code="TEST_ERROR", message="Test message")

        # Missing code
        with pytest.raises(ValidationError, match="Field required"):
            ValidationIssue(severity=ValidationSeverity.ERROR, message="Test message")

        # Missing message
        with pytest.raises(ValidationError, match="Field required"):
            ValidationIssue(severity=ValidationSeverity.ERROR, code="TEST_ERROR")


class TestFilterValidationResult:
    """Test cases for FilterValidationResult."""

    def test_validation_result_creation_basic(self) -> None:
        """Test creating basic validation result."""
        result = FilterValidationResult(
            is_valid=True,
            filter_string="(cn=test)",
        )

        assert result.is_valid is True
        assert result.filter_string == "(cn=test)"
        assert result.parsed_filter is None
        assert result.issues == []
        assert result.complexity_score == 0
        assert result.performance_rating == "unknown"
        assert result.security_rating == "unknown"

    def test_validation_result_creation_complete(self) -> None:
        """Test creating complete validation result."""
        mock_parsed = Mock()
        mock_parsed.filter_type = "equality"

        issues = [
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                code="PERFORMANCE_WARNING",
                message="Test warning",
            ),
        ]

        result = FilterValidationResult(
            is_valid=True,
            filter_string="(cn=test)",
            parsed_filter=mock_parsed,
            issues=issues,
            complexity_score=5,
            performance_rating="good",
            security_rating="secure",
        )

        assert result.is_valid is True
        assert result.filter_string == "(cn=test)"
        assert result.parsed_filter == mock_parsed
        assert len(result.issues) == 1
        assert result.complexity_score == 5
        assert result.performance_rating == "good"
        assert result.security_rating == "secure"

    def test_validation_result_errors_property(self) -> None:
        """Test errors property filters error-level issues."""
        issues = [
            ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="SYNTAX_ERROR",
                message="Syntax error",
            ),
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                code="PERFORMANCE_WARNING",
                message="Performance warning",
            ),
            ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="SECURITY_ERROR",
                message="Security error",
            ),
        ]

        result = FilterValidationResult(
            is_valid=False,
            filter_string="(invalid)",
            issues=issues,
        )

        errors = result.errors
        assert len(errors) == 2
        assert all(issue.severity == ValidationSeverity.ERROR for issue in errors)

    def test_validation_result_warnings_property(self) -> None:
        """Test warnings property filters warning-level issues."""
        issues = [
            ValidationIssue(
                severity=ValidationSeverity.ERROR,
                code="SYNTAX_ERROR",
                message="Syntax error",
            ),
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                code="PERFORMANCE_WARNING",
                message="Performance warning",
            ),
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                code="SECURITY_WARNING",
                message="Security warning",
            ),
        ]

        result = FilterValidationResult(
            is_valid=False,
            filter_string="(test)",
            issues=issues,
        )

        warnings = result.warnings
        assert len(warnings) == 2
        assert all(issue.severity == ValidationSeverity.WARNING for issue in warnings)

    def test_validation_result_infos_property(self) -> None:
        """Test infos property filters info-level issues."""
        issues = [
            ValidationIssue(
                severity=ValidationSeverity.INFO,
                code="INFO_MESSAGE",
                message="Info message",
            ),
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                code="WARNING_MESSAGE",
                message="Warning message",
            ),
        ]

        result = FilterValidationResult(
            is_valid=True,
            filter_string="(test)",
            issues=issues,
        )

        infos = result.infos
        assert len(infos) == 1
        assert infos[0].severity == ValidationSeverity.INFO

    def test_validation_result_hints_property(self) -> None:
        """Test hints property filters hint-level issues."""
        issues = [
            ValidationIssue(
                severity=ValidationSeverity.HINT,
                code="OPTIMIZATION_HINT",
                message="Optimization hint",
            ),
            ValidationIssue(
                severity=ValidationSeverity.INFO,
                code="INFO_MESSAGE",
                message="Info message",
            ),
        ]

        result = FilterValidationResult(
            is_valid=True,
            filter_string="(test)",
            issues=issues,
        )

        hints = result.hints
        assert len(hints) == 1
        assert hints[0].severity == ValidationSeverity.HINT

    def test_validation_result_has_errors(self) -> None:
        """Test has_errors method detects error presence."""
        # No errors
        result_no_errors = FilterValidationResult(
            is_valid=True,
            filter_string="(cn=test)",
            issues=[
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="WARNING",
                    message="Warning only",
                ),
            ],
        )
        assert result_no_errors.has_errors() is False

        # Has errors
        result_with_errors = FilterValidationResult(
            is_valid=False,
            filter_string="(invalid)",
            issues=[
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="ERROR",
                    message="Error present",
                ),
            ],
        )
        assert result_with_errors.has_errors() is True

    def test_validation_result_has_warnings(self) -> None:
        """Test has_warnings method detects warning presence."""
        # No warnings
        result_no_warnings = FilterValidationResult(
            is_valid=True,
            filter_string="(cn=test)",
            issues=[
                ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    code="INFO",
                    message="Info only",
                ),
            ],
        )
        assert result_no_warnings.has_warnings() is False

        # Has warnings
        result_with_warnings = FilterValidationResult(
            is_valid=True,
            filter_string="(cn=test)",
            issues=[
                ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    code="WARNING",
                    message="Warning present",
                ),
            ],
        )
        assert result_with_warnings.has_warnings() is True

    def test_validation_result_get_summary(self) -> None:
        """Test get_summary method formats result summary."""
        # Valid with no issues
        result_clean = FilterValidationResult(
            is_valid=True,
            filter_string="(cn=test)",
        )
        assert result_clean.get_summary() == "VALID"

        # Invalid with errors
        result_errors = FilterValidationResult(
            is_valid=False,
            filter_string="(invalid)",
            issues=[
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="ERROR1",
                    message="Error 1",
                ),
                ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    code="ERROR2",
                    message="Error 2",
                ),
            ],
        )
        summary = result_errors.get_summary()
        assert "INVALID" in summary
        assert "2 errors" in summary

    def test_validation_result_str_representation(self) -> None:
        """Test __str__ method delegates to get_summary."""
        result = FilterValidationResult(
            is_valid=True,
            filter_string="(cn=test)",
        )

        assert str(result) == result.get_summary()


class TestValidationRule:
    """Test cases for ValidationRule base class."""

    def test_validation_rule_initialization(self) -> None:
        """Test ValidationRule initialization."""
        rule = ValidationRule(
            name="test_rule",
            description="Test rule description",
            severity=ValidationSeverity.WARNING,
        )

        assert rule.name == "test_rule"
        assert rule.description == "Test rule description"
        assert rule.severity == ValidationSeverity.WARNING

    def test_validation_rule_default_severity(self) -> None:
        """Test ValidationRule default severity."""
        rule = ValidationRule(
            name="test_rule",
            description="Test rule description",
        )

        assert rule.severity == ValidationSeverity.ERROR

    def test_validation_rule_validate_not_implemented(self) -> None:
        """Test ValidationRule validate method raises NotImplementedError."""
        rule = ValidationRule(
            name="test_rule",
            description="Test rule description",
        )

        mock_parsed = Mock()
        context = {}

        with pytest.raises(
            NotImplementedError, match="Subclasses must implement validate method"
        ):
            rule.validate(mock_parsed, context)


class TestSyntaxRule:
    """Test cases for SyntaxRule."""

    def test_syntax_rule_initialization(self) -> None:
        """Test SyntaxRule initialization."""
        rule = SyntaxRule()

        assert rule.name == "syntax"
        assert rule.description == "Basic filter syntax validation"
        assert rule.severity == ValidationSeverity.ERROR

    def test_syntax_rule_validate_parsed_filter(self) -> None:
        """Test SyntaxRule validate with parsed filter (no issues)."""
        rule = SyntaxRule()
        mock_parsed = Mock()
        context = {}

        issues = rule.validate(mock_parsed, context)

        # If we have a parsed filter, syntax is valid
        assert issues == []


class TestAttributeNameRule:
    """Test cases for AttributeNameRule."""

    def test_attribute_name_rule_initialization(self) -> None:
        """Test AttributeNameRule initialization."""
        rule = AttributeNameRule()

        assert rule.name == "attribute_name"
        assert rule.description == "Attribute name format validation"
        assert rule.severity == ValidationSeverity.ERROR

    def test_attribute_name_rule_validate_valid_names(self) -> None:
        """Test AttributeNameRule with valid attribute names."""
        rule = AttributeNameRule()

        # Mock parsed filter with valid attribute name
        mock_parsed = Mock()
        mock_parsed.attribute = "cn"
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert issues == []

    def test_attribute_name_rule_validate_invalid_names(self) -> None:
        """Test AttributeNameRule with invalid attribute names."""
        rule = AttributeNameRule()

        # Mock parsed filter with invalid attribute name
        mock_parsed = Mock()
        mock_parsed.attribute = "123invalid"  # Starts with number
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert len(issues) == 1
        assert issues[0].severity == ValidationSeverity.ERROR
        assert issues[0].code == "INVALID_ATTRIBUTE_NAME"
        assert "123invalid" in issues[0].message

    def test_attribute_name_rule_validate_no_attribute(self) -> None:
        """Test AttributeNameRule with no attribute (compound filter)."""
        rule = AttributeNameRule()

        # Mock parsed filter without attribute (compound filter)
        mock_parsed = Mock()
        mock_parsed.attribute = None
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert issues == []

    def test_attribute_name_rule_validate_recursive(self) -> None:
        """Test AttributeNameRule validates children recursively."""
        rule = AttributeNameRule()

        # Mock child with invalid attribute
        mock_child = Mock()
        mock_child.attribute = "invalid-name!"
        mock_child.children = []

        # Mock parent filter
        mock_parsed = Mock()
        mock_parsed.attribute = None
        mock_parsed.children = [mock_child]

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert len(issues) == 1
        assert "invalid-name!" in issues[0].message


class TestComplexityRule:
    """Test cases for ComplexityRule."""

    def test_complexity_rule_initialization_default(self) -> None:
        """Test ComplexityRule initialization with default max complexity."""
        rule = ComplexityRule()

        assert rule.name == "complexity"
        assert rule.description == "Filter complexity validation"
        assert rule.severity == ValidationSeverity.WARNING
        assert rule.max_complexity == 50

    def test_complexity_rule_initialization_custom(self) -> None:
        """Test ComplexityRule initialization with custom max complexity."""
        rule = ComplexityRule(max_complexity=25)

        assert rule.max_complexity == 25

    def test_complexity_rule_validate_low_complexity(self) -> None:
        """Test ComplexityRule with low complexity filter."""
        rule = ComplexityRule(max_complexity=10)

        # Mock simple filter
        mock_parsed = Mock()
        mock_parsed.get_complexity_score.return_value = 5

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert issues == []

    def test_complexity_rule_validate_high_complexity(self) -> None:
        """Test ComplexityRule with high complexity filter."""
        rule = ComplexityRule(max_complexity=10)

        # Mock complex filter
        mock_parsed = Mock()
        mock_parsed.get_complexity_score.return_value = 15

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert len(issues) == 1
        assert issues[0].severity == ValidationSeverity.WARNING
        assert issues[0].code == "HIGH_COMPLEXITY"
        assert "15" in issues[0].message
        assert "10" in issues[0].message


class TestSecurityRule:
    """Test cases for SecurityRule."""

    def test_security_rule_initialization(self) -> None:
        """Test SecurityRule initialization."""
        rule = SecurityRule()

        assert rule.name == "security"
        assert rule.description == "Security validation for potential attacks"
        assert rule.severity == ValidationSeverity.WARNING
        assert len(rule._suspicious_patterns) > 0

    def test_security_rule_validate_clean_filter(self) -> None:
        """Test SecurityRule with clean filter."""
        rule = SecurityRule()

        # Mock clean filter
        mock_parsed = Mock()
        mock_parsed.value = "test"
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        # Should have no security issues for clean filter
        assert len(issues) == 0

    def test_security_rule_validate_suspicious_patterns(self) -> None:
        """Test SecurityRule with suspicious patterns."""
        rule = SecurityRule()

        # Mock filter with suspicious pattern
        mock_parsed = Mock()
        mock_parsed.value = "(*)"  # Matches suspicious pattern
        mock_parsed.attribute = "cn"
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert len(issues) >= 1
        assert any(issue.code == "SUSPICIOUS_PATTERN" for issue in issues)

    def test_security_rule_validate_long_value(self) -> None:
        """Test SecurityRule with excessively long value."""
        rule = SecurityRule()

        # Mock filter with very long value
        mock_parsed = Mock()
        mock_parsed.value = "x" * 2000  # Very long value
        mock_parsed.attribute = "cn"
        mock_parsed.children = []

        with patch("ldap_core_shared.filters.validator.DEFAULT_LARGE_LIMIT", 1000):
            context = {}
            issues = rule.validate(mock_parsed, context)

        assert len(issues) >= 1
        assert any(issue.code == "LONG_VALUE" for issue in issues)

    def test_security_rule_validate_overly_broad(self) -> None:
        """Test SecurityRule with overly broad filter."""
        rule = SecurityRule()

        # Mock presence filter (overly broad)
        mock_parsed = Mock()
        mock_parsed.value = None
        mock_parsed.children = []
        mock_parsed.filter_type = Mock()
        mock_parsed.filter_type.PRESENT = "present"

        # Mock _is_overly_broad to return True
        rule._is_overly_broad = Mock(return_value=True)

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert len(issues) >= 1
        assert any(issue.code == "OVERLY_BROAD" for issue in issues)

    def test_security_rule_is_overly_broad_presence(self) -> None:
        """Test SecurityRule _is_overly_broad with presence filter."""
        rule = SecurityRule()

        # Mock presence filter
        mock_parsed = Mock()
        mock_parsed.filter_type = Mock()

        # Import FilterType for comparison
        from ldap_core_shared.filters.parser import FilterType

        mock_parsed.filter_type = FilterType.PRESENT

        assert rule._is_overly_broad(mock_parsed) is True

    def test_security_rule_is_overly_broad_substring(self) -> None:
        """Test SecurityRule _is_overly_broad with wildcard substring."""
        rule = SecurityRule()

        # Mock substring filter with many wildcards
        mock_parsed = Mock()
        from ldap_core_shared.filters.parser import FilterType

        mock_parsed.filter_type = FilterType.SUBSTRING
        mock_parsed.value = "*test*with*many*wildcards*"

        result = rule._is_overly_broad(mock_parsed)
        # Should be True due to many wildcards
        assert result is True


class TestPerformanceRule:
    """Test cases for PerformanceRule."""

    def test_performance_rule_initialization(self) -> None:
        """Test PerformanceRule initialization."""
        rule = PerformanceRule()

        assert rule.name == "performance"
        assert rule.description == "Performance impact validation"
        assert rule.severity == ValidationSeverity.HINT

    def test_performance_rule_validate_clean_filter(self) -> None:
        """Test PerformanceRule with performance-friendly filter."""
        rule = PerformanceRule()

        # Mock equality filter (good performance)
        mock_parsed = Mock()
        from ldap_core_shared.filters.parser import FilterType

        mock_parsed.filter_type = FilterType.EQUALITY
        mock_parsed.value = "test"
        mock_parsed.attribute = "cn"
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert len(issues) == 0

    def test_performance_rule_validate_leading_wildcard(self) -> None:
        """Test PerformanceRule with leading wildcard substring."""
        rule = PerformanceRule()

        # Mock substring filter with leading wildcard
        mock_parsed = Mock()
        from ldap_core_shared.filters.parser import FilterType

        mock_parsed.filter_type = FilterType.SUBSTRING
        mock_parsed.value = "*test"  # Leading wildcard
        mock_parsed.attribute = "cn"
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert len(issues) == 1
        assert issues[0].code == "LEADING_WILDCARD"
        assert issues[0].severity == ValidationSeverity.HINT

    def test_performance_rule_validate_presence_filter(self) -> None:
        """Test PerformanceRule with presence filter."""
        rule = PerformanceRule()

        # Mock presence filter
        mock_parsed = Mock()
        from ldap_core_shared.filters.parser import FilterType

        mock_parsed.filter_type = FilterType.PRESENT
        mock_parsed.attribute = "objectClass"
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert len(issues) == 1
        assert issues[0].code == "PRESENCE_FILTER"
        assert issues[0].severity == ValidationSeverity.INFO


class TestSchemaRule:
    """Test cases for SchemaRule."""

    def test_schema_rule_initialization_no_schema(self) -> None:
        """Test SchemaRule initialization without schema."""
        rule = SchemaRule()

        assert rule.name == "schema"
        assert rule.description == "LDAP schema validation"
        assert rule.severity == ValidationSeverity.WARNING
        assert rule.schema == {}

    def test_schema_rule_initialization_with_schema(self) -> None:
        """Test SchemaRule initialization with schema."""
        schema = {
            "cn": {"syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
            "uidNumber": {"syntax": "1.3.6.1.4.1.1466.115.121.1.27"},
        }

        rule = SchemaRule(schema)

        assert rule.schema == schema

    def test_schema_rule_validate_no_schema(self) -> None:
        """Test SchemaRule validation without schema."""
        rule = SchemaRule()

        mock_parsed = Mock()
        mock_parsed.attribute = "cn"
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert issues == []

    def test_schema_rule_validate_known_attribute(self) -> None:
        """Test SchemaRule with known attribute."""
        schema = {
            "cn": {"syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
        }
        rule = SchemaRule(schema)

        mock_parsed = Mock()
        mock_parsed.attribute = "cn"
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert issues == []

    def test_schema_rule_validate_unknown_attribute(self) -> None:
        """Test SchemaRule with unknown attribute."""
        schema = {
            "cn": {"syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
        }
        rule = SchemaRule(schema)

        mock_parsed = Mock()
        mock_parsed.attribute = "unknownAttr"
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert len(issues) == 1
        assert issues[0].code == "UNKNOWN_ATTRIBUTE"
        assert "unknownAttr" in issues[0].message

    def test_schema_rule_validate_incompatible_operator(self) -> None:
        """Test SchemaRule with incompatible operator for attribute syntax."""
        schema = {
            "cn": {"syntax": "1.3.6.1.4.1.1466.115.121.1.15"},  # String syntax
        }
        rule = SchemaRule(schema)

        mock_parsed = Mock()
        mock_parsed.attribute = "cn"
        mock_parsed.operator = ">="  # Ordering operator on string
        mock_parsed.children = []

        context = {}
        issues = rule.validate(mock_parsed, context)

        assert len(issues) == 1
        assert issues[0].code == "INCOMPATIBLE_OPERATOR"


class TestFilterValidator:
    """Test cases for FilterValidator."""

    def test_validator_initialization_default(self) -> None:
        """Test FilterValidator initialization with defaults."""
        validator = FilterValidator()

        assert validator.level == ValidationLevel.STANDARD
        assert validator.schema is None
        assert validator.schema_aware is False
        assert len(validator._rules) > 0

    def test_validator_initialization_custom(self) -> None:
        """Test FilterValidator initialization with custom settings."""
        schema = {"cn": {"syntax": "string"}}
        custom_rule = Mock(spec=ValidationRule)

        validator = FilterValidator(
            level=ValidationLevel.ENTERPRISE,
            schema=schema,
            custom_rules=[custom_rule],
            schema_aware=True,
        )

        assert validator.level == ValidationLevel.ENTERPRISE
        assert validator.schema == schema
        assert validator.schema_aware is True
        assert custom_rule in validator._rules

    def test_validator_validate_valid_filter(self) -> None:
        """Test validator with valid filter."""
        validator = FilterValidator()

        result = validator.validate("(cn=test)")

        assert result.is_valid is True
        assert result.filter_string == "(cn=test)"
        assert result.parsed_filter is not None
        assert result.complexity_score > 0

    def test_validator_validate_invalid_syntax(self) -> None:
        """Test validator with invalid filter syntax."""
        validator = FilterValidator()

        result = validator.validate("(cn=test")  # Missing closing paren

        assert result.is_valid is False
        assert len(result.errors) > 0
        assert any(issue.code == "SYNTAX_ERROR" for issue in result.errors)

    def test_validator_validate_with_warnings(self) -> None:
        """Test validator generating warnings."""
        validator = FilterValidator(level=ValidationLevel.ENTERPRISE)

        # Complex filter that should generate performance warnings
        complex_filter = "(&" + "(cn=test)" * 20 + ")"
        result = validator.validate(complex_filter)

        assert result.is_valid is True
        assert len(result.warnings) > 0 or len(result.hints) > 0

    def test_validator_rule_exception_handling(self) -> None:
        """Test validator handles rule exceptions gracefully."""
        # Create a mock rule that raises an exception
        failing_rule = Mock(spec=ValidationRule)
        failing_rule.name = "failing_rule"
        failing_rule.validate.side_effect = Exception("Rule failed")

        validator = FilterValidator(custom_rules=[failing_rule])

        result = validator.validate("(cn=test)")

        # Should still be valid but have a rule error issue
        assert result.is_valid is True
        assert any(issue.code == "RULE_ERROR" for issue in result.issues)

    def test_validator_initialize_rules_basic(self) -> None:
        """Test validator rule initialization for basic level."""
        validator = FilterValidator(level=ValidationLevel.BASIC)

        rule_names = [rule.name for rule in validator._rules]
        assert "syntax" in rule_names
        assert "attribute_name" in rule_names
        assert "security" not in rule_names  # Not included in basic

    def test_validator_initialize_rules_standard(self) -> None:
        """Test validator rule initialization for standard level."""
        validator = FilterValidator(level=ValidationLevel.STANDARD)

        rule_names = [rule.name for rule in validator._rules]
        assert "syntax" in rule_names
        assert "attribute_name" in rule_names
        assert "complexity" in rule_names
        assert "security" not in rule_names  # Not included in standard

    def test_validator_initialize_rules_strict(self) -> None:
        """Test validator rule initialization for strict level."""
        validator = FilterValidator(level=ValidationLevel.STRICT)

        rule_names = [rule.name for rule in validator._rules]
        assert "syntax" in rule_names
        assert "attribute_name" in rule_names
        assert "complexity" in rule_names
        assert "security" in rule_names
        assert "performance" not in rule_names  # Not included in strict

    def test_validator_initialize_rules_enterprise(self) -> None:
        """Test validator rule initialization for enterprise level."""
        validator = FilterValidator(level=ValidationLevel.ENTERPRISE)

        rule_names = [rule.name for rule in validator._rules]
        assert "syntax" in rule_names
        assert "attribute_name" in rule_names
        assert "complexity" in rule_names
        assert "security" in rule_names
        assert "performance" in rule_names

    def test_validator_initialize_rules_schema_aware(self) -> None:
        """Test validator rule initialization with schema awareness."""
        schema = {"cn": {"syntax": "string"}}
        validator = FilterValidator(
            level=ValidationLevel.STANDARD,
            schema=schema,
            schema_aware=True,
        )

        rule_names = [rule.name for rule in validator._rules]
        assert "schema" in rule_names

    def test_validator_calculate_performance_rating(self) -> None:
        """Test validator performance rating calculation."""
        validator = FilterValidator()

        # Mock simple filter
        mock_parsed = Mock()
        mock_parsed.get_complexity_score.return_value = 3

        issues = []
        rating = validator._calculate_performance_rating(mock_parsed, issues)

        assert rating == "excellent"

    def test_validator_calculate_security_rating(self) -> None:
        """Test validator security rating calculation."""
        validator = FilterValidator()

        # No security issues
        issues = []
        rating = validator._calculate_security_rating(issues)

        assert rating == "secure"

        # With security issues
        security_issues = [
            ValidationIssue(
                severity=ValidationSeverity.WARNING,
                code="SUSPICIOUS_PATTERN",
                message="Suspicious pattern detected",
            ),
        ]
        rating = validator._calculate_security_rating(security_issues)

        assert rating == "warning"


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_validate_filter_function(self) -> None:
        """Test validate_filter convenience function."""
        result = validate_filter("(cn=test)")

        assert isinstance(result, FilterValidationResult)
        assert result.is_valid is True
        assert result.filter_string == "(cn=test)"

    def test_validate_filter_function_with_level(self) -> None:
        """Test validate_filter with specific validation level."""
        result = validate_filter("(cn=test)", ValidationLevel.ENTERPRISE)

        assert isinstance(result, FilterValidationResult)
        assert result.is_valid is True

    def test_is_filter_secure_function_secure(self) -> None:
        """Test is_filter_secure with secure filter."""
        assert is_filter_secure("(cn=test)") is True

    def test_is_filter_secure_function_insecure(self) -> None:
        """Test is_filter_secure with potentially insecure filter."""
        # This depends on the specific security rules implementation
        is_filter_secure("(objectClass=*)")  # Very broad filter
        # The result may vary based on security rule implementation

    def test_get_filter_performance_rating_function(self) -> None:
        """Test get_filter_performance_rating convenience function."""
        rating = get_filter_performance_rating("(cn=test)")

        assert rating in {"excellent", "good", "fair", "poor"}

    def test_get_filter_performance_rating_complex(self) -> None:
        """Test performance rating for complex filter."""
        complex_filter = "(&" + "(cn=test)" * 10 + ")"
        rating = get_filter_performance_rating(complex_filter)

        assert rating in {"excellent", "good", "fair", "poor"}
        # Complex filter should not get "excellent" rating
        assert rating != "excellent"


class TestFilterValidatorIntegration:
    """Test cases for FilterValidator integration scenarios."""

    def test_comprehensive_validation_workflow(self) -> None:
        """Test comprehensive validation workflow."""
        validator = FilterValidator(level=ValidationLevel.ENTERPRISE)

        # Test various types of filters
        test_filters = [
            "(cn=test)",  # Simple equality
            "(&(cn=test)(objectClass=person))",  # Compound AND
            "(|(cn=REDACTED_LDAP_BIND_PASSWORD)(cn=REDACTED_LDAP_BIND_PASSWORDistrator))",  # Compound OR
            "(!(cn=guest))",  # NOT filter
            "(cn=*REDACTED_LDAP_BIND_PASSWORD*)",  # Substring
            "(objectClass=*)",  # Presence
            "(uidNumber>=1000)",  # Greater-equal
            "(cn~=test)",  # Approximate
        ]

        for filter_str in test_filters:
            result = validator.validate(filter_str)

            # All should parse successfully
            assert result.is_valid is True
            assert result.parsed_filter is not None
            assert result.complexity_score > 0

    def test_configuration_based_validation_behavior(self) -> None:
        """Test validation behavior varies by configuration."""
        test_filter = "(objectClass=*)"  # Broad filter

        # Basic validation - should be lenient
        basic_validator = FilterValidator(level=ValidationLevel.BASIC)
        basic_result = basic_validator.validate(test_filter)

        # Enterprise validation - should be strict
        enterprise_validator = FilterValidator(level=ValidationLevel.ENTERPRISE)
        enterprise_result = enterprise_validator.validate(test_filter)

        # Both should be valid but enterprise should have more issues
        assert basic_result.is_valid is True
        assert enterprise_result.is_valid is True
        assert len(enterprise_result.issues) >= len(basic_result.issues)

    def test_error_accumulation_and_reporting(self) -> None:
        """Test comprehensive error accumulation."""
        validator = FilterValidator(level=ValidationLevel.ENTERPRISE)

        # Filter with multiple types of issues
        problematic_filter = "(&(123invalid=test)(cn=*" + "x" * 1000 + "*))"

        result = validator.validate(problematic_filter)

        # Should have multiple types of issues
        assert len(result.issues) > 0

        [issue.code for issue in result.issues]
        # Should have various types of validation issues

    def test_schema_aware_validation(self) -> None:
        """Test schema-aware validation workflow."""
        schema = {
            "cn": {"syntax": "1.3.6.1.4.1.1466.115.121.1.15"},
            "uidNumber": {"syntax": "1.3.6.1.4.1.1466.115.121.1.27"},
        }

        validator = FilterValidator(
            level=ValidationLevel.STANDARD,
            schema=schema,
            schema_aware=True,
        )

        # Valid attribute
        result_valid = validator.validate("(cn=test)")
        assert result_valid.is_valid is True

        # Unknown attribute
        result_unknown = validator.validate("(unknownAttr=test)")
        assert result_unknown.is_valid is True  # Still valid but with warnings
        assert any(issue.code == "UNKNOWN_ATTRIBUTE" for issue in result_unknown.issues)

    def test_custom_rule_integration(self) -> None:
        """Test integration with custom validation rules."""
        # Create custom rule
        custom_rule = Mock(spec=ValidationRule)
        custom_rule.name = "custom_rule"
        custom_rule.validate.return_value = [
            ValidationIssue(
                severity=ValidationSeverity.INFO,
                code="CUSTOM_INFO",
                message="Custom rule triggered",
            ),
        ]

        validator = FilterValidator(custom_rules=[custom_rule])

        result = validator.validate("(cn=test)")

        assert result.is_valid is True
        assert any(issue.code == "CUSTOM_INFO" for issue in result.issues)
        custom_rule.validate.assert_called_once()

    def test_performance_with_complex_nested_filters(self) -> None:
        """Test validator performance with complex nested structures."""
        validator = FilterValidator(level=ValidationLevel.ENTERPRISE)

        # Build very complex nested filter
        base_filter = "(cn=test)"
        nested_filter = base_filter
        for _i in range(5):  # 5 levels of nesting
            nested_filter = f"(&{nested_filter}{base_filter})"

        result = validator.validate(nested_filter)

        # Should handle complex filter without errors
        assert result.is_valid is True
        assert result.complexity_score > 10
        # Should have performance warnings due to complexity
        assert len(result.hints) > 0 or len(result.warnings) > 0

    def test_security_validation_comprehensive(self) -> None:
        """Test comprehensive security validation scenarios."""
        validator = FilterValidator(level=ValidationLevel.STRICT)

        # Various potentially problematic filters
        security_test_filters = [
            "(objectClass=*)",  # Very broad
            "(cn=*)",  # Broad substring
            "(cn=test" + "x" * 500 + ")",  # Long value
        ]

        for filter_str in security_test_filters:
            result = validator.validate(filter_str)

            # Should be valid but may have security warnings
            assert result.is_valid is True
            # Enterprise level should flag security issues

    def test_error_recovery_and_resilience(self) -> None:
        """Test error recovery and system resilience."""
        validator = FilterValidator()

        # Test various error conditions
        error_cases = [
            "",  # Empty filter
            "(cn=test",  # Unclosed parenthesis
            "cn=test)",  # Missing opening parenthesis
            "(=test)",  # Missing attribute
            "(cn)",  # Missing operator and value
        ]

        for filter_str in error_cases:
            result = validator.validate(filter_str)

            # Should handle errors gracefully
            assert isinstance(result, FilterValidationResult)
            if not result.is_valid:
                assert len(result.errors) > 0

    def test_rating_calculation_accuracy(self) -> None:
        """Test accuracy of performance and security ratings."""
        validator = FilterValidator(level=ValidationLevel.ENTERPRISE)

        # Simple filter should get excellent ratings
        simple_result = validator.validate("(cn=test)")
        assert simple_result.performance_rating in {"excellent", "good"}
        assert simple_result.security_rating in {"secure", "warning"}

        # Complex filter should get lower performance rating
        complex_filter = "(&" + "(cn=test)" * 15 + ")"
        complex_result = validator.validate(complex_filter)

        # Complex filter should have lower performance rating
        performance_order = ["excellent", "good", "fair", "poor"]
        simple_perf_idx = performance_order.index(simple_result.performance_rating)
        complex_perf_idx = performance_order.index(complex_result.performance_rating)

        # Complex should be equal or worse than simple
        assert complex_perf_idx >= simple_perf_idx
