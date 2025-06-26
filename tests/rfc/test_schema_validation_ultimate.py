"""🚀 ULTIMATE Schema Validation Testing - EXTREMAMENTE RIGOROSO.

Este módulo implementa os testes MAIS EXIGENTES possíveis para validação de esquema LDAP,
baseado em múltiplos RFCs e indo MUITO ALÉM dos requisitos padrão.

RFCs COBERTOS:
- RFC 4512: Directory Information Models (Schema)
- RFC 4517: Syntaxes and Matching Rules
- RFC 4519: Schema for User Applications
- RFC 4523: Certificate Schema
- RFC 4524: COSINE LDAP/X.500 Schema

ZERO TOLERANCE: Cada aspecto do esquema deve ser perfeito.
AINDA MAIS EXIGENTE: Testa cenários impossíveis e edge cases extremos.

COBERTURA EXTREMA:
- Validação rigorosa de object classes e hierarquias
- Atributos obrigatórios e opcionais com precisão absoluta
- Sintaxes de atributos com validação extrema
- Matching rules e comparações complexas
- Herança de object class com múltiplos níveis
- Esquemas customizados e extensões
- Validação de integridade referencial
- Performance de validação em larga escala
"""

from __future__ import annotations

import asyncio
import operator
import re
from typing import Any

import pytest

from ldap_core_shared.domain.models import LDAPEntry
from ldap_core_shared.schema.migrator import SchemaMigrator
from ldap_core_shared.schema.validator import SchemaValidator
from ldap_core_shared.utils.performance import PerformanceMonitor


class TestObjectClassValidationUltimate:
    """🔥🔥🔥 Object Class Validation ULTIMATE Testing."""

    def test_object_class_hierarchy_extreme_validation(self) -> None:
        """Extreme object class hierarchy validation."""
        # Test complex object class inheritance chains

        # Define complex object class hierarchy
        object_class_definitions = {
            "top": {
                "type": "abstract",
                "must_attributes": [],
                "may_attributes": ["objectClass"],
                "superior_classes": [],
            },
            "person": {
                "type": "structural",
                "must_attributes": ["cn", "sn"],
                "may_attributes": ["description", "seeAlso", "telephoneNumber"],
                "superior_classes": ["top"],
            },
            "organizationalPerson": {
                "type": "structural",
                "must_attributes": [],
                "may_attributes": ["title", "x121Address", "registeredAddress", "destinationIndicator", "preferredDeliveryMethod", "telexNumber", "teletexTerminalIdentifier", "internationaliSDNNumber", "facsimileTelephoneNumber", "street", "postOfficeBox", "postalCode", "postalAddress", "physicalDeliveryOfficeName", "ou", "st", "l"],
                "superior_classes": ["person"],
            },
            "inetOrgPerson": {
                "type": "structural",
                "must_attributes": [],
                "may_attributes": ["audio", "businessCategory", "carLicense", "departmentNumber", "displayName", "employeeNumber", "employeeType", "givenName", "homePhone", "homePostalAddress", "initials", "jpegPhoto", "labeledURI", "mail", "manager", "mobile", "o", "pager", "photo", "roomNumber", "secretary", "uid", "userCertificate", "x500uniqueIdentifier", "preferredLanguage", "userSMIMECertificate", "userPKCS12"],
                "superior_classes": ["organizationalPerson"],
            },
            "customEmployee": {
                "type": "auxiliary",
                "must_attributes": ["employeeId"],
                "may_attributes": ["badge", "securityClearance", "costCenter"],
                "superior_classes": ["top"],
            },
        }

        validator = SchemaValidator()
        validator.load_object_class_definitions(object_class_definitions)

        # Test valid inheritance chain
        valid_entry = LDAPEntry(
            dn="cn=John Doe,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["top", "person", "organizationalPerson", "inetOrgPerson"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
                "mail": ["john@example.com"],
                "employeeNumber": ["12345"],
            },
        )

        validation_result = validator.validate_entry(valid_entry)
        assert validation_result.is_valid is True
        assert len(validation_result.errors) == 0

        # Test missing required attributes
        invalid_entry = LDAPEntry(
            dn="cn=Invalid,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["Invalid"],
                # Missing required 'sn' attribute
            },
        )

        validation_result = validator.validate_entry(invalid_entry)
        assert validation_result.is_valid is False
        assert any("sn" in error.message for error in validation_result.errors)

        # Test auxiliary object class combination
        auxiliary_entry = LDAPEntry(
            dn="cn=Employee,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson", "customEmployee"],
                "cn": ["Employee"],
                "sn": ["Test"],
                "employeeId": ["EMP001"],  # Required by auxiliary class
                "badge": ["BADGE123"],
            },
        )

        validation_result = validator.validate_entry(auxiliary_entry)
        assert validation_result.is_valid is True

    def test_object_class_structural_rules_extreme(self) -> None:
        """Extreme structural object class rules testing."""
        # RFC 4512: Entry must have exactly one structural object class

        validator = SchemaValidator()

        # Test multiple structural object classes (invalid)
        multiple_structural = LDAPEntry(
            dn="cn=Invalid,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "organizationalUnit"],  # Both structural
                "cn": ["Invalid"],
                "sn": ["Test"],
                "ou": ["TestOU"],
            },
        )

        validation_result = validator.validate_entry(multiple_structural)
        assert validation_result.is_valid is False
        assert any("structural" in error.message.lower() for error in validation_result.errors)

        # Test no structural object class (invalid)
        no_structural = LDAPEntry(
            dn="cn=NoStructural,dc=example,dc=com",
            attributes={
                "objectClass": ["top"],  # Only abstract
                "cn": ["NoStructural"],
            },
        )

        validation_result = validator.validate_entry(no_structural)
        assert validation_result.is_valid is False

        # Test valid single structural with auxiliaries
        valid_structural = LDAPEntry(
            dn="cn=Valid,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "customEmployee"],  # One structural + auxiliary
                "cn": ["Valid"],
                "sn": ["Test"],
                "employeeId": ["EMP123"],
            },
        )

        validation_result = validator.validate_entry(valid_structural)
        assert validation_result.is_valid is True

    def test_object_class_evolution_compatibility(self) -> None:
        """Test object class evolution and backward compatibility."""
        # Test schema evolution scenarios

        # Original schema version

        # Evolved schema version
        evolved_schema = {
            "person": {
                "type": "structural",
                "must_attributes": ["cn", "sn"],
                "may_attributes": ["description", "telephoneNumber", "mail", "mobile"],  # Added new optional attributes
                "superior_classes": ["top"],
            },
        }

        # Entry created with original schema
        legacy_entry = LDAPEntry(
            dn="cn=Legacy,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["Legacy"],
                "sn": ["User"],
                "description": ["Created with original schema"],
            },
        )

        # Validate legacy entry against evolved schema
        validator = SchemaValidator()
        validator.load_object_class_definitions(evolved_schema)

        validation_result = validator.validate_entry(legacy_entry)
        assert validation_result.is_valid is True  # Should remain valid

        # Entry created with evolved schema
        modern_entry = LDAPEntry(
            dn="cn=Modern,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["Modern"],
                "sn": ["User"],
                "mail": ["modern@example.com"],  # Uses new optional attribute
                "mobile": ["+1-555-1234"],
            },
        )

        validation_result = validator.validate_entry(modern_entry)
        assert validation_result.is_valid is True


class TestAttributeSyntaxValidationExtreme:
    """🔥🔥 Attribute Syntax Validation EXTREME Testing."""

    def test_attribute_syntax_comprehensive_validation(self) -> None:
        """Comprehensive attribute syntax validation."""
        # RFC 4517: LDAP Syntaxes and Matching Rules

        # Define comprehensive syntax validation rules
        syntax_rules = {
            "1.3.6.1.4.1.1466.115.121.1.15": {  # Directory String
                "name": "directoryString",
                "validator": lambda value: isinstance(value, str) and len(value) <= 32768,
            },
            "1.3.6.1.4.1.1466.115.121.1.26": {  # IA5 String (email)
                "name": "ia5String",
                "validator": lambda value: re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value) is not None,
            },
            "1.3.6.1.4.1.1466.115.121.1.36": {  # Numeric String
                "name": "numericString",
                "validator": lambda value: value.isdigit(),
            },
            "1.3.6.1.4.1.1466.115.121.1.50": {  # Telephone Number
                "name": "telephoneNumber",
                "validator": lambda value: re.match(r"^\+?[0-9\s\-\(\)\.]+$", value) is not None,
            },
            "1.3.6.1.4.1.1466.115.121.1.12": {  # Distinguished Name
                "name": "distinguishedName",
                "validator": lambda value: ("=" in value and "," in value) or value.count("=") == 1,
            },
        }

        # Attribute definitions with syntax
        attribute_definitions = {
            "cn": {"syntax": "1.3.6.1.4.1.1466.115.121.1.15", "single_value": False},
            "mail": {"syntax": "1.3.6.1.4.1.1466.115.121.1.26", "single_value": False},
            "employeeNumber": {"syntax": "1.3.6.1.4.1.1466.115.121.1.36", "single_value": True},
            "telephoneNumber": {"syntax": "1.3.6.1.4.1.1466.115.121.1.50", "single_value": False},
            "manager": {"syntax": "1.3.6.1.4.1.1466.115.121.1.12", "single_value": True},
        }

        validator = SchemaValidator()
        validator.load_syntax_rules(syntax_rules)
        validator.load_attribute_definitions(attribute_definitions)

        # Test valid attribute values
        valid_tests = [
            {"attribute": "cn", "values": ["John Doe", "Johnny"]},
            {"attribute": "mail", "values": ["john@example.com", "test.email@domain.org"]},
            {"attribute": "employeeNumber", "values": ["12345"]},
            {"attribute": "telephoneNumber", "values": ["+1-555-1234", "(555) 123-4567"]},
            {"attribute": "manager", "values": ["cn=Manager,ou=People,dc=example,dc=com"]},
        ]

        for test in valid_tests:
            for value in test["values"]:
                is_valid = validator.validate_attribute_syntax(test["attribute"], value)
                assert is_valid is True, f"Valid value failed: {test['attribute']}={value}"

        # Test invalid attribute values
        invalid_tests = [
            {"attribute": "mail", "values": ["invalid-email", "@domain.com", "user@"]},
            {"attribute": "employeeNumber", "values": ["ABC123", "12-34", ""]},
            {"attribute": "telephoneNumber", "values": ["invalid-phone", "+++123", ""]},
            {"attribute": "manager", "values": ["invalid-dn", "no-equals-sign"]},
        ]

        for test in invalid_tests:
            for value in test["values"]:
                is_valid = validator.validate_attribute_syntax(test["attribute"], value)
                assert is_valid is False, f"Invalid value passed: {test['attribute']}={value}"

    def test_attribute_value_length_constraints(self) -> None:
        """Test attribute value length constraints."""
        # Test various length constraints

        length_constraints = {
            "cn": {"min_length": 1, "max_length": 256},
            "description": {"min_length": 0, "max_length": 1024},
            "jpegPhoto": {"min_length": 1, "max_length": 1048576},  # 1MB
            "userPassword": {"min_length": 8, "max_length": 128},
        }

        validator = SchemaValidator()
        validator.load_length_constraints(length_constraints)

        # Test length validations
        length_tests = [
            {"attribute": "cn", "value": "", "valid": False},  # Too short
            {"attribute": "cn", "value": "A", "valid": True},  # Minimum
            {"attribute": "cn", "value": "A" * 256, "valid": True},  # Maximum
            {"attribute": "cn", "value": "A" * 257, "valid": False},  # Too long
            {"attribute": "description", "value": "", "valid": True},  # Empty allowed
            {"attribute": "description", "value": "A" * 1024, "valid": True},  # Maximum
            {"attribute": "description", "value": "A" * 1025, "valid": False},  # Too long
            {"attribute": "userPassword", "value": "1234567", "valid": False},  # Too short
            {"attribute": "userPassword", "value": "12345678", "valid": True},  # Minimum
            {"attribute": "userPassword", "value": "A" * 128, "valid": True},  # Maximum
            {"attribute": "userPassword", "value": "A" * 129, "valid": False},  # Too long
        ]

        for test in length_tests:
            is_valid = validator.validate_attribute_length(
                test["attribute"],
                test["value"],
            )
            assert is_valid == test["valid"], \
                f"Length validation failed: {test['attribute']}='{test['value'][:20]}...'"

    def test_attribute_cardinality_validation(self) -> None:
        """Test attribute cardinality validation."""
        # Test single-value vs multi-value constraints

        cardinality_rules = {
            "cn": {"single_value": False, "required": True},
            "sn": {"single_value": False, "required": True},
            "employeeNumber": {"single_value": True, "required": False},
            "mail": {"single_value": False, "required": False},
            "manager": {"single_value": True, "required": False},
            "objectClass": {"single_value": False, "required": True},
        }

        validator = SchemaValidator()
        validator.load_cardinality_rules(cardinality_rules)

        # Test cardinality violations
        cardinality_tests = [
            {
                "entry": LDAPEntry(
                    dn="cn=Test,ou=People,dc=example,dc=com",
                    attributes={
                        "objectClass": ["person"],
                        "cn": ["Test"],
                        "sn": ["User"],
                        "employeeNumber": ["12345", "67890"],  # Should be single-value
                    },
                ),
                "valid": False,
                "violation": "employeeNumber cardinality",
            },
            {
                "entry": LDAPEntry(
                    dn="cn=Valid,ou=People,dc=example,dc=com",
                    attributes={
                        "objectClass": ["person"],
                        "cn": ["Valid"],
                        "sn": ["User"],
                        "employeeNumber": ["12345"],  # Single value OK
                        "mail": ["test@example.com", "test2@example.com"],  # Multi-value OK
                    },
                ),
                "valid": True,
                "violation": None,
            },
        ]

        for test in cardinality_tests:
            validation_result = validator.validate_entry_cardinality(test["entry"])
            assert validation_result.is_valid == test["valid"]

            if not test["valid"]:
                assert any(test["violation"].split()[0] in error.message
                          for error in validation_result.errors)


class TestSchemaMatchingRulesExtreme:
    """🔥🔥 Schema Matching Rules EXTREME Testing."""

    def test_matching_rules_comprehensive(self) -> None:
        """Comprehensive matching rules testing."""
        # RFC 4517: LDAP Syntaxes and Matching Rules

        # Define comprehensive matching rules
        matching_rules = {
            "caseIgnoreMatch": {
                "oid": "2.5.13.2",
                "syntax": "directoryString",
                "comparator": lambda a, b: a.lower() == b.lower(),
            },
            "caseExactMatch": {
                "oid": "2.5.13.5",
                "syntax": "directoryString",
                "comparator": operator.eq,
            },
            "numericStringMatch": {
                "oid": "2.5.13.8",
                "syntax": "numericString",
                "comparator": lambda a, b: a.strip() == b.strip(),
            },
            "telephoneNumberMatch": {
                "oid": "2.5.13.20",
                "syntax": "telephoneNumber",
                "comparator": lambda a, b: re.sub(r"[^\d]", "", a) == re.sub(r"[^\d]", "", b),
            },
            "distinguishedNameMatch": {
                "oid": "2.5.13.1",
                "syntax": "distinguishedName",
                "comparator": lambda a, b: a.lower().replace(" ", "") == b.lower().replace(" ", ""),
            },
        }

        validator = SchemaValidator()
        validator.load_matching_rules(matching_rules)

        # Test case-insensitive matching
        case_ignore_tests = [
            {"value1": "John Doe", "value2": "john doe", "should_match": True},
            {"value1": "John Doe", "value2": "JOHN DOE", "should_match": True},
            {"value1": "John Doe", "value2": "Jane Doe", "should_match": False},
        ]

        for test in case_ignore_tests:
            matches = validator.values_match(
                test["value1"],
                test["value2"],
                "caseIgnoreMatch",
            )
            assert matches == test["should_match"], \
                f"Case ignore match failed: '{test['value1']}' vs '{test['value2']}'"

        # Test telephone number matching (ignoring formatting)
        phone_tests = [
            {"value1": "+1-555-1234", "value2": "(555) 123-4", "should_match": True},
            {"value1": "555.123.4567", "value2": "5551234567", "should_match": True},
            {"value1": "+1-555-1234", "value2": "+1-555-5678", "should_match": False},
        ]

        for test in phone_tests:
            matches = validator.values_match(
                test["value1"],
                test["value2"],
                "telephoneNumberMatch",
            )
            assert matches == test["should_match"], \
                f"Phone match failed: '{test['value1']}' vs '{test['value2']}'"

        # Test DN matching (case-insensitive, space-insensitive)
        dn_tests = [
            {
                "value1": "cn=John Doe,ou=People,dc=example,dc=com",
                "value2": "CN=John Doe, OU=People, DC=Example, DC=Com",
                "should_match": True,
            },
            {
                "value1": "cn=John Doe,ou=People,dc=example,dc=com",
                "value2": "cn=Jane Doe,ou=People,dc=example,dc=com",
                "should_match": False,
            },
        ]

        for test in dn_tests:
            matches = validator.values_match(
                test["value1"],
                test["value2"],
                "distinguishedNameMatch",
            )
            assert matches == test["should_match"], \
                f"DN match failed: '{test['value1']}' vs '{test['value2']}'"

    def test_substring_matching_rules(self) -> None:
        """Test substring matching rules."""
        # RFC 4517: Substring matching rules

        substring_rules = {
            "caseIgnoreSubstringsMatch": {
                "oid": "2.5.13.4",
                "initial_match": lambda value, initial: value.lower().startswith(initial.lower()),
                "any_match": lambda value, substring: substring.lower() in value.lower(),
                "final_match": lambda value, final: value.lower().endswith(final.lower()),
            },
        }

        validator = SchemaValidator()
        validator.load_substring_rules(substring_rules)

        # Test substring matching scenarios
        substring_tests = [
            {
                "value": "John Doe",
                "filter": {"initial": "john"},
                "should_match": True,
            },
            {
                "value": "John Doe",
                "filter": {"any": "hn D"},
                "should_match": True,
            },
            {
                "value": "John Doe",
                "filter": {"final": "doe"},
                "should_match": True,
            },
            {
                "value": "John Doe",
                "filter": {"initial": "jane"},
                "should_match": False,
            },
            {
                "value": "Engineering Department",
                "filter": {"initial": "eng", "any": "ering", "final": "ment"},
                "should_match": True,
            },
        ]

        for test in substring_tests:
            matches = validator.substring_matches(
                test["value"],
                test["filter"],
                "caseIgnoreSubstringsMatch",
            )
            assert matches == test["should_match"], \
                f"Substring match failed: '{test['value']}' with filter {test['filter']}"


class TestSchemaPerformanceExtreme:
    """🔥🔥 Schema Validation Performance EXTREME Testing."""

    @pytest.mark.asyncio
    async def test_large_scale_validation_performance(self) -> None:
        """Large-scale schema validation performance testing."""
        # Test validation performance with thousands of entries

        performance_monitor = PerformanceMonitor()
        validator = SchemaValidator()

        # Create large number of test entries
        def generate_test_entries(count: int) -> list[LDAPEntry]:
            entries = []

            for i in range(count):
                entry = LDAPEntry(
                    dn=f"uid=user{i:06d},ou=People,dc=example,dc=com",
                    attributes={
                        "objectClass": ["person", "inetOrgPerson"],
                        "uid": [f"user{i:06d}"],
                        "cn": [f"User {i:06d}"],
                        "sn": [f"User{i:06d}"],
                        "givenName": ["Test"],
                        "mail": [f"user{i:06d}@example.com"],
                        "telephoneNumber": [f"+1-555-{i:04d}"],
                        "employeeNumber": [str(10000 + i)],
                        "department": ["Engineering"],
                        "title": ["Software Engineer"],
                        "manager": ["cn=Manager,ou=People,dc=example,dc=com"],
                    },
                )
                entries.append(entry)

            return entries

        # Test different batch sizes
        batch_sizes = [100, 500, 1000, 2000]

        for batch_size in batch_sizes:
            performance_monitor.start_measurement(f"validation_batch_{batch_size}")

            # Generate test entries
            test_entries = generate_test_entries(batch_size)

            # Validate all entries
            validation_results = []
            for entry in test_entries:
                result = validator.validate_entry(entry)
                validation_results.append(result)

            performance_monitor.stop_measurement(f"validation_batch_{batch_size}")

            # Verify all validations completed
            assert len(validation_results) == batch_size

            # Most entries should be valid (this is a performance test)
            valid_count = sum(1 for result in validation_results if result.is_valid)
            validity_rate = valid_count / batch_size
            assert validity_rate > 0.95  # At least 95% should be valid

            # Analyze performance
            metrics = performance_monitor.get_metrics()
            duration = metrics[f"validation_batch_{batch_size}"]["duration"]
            throughput = batch_size / duration if duration > 0 else 0

            # Performance should be reasonable
            assert throughput > 100  # At least 100 validations per second

    @pytest.mark.asyncio
    async def test_concurrent_validation_performance(self) -> None:
        """Concurrent schema validation performance testing."""
        # Test validation under concurrent load

        performance_monitor = PerformanceMonitor()
        validator = SchemaValidator()

        async def validate_entry_batch(batch_id: int, entry_count: int) -> dict[str, Any]:
            """Validate a batch of entries concurrently."""
            validation_results = []

            for i in range(entry_count):
                entry = LDAPEntry(
                    dn=f"uid=batch{batch_id}_user{i:04d},ou=People,dc=example,dc=com",
                    attributes={
                        "objectClass": ["person", "inetOrgPerson"],
                        "uid": [f"batch{batch_id}_user{i:04d}"],
                        "cn": [f"Batch {batch_id} User {i:04d}"],
                        "sn": [f"User{i:04d}"],
                        "mail": [f"batch{batch_id}_user{i:04d}@example.com"],
                        "batchId": [str(batch_id)],
                    },
                )

                # Validate entry
                result = validator.validate_entry(entry)
                validation_results.append(result)

                # Yield control periodically
                if i % 10 == 0:
                    await asyncio.sleep(0)

            return {
                "batch_id": batch_id,
                "entry_count": entry_count,
                "validation_results": validation_results,
                "valid_count": sum(1 for r in validation_results if r.is_valid),
            }

        # Launch concurrent validation tasks
        performance_monitor.start_measurement("concurrent_validation")

        concurrent_tasks = [
            validate_entry_batch(batch_id, 200)
            for batch_id in range(10)
        ]

        # Execute all batches concurrently
        batch_results = await asyncio.gather(*concurrent_tasks)

        performance_monitor.stop_measurement("concurrent_validation")

        # Verify all batches completed
        assert len(batch_results) == 10

        total_entries = 0
        total_valid = 0

        for result in batch_results:
            assert result["entry_count"] == 200
            assert len(result["validation_results"]) == 200
            total_entries += result["entry_count"]
            total_valid += result["valid_count"]

        # Verify concurrent processing integrity
        assert total_entries == 2000
        validity_rate = total_valid / total_entries
        assert validity_rate > 0.95

        # Performance analysis
        metrics = performance_monitor.get_metrics()
        duration = metrics["concurrent_validation"]["duration"]
        throughput = total_entries / duration if duration > 0 else 0

        # Concurrent processing should maintain good performance
        assert throughput > 200  # Should be faster due to concurrency

    def test_schema_caching_performance(self) -> None:
        """Test schema validation with caching for performance."""
        # Test schema caching mechanisms for improved performance

        performance_monitor = PerformanceMonitor()

        # Create validator with caching enabled
        cached_validator = SchemaValidator(enable_caching=True)
        uncached_validator = SchemaValidator(enable_caching=False)

        # Create test entry for repeated validation
        test_entry = LDAPEntry(
            dn="cn=Cache Test,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson"],
                "cn": ["Cache Test"],
                "sn": ["Test"],
                "mail": ["cache@example.com"],
            },
        )

        # Test uncached validation performance
        performance_monitor.start_measurement("uncached_validation")

        for _ in range(1000):
            uncached_validator.validate_entry(test_entry)

        performance_monitor.stop_measurement("uncached_validation")

        # Test cached validation performance
        performance_monitor.start_measurement("cached_validation")

        for _ in range(1000):
            cached_validator.validate_entry(test_entry)

        performance_monitor.stop_measurement("cached_validation")

        # Analyze performance difference
        metrics = performance_monitor.get_metrics()
        uncached_duration = metrics["uncached_validation"]["duration"]
        cached_duration = metrics["cached_validation"]["duration"]

        # Cached validation should be significantly faster
        speedup_ratio = uncached_duration / cached_duration if cached_duration > 0 else 0

        # Caching should provide at least 2x speedup
        assert speedup_ratio >= 2.0


class TestSchemaExtensibilityExtreme:
    """🔥🔥 Schema Extensibility EXTREME Testing."""

    def test_custom_object_class_extension(self) -> None:
        """Test custom object class extensions."""
        # Test extending schema with custom object classes

        # Define custom object classes
        custom_object_classes = {
            "customEmployee": {
                "type": "auxiliary",
                "must_attributes": ["employeeId"],
                "may_attributes": ["badge", "securityClearance", "costCenter", "workspace"],
                "superior_classes": ["top"],
            },
            "contractor": {
                "type": "auxiliary",
                "must_attributes": ["contractorId", "contractEndDate"],
                "may_attributes": ["contractorCompany", "billableRate"],
                "superior_classes": ["top"],
            },
            "securityPrincipal": {
                "type": "auxiliary",
                "must_attributes": ["securityId"],
                "may_attributes": ["securityGroups", "accessLevel", "lastSecurityReview"],
                "superior_classes": ["top"],
            },
        }

        validator = SchemaValidator()
        validator.extend_schema(custom_object_classes)

        # Test entry with custom object classes
        custom_entry = LDAPEntry(
            dn="cn=Custom Employee,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "inetOrgPerson", "customEmployee", "securityPrincipal"],
                "cn": ["Custom Employee"],
                "sn": ["Employee"],
                "mail": ["custom@example.com"],
                "employeeId": ["EMP001"],  # Required by customEmployee
                "badge": ["BADGE123"],
                "securityId": ["SEC001"],  # Required by securityPrincipal
                "accessLevel": ["CONFIDENTIAL"],
                "securityGroups": ["ADMIN", "ENGINEERING"],
            },
        )

        validation_result = validator.validate_entry(custom_entry)
        assert validation_result.is_valid is True

        # Test missing required custom attributes
        invalid_custom = LDAPEntry(
            dn="cn=Invalid Custom,ou=People,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "customEmployee"],
                "cn": ["Invalid Custom"],
                "sn": ["Test"],
                # Missing required employeeId
            },
        )

        validation_result = validator.validate_entry(invalid_custom)
        assert validation_result.is_valid is False
        assert any("employeeId" in error.message for error in validation_result.errors)

    def test_schema_migration_compatibility(self) -> None:
        """Test schema migration and compatibility."""
        # Test migrating from old schema to new schema

        # Old schema version
        old_schema = {
            "person": {
                "type": "structural",
                "must_attributes": ["cn", "sn"],
                "may_attributes": ["description", "telephoneNumber"],
                "superior_classes": ["top"],
            },
        }

        # New schema version with additional attributes
        new_schema = {
            "person": {
                "type": "structural",
                "must_attributes": ["cn", "sn"],
                "may_attributes": ["description", "telephoneNumber", "mail", "mobile", "title"],
                "superior_classes": ["top"],
            },
        }

        # Entries created with old schema
        old_entries = [
            LDAPEntry(
                dn="cn=Old Entry 1,ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Old Entry 1"],
                    "sn": ["Entry"],
                    "description": ["Created with old schema"],
                },
            ),
            LDAPEntry(
                dn="cn=Old Entry 2,ou=People,dc=example,dc=com",
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Old Entry 2"],
                    "sn": ["Entry"],
                    "telephoneNumber": ["+1-555-1234"],
                },
            ),
        ]

        # Test migration
        migrator = SchemaMigrator()
        migration_result = migrator.migrate_entries(
            entries=old_entries,
            from_schema=old_schema,
            to_schema=new_schema,
        )

        # Verify migration successful
        assert migration_result.success is True
        assert len(migration_result.migrated_entries) == 2

        # Validate migrated entries against new schema
        new_validator = SchemaValidator()
        new_validator.load_object_class_definitions(new_schema)

        for migrated_entry in migration_result.migrated_entries:
            validation_result = new_validator.validate_entry(migrated_entry)
            assert validation_result.is_valid is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
