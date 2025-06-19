# 🧪 LDAP Core Shared - Test Suite

> **Module**: Comprehensive test suite for LDAP Core Shared library with domain-driven design validation | **Audience**: Core Library Developers, LDAP Engineers, Test Specialists | **Status**: Production Ready

## 📋 **Overview**

Enterprise-grade test suite for the LDAP Core Shared library, providing comprehensive testing coverage for shared LDAP utilities, domain models, value objects, and event handling components. This test suite demonstrates best practices for testing shared library components used across multiple LDAP-related projects in the PyAuto ecosystem.

---

## 🧭 **Navigation Context**

**🏠 Root**: [PyAuto Home](../../README.md) → **📂 Component**: [LDAP Core Shared](../README.md) → **📂 Current**: Test Suite

---

## 🎯 **Module Purpose**

This test module provides comprehensive validation for the LDAP Core Shared library, ensuring reliability, performance, and correctness of all shared LDAP utilities, domain models, event handling, and common functionality used across LDAP projects.

### **Key Testing Areas**

- **Unit Testing** - Core library components and utilities validation
- **Domain Testing** - Domain models and value objects validation
- **Event Testing** - Domain event handling and processing
- **Utility Testing** - LDAP DN utilities and operation helpers
- **Integration Testing** - Cross-component integration validation
- **Performance Testing** - Library component performance validation

---

## 📁 **Test Structure**

```
tests/
├── unit/
│   ├── test_domain_models.py            # Domain model tests
│   ├── test_value_objects.py            # Value object tests
│   ├── test_dn_utils.py                 # DN utility tests
│   ├── test_ldap_operations.py          # LDAP operation tests
│   └── test_logging_utils.py            # Logging utility tests
├── integration/
│   ├── test_domain_integration.py       # Domain layer integration tests
│   ├── test_event_integration.py        # Event handling integration tests
│   ├── test_config_integration.py       # Configuration integration tests
│   └── test_cross_component.py          # Cross-component tests
├── domain/
│   ├── test_domain_events.py            # Domain event tests
│   ├── test_event_handlers.py           # Event handler tests
│   ├── test_aggregates.py               # Aggregate root tests
│   └── test_repositories.py             # Repository pattern tests
├── utils/
│   ├── test_dn_parsing.py               # DN parsing utility tests
│   ├── test_dn_validation.py            # DN validation tests
│   ├── test_ldap_helpers.py             # LDAP helper function tests
│   └── test_logging_config.py           # Logging configuration tests
├── performance/
│   ├── test_dn_performance.py           # DN operation performance tests
│   ├── test_event_performance.py        # Event handling performance tests
│   └── test_memory_usage.py             # Memory usage tests
├── fixtures/
│   ├── domain_fixtures.py               # Domain model test fixtures
│   ├── ldap_fixtures.py                 # LDAP test data fixtures
│   └── event_fixtures.py                # Event test fixtures
├── conftest.py                           # Pytest configuration and fixtures
├── test_dn_utils.py                      # DN utility tests
├── test_domain_models.py                 # Domain model tests
└── test_value_objects.py                 # Value object tests
```

---

## 🔧 **Test Categories**

### **1. Unit Tests (unit/)**

#### **Domain Model Testing (test_domain_models.py)**

```python
"""Unit tests for LDAP Core Shared domain models."""

import pytest
from datetime import datetime
from typing import List, Optional

from ldap_core_shared.domain.models import (
    LDAPEntry,
    LDAPAttribute,
    LDAPObjectClass,
    LDAPSchemaElement,
    LDAPConnection
)
from ldap_core_shared.domain.value_objects import DN, AttributeValue
from ldap_core_shared.exceptions import DomainModelError

class TestLDAPEntry:
    """Test LDAP entry domain model."""

    @pytest.fixture
    def sample_dn(self):
        """Sample DN for testing."""
        return DN("uid=john.doe,ou=users,dc=example,dc=com")

    @pytest.fixture
    def sample_attributes(self):
        """Sample attributes for testing."""
        return {
            "uid": [AttributeValue("john.doe")],
            "cn": [AttributeValue("John Doe")],
            "sn": [AttributeValue("Doe")],
            "mail": [AttributeValue("john.doe@example.com")],
            "objectClass": [
                AttributeValue("inetOrgPerson"),
                AttributeValue("organizationalPerson"),
                AttributeValue("person")
            ]
        }

    def test_ldap_entry_creation_success(self, sample_dn, sample_attributes):
        """Test successful LDAP entry creation."""
        # Act
        entry = LDAPEntry(dn=sample_dn, attributes=sample_attributes)
        
        # Assert
        assert entry.dn == sample_dn
        assert entry.attributes == sample_attributes
        assert len(entry.get_object_classes()) == 3
        assert "inetOrgPerson" in [oc.value for oc in entry.get_object_classes()]

    def test_ldap_entry_creation_invalid_dn(self, sample_attributes):
        """Test LDAP entry creation with invalid DN."""
        # Arrange
        invalid_dn = "invalid_dn_format"
        
        # Act & Assert
        with pytest.raises(DomainModelError):
            LDAPEntry(dn=invalid_dn, attributes=sample_attributes)

    def test_ldap_entry_get_attribute_single_value(self, sample_dn, sample_attributes):
        """Test getting single-value attribute."""
        # Arrange
        entry = LDAPEntry(dn=sample_dn, attributes=sample_attributes)
        
        # Act
        uid = entry.get_attribute("uid")
        
        # Assert
        assert uid is not None
        assert uid.value == "john.doe"

    def test_ldap_entry_get_attribute_multi_value(self, sample_dn, sample_attributes):
        """Test getting multi-value attribute."""
        # Arrange
        entry = LDAPEntry(dn=sample_dn, attributes=sample_attributes)
        
        # Act
        object_classes = entry.get_attributes("objectClass")
        
        # Assert
        assert len(object_classes) == 3
        values = [attr.value for attr in object_classes]
        assert "inetOrgPerson" in values
        assert "person" in values

    def test_ldap_entry_add_attribute(self, sample_dn, sample_attributes):
        """Test adding attribute to LDAP entry."""
        # Arrange
        entry = LDAPEntry(dn=sample_dn, attributes=sample_attributes)
        
        # Act
        entry.add_attribute("telephoneNumber", AttributeValue("+1-555-1234"))
        
        # Assert
        phone = entry.get_attribute("telephoneNumber")
        assert phone is not None
        assert phone.value == "+1-555-1234"

    def test_ldap_entry_remove_attribute(self, sample_dn, sample_attributes):
        """Test removing attribute from LDAP entry."""
        # Arrange
        entry = LDAPEntry(dn=sample_dn, attributes=sample_attributes)
        
        # Act
        entry.remove_attribute("mail")
        
        # Assert
        mail = entry.get_attribute("mail")
        assert mail is None

    def test_ldap_entry_update_attribute(self, sample_dn, sample_attributes):
        """Test updating attribute in LDAP entry."""
        # Arrange
        entry = LDAPEntry(dn=sample_dn, attributes=sample_attributes)
        
        # Act
        entry.update_attribute("mail", AttributeValue("john.new@example.com"))
        
        # Assert
        mail = entry.get_attribute("mail")
        assert mail is not None
        assert mail.value == "john.new@example.com"

    def test_ldap_entry_validation(self, sample_dn):
        """Test LDAP entry validation."""
        # Arrange
        invalid_attributes = {
            "uid": [AttributeValue("john.doe")],
            # Missing required objectClass attribute
        }
        
        # Act & Assert
        with pytest.raises(DomainModelError):
            entry = LDAPEntry(dn=sample_dn, attributes=invalid_attributes)
            entry.validate()

class TestLDAPAttribute:
    """Test LDAP attribute domain model."""

    def test_ldap_attribute_creation(self):
        """Test LDAP attribute creation."""
        # Act
        attribute = LDAPAttribute(
            name="cn",
            values=[AttributeValue("John Doe"), AttributeValue("J. Doe")]
        )
        
        # Assert
        assert attribute.name == "cn"
        assert len(attribute.values) == 2
        assert attribute.is_multi_valued()

    def test_ldap_attribute_single_value(self):
        """Test single-value LDAP attribute."""
        # Act
        attribute = LDAPAttribute(
            name="uid",
            values=[AttributeValue("john.doe")]
        )
        
        # Assert
        assert attribute.name == "uid"
        assert len(attribute.values) == 1
        assert not attribute.is_multi_valued()
        assert attribute.get_single_value().value == "john.doe"

    def test_ldap_attribute_add_value(self):
        """Test adding value to LDAP attribute."""
        # Arrange
        attribute = LDAPAttribute(name="mail", values=[])
        
        # Act
        attribute.add_value(AttributeValue("john@example.com"))
        attribute.add_value(AttributeValue("john.doe@example.com"))
        
        # Assert
        assert len(attribute.values) == 2
        assert attribute.is_multi_valued()

    def test_ldap_attribute_remove_value(self):
        """Test removing value from LDAP attribute."""
        # Arrange
        attribute = LDAPAttribute(
            name="mail",
            values=[
                AttributeValue("john@example.com"),
                AttributeValue("john.doe@example.com")
            ]
        )
        
        # Act
        attribute.remove_value(AttributeValue("john@example.com"))
        
        # Assert
        assert len(attribute.values) == 1
        assert attribute.get_single_value().value == "john.doe@example.com"

class TestLDAPObjectClass:
    """Test LDAP object class domain model."""

    def test_object_class_creation(self):
        """Test object class creation."""
        # Act
        oc = LDAPObjectClass(
            name="inetOrgPerson",
            oid="2.16.840.1.113730.3.2.2",
            description="RFC2798: Internet Organizational Person",
            superior_classes=["organizationalPerson"],
            required_attributes=["cn"],
            optional_attributes=["audio", "businessCategory", "carLicense"]
        )
        
        # Assert
        assert oc.name == "inetOrgPerson"
        assert oc.oid == "2.16.840.1.113730.3.2.2"
        assert "organizationalPerson" in oc.superior_classes
        assert "cn" in oc.required_attributes
        assert "audio" in oc.optional_attributes

    def test_object_class_attribute_requirements(self):
        """Test object class attribute requirements."""
        # Arrange
        oc = LDAPObjectClass(
            name="person",
            required_attributes=["cn", "sn"],
            optional_attributes=["description", "seeAlso", "telephoneNumber"]
        )
        
        # Act & Assert
        assert oc.is_attribute_required("cn")
        assert oc.is_attribute_required("sn")
        assert not oc.is_attribute_required("description")
        assert oc.is_attribute_allowed("telephoneNumber")
        assert not oc.is_attribute_allowed("nonExistentAttribute")

    def test_object_class_inheritance(self):
        """Test object class inheritance."""
        # Arrange
        person_oc = LDAPObjectClass(
            name="person",
            required_attributes=["cn", "sn"]
        )
        
        org_person_oc = LDAPObjectClass(
            name="organizationalPerson",
            superior_classes=["person"],
            optional_attributes=["title", "ou"]
        )
        
        # Act
        all_required = org_person_oc.get_all_required_attributes([person_oc])
        all_optional = org_person_oc.get_all_optional_attributes([person_oc])
        
        # Assert
        assert "cn" in all_required
        assert "sn" in all_required
        assert "title" in all_optional
        assert "ou" in all_optional
```

#### **Value Object Testing (test_value_objects.py)**

```python
"""Unit tests for LDAP Core Shared value objects."""

import pytest
from typing import Any

from ldap_core_shared.domain.value_objects import (
    DN,
    AttributeValue,
    LDAPFilter,
    ObjectIdentifier,
    TimestampValue
)
from ldap_core_shared.exceptions import ValueObjectError

class TestDN:
    """Test Distinguished Name value object."""

    def test_dn_creation_valid(self):
        """Test DN creation with valid format."""
        # Act
        dn = DN("uid=john.doe,ou=users,dc=example,dc=com")
        
        # Assert
        assert str(dn) == "uid=john.doe,ou=users,dc=example,dc=com"
        assert dn.value == "uid=john.doe,ou=users,dc=example,dc=com"

    def test_dn_creation_invalid(self):
        """Test DN creation with invalid format."""
        # Act & Assert
        with pytest.raises(ValueObjectError):
            DN("invalid_dn_format")

    def test_dn_parsing(self):
        """Test DN parsing into components."""
        # Arrange
        dn = DN("uid=john.doe,ou=users,dc=example,dc=com")
        
        # Act
        components = dn.get_components()
        
        # Assert
        assert len(components) == 3
        assert components[0] == ("uid", "john.doe")
        assert components[1] == ("ou", "users")
        assert components[2] == ("dc", "example")

    def test_dn_parent(self):
        """Test getting parent DN."""
        # Arrange
        dn = DN("uid=john.doe,ou=users,dc=example,dc=com")
        
        # Act
        parent = dn.get_parent()
        
        # Assert
        assert str(parent) == "ou=users,dc=example,dc=com"

    def test_dn_rdn(self):
        """Test getting relative DN."""
        # Arrange
        dn = DN("uid=john.doe,ou=users,dc=example,dc=com")
        
        # Act
        rdn = dn.get_rdn()
        
        # Assert
        assert rdn == "uid=john.doe"

    def test_dn_base_dn(self):
        """Test getting base DN."""
        # Arrange
        dn = DN("uid=john.doe,ou=users,dc=example,dc=com")
        
        # Act
        base_dn = dn.get_base_dn()
        
        # Assert
        assert str(base_dn) == "dc=example,dc=com"

    def test_dn_is_child_of(self):
        """Test checking if DN is child of another DN."""
        # Arrange
        child_dn = DN("uid=john.doe,ou=users,dc=example,dc=com")
        parent_dn = DN("ou=users,dc=example,dc=com")
        unrelated_dn = DN("ou=groups,dc=example,dc=com")
        
        # Act & Assert
        assert child_dn.is_child_of(parent_dn)
        assert not child_dn.is_child_of(unrelated_dn)

    def test_dn_escape_special_characters(self):
        """Test DN with special characters."""
        # Act
        dn = DN("cn=John, Doe+title=Manager,ou=users,dc=example,dc=com")
        
        # Assert
        components = dn.get_components()
        assert components[0][1] == "John, Doe"  # Comma should be preserved

    def test_dn_equality(self):
        """Test DN equality comparison."""
        # Arrange
        dn1 = DN("uid=john.doe,ou=users,dc=example,dc=com")
        dn2 = DN("uid=john.doe,ou=users,dc=example,dc=com")
        dn3 = DN("uid=jane.smith,ou=users,dc=example,dc=com")
        
        # Act & Assert
        assert dn1 == dn2
        assert dn1 != dn3
        assert hash(dn1) == hash(dn2)

class TestAttributeValue:
    """Test LDAP attribute value object."""

    def test_attribute_value_string(self):
        """Test string attribute value."""
        # Act
        attr_val = AttributeValue("john.doe")
        
        # Assert
        assert attr_val.value == "john.doe"
        assert attr_val.is_string()
        assert not attr_val.is_binary()

    def test_attribute_value_binary(self):
        """Test binary attribute value."""
        # Arrange
        binary_data = b"\\x89PNG\\r\\n\\x1a\\n"
        
        # Act
        attr_val = AttributeValue(binary_data, is_binary=True)
        
        # Assert
        assert attr_val.value == binary_data
        assert attr_val.is_binary()
        assert not attr_val.is_string()

    def test_attribute_value_base64_encoding(self):
        """Test base64 encoding for binary values."""
        # Arrange
        binary_data = b"binary_content"
        attr_val = AttributeValue(binary_data, is_binary=True)
        
        # Act
        base64_encoded = attr_val.to_base64()
        
        # Assert
        assert base64_encoded == "YmluYXJ5X2NvbnRlbnQ="

    def test_attribute_value_from_base64(self):
        """Test creating attribute value from base64."""
        # Arrange
        base64_string = "YmluYXJ5X2NvbnRlbnQ="
        
        # Act
        attr_val = AttributeValue.from_base64(base64_string)
        
        # Assert
        assert attr_val.value == b"binary_content"
        assert attr_val.is_binary()

    def test_attribute_value_validation(self):
        """Test attribute value validation."""
        # Act & Assert
        with pytest.raises(ValueObjectError):
            AttributeValue(None)  # None value not allowed

    def test_attribute_value_equality(self):
        """Test attribute value equality."""
        # Arrange
        val1 = AttributeValue("test")
        val2 = AttributeValue("test")
        val3 = AttributeValue("different")
        
        # Act & Assert
        assert val1 == val2
        assert val1 != val3
        assert hash(val1) == hash(val2)

class TestLDAPFilter:
    """Test LDAP filter value object."""

    def test_ldap_filter_simple(self):
        """Test simple LDAP filter."""
        # Act
        filter_obj = LDAPFilter("(uid=john.doe)")
        
        # Assert
        assert str(filter_obj) == "(uid=john.doe)"
        assert filter_obj.is_valid()

    def test_ldap_filter_complex(self):
        """Test complex LDAP filter."""
        # Act
        filter_obj = LDAPFilter("(&(objectClass=person)(|(uid=john*)(cn=John*)))")
        
        # Assert
        assert filter_obj.is_valid()
        assert "objectClass=person" in str(filter_obj)

    def test_ldap_filter_invalid(self):
        """Test invalid LDAP filter."""
        # Act & Assert
        with pytest.raises(ValueObjectError):
            LDAPFilter("invalid_filter_format")

    def test_ldap_filter_parsing(self):
        """Test LDAP filter parsing."""
        # Arrange
        filter_obj = LDAPFilter("(&(objectClass=person)(uid=john.doe))")
        
        # Act
        components = filter_obj.get_components()
        
        # Assert
        assert len(components) >= 2
        assert any("objectClass=person" in comp for comp in components)
        assert any("uid=john.doe" in comp for comp in components)

    def test_ldap_filter_escape_special_chars(self):
        """Test LDAP filter with special characters."""
        # Act
        filter_obj = LDAPFilter("(cn=John\\2C Doe)")  # Escaped comma
        
        # Assert
        assert filter_obj.is_valid()
        assert "John\\2C Doe" in str(filter_obj)

class TestObjectIdentifier:
    """Test Object Identifier value object."""

    def test_oid_creation_valid(self):
        """Test OID creation with valid format."""
        # Act
        oid = ObjectIdentifier("2.16.840.1.113730.3.2.2")
        
        # Assert
        assert str(oid) == "2.16.840.1.113730.3.2.2"
        assert oid.is_valid()

    def test_oid_creation_invalid(self):
        """Test OID creation with invalid format."""
        # Act & Assert
        with pytest.raises(ValueObjectError):
            ObjectIdentifier("invalid.oid.format")

    def test_oid_components(self):
        """Test OID component extraction."""
        # Arrange
        oid = ObjectIdentifier("2.16.840.1.113730.3.2.2")
        
        # Act
        components = oid.get_components()
        
        # Assert
        assert components == [2, 16, 840, 1, 113730, 3, 2, 2]

    def test_oid_equality(self):
        """Test OID equality comparison."""
        # Arrange
        oid1 = ObjectIdentifier("2.16.840.1.113730.3.2.2")
        oid2 = ObjectIdentifier("2.16.840.1.113730.3.2.2")
        oid3 = ObjectIdentifier("2.16.840.1.113730.3.2.3")
        
        # Act & Assert
        assert oid1 == oid2
        assert oid1 != oid3

class TestTimestampValue:
    """Test timestamp value object."""

    def test_timestamp_creation_from_string(self):
        """Test timestamp creation from string."""
        # Act
        timestamp = TimestampValue("20250619120000Z")
        
        # Assert
        assert timestamp.value == "20250619120000Z"
        assert timestamp.is_valid()

    def test_timestamp_creation_from_datetime(self):
        """Test timestamp creation from datetime."""
        # Arrange
        from datetime import datetime, timezone
        dt = datetime(2025, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        
        # Act
        timestamp = TimestampValue.from_datetime(dt)
        
        # Assert
        assert timestamp.value == "20250619120000Z"

    def test_timestamp_to_datetime(self):
        """Test timestamp conversion to datetime."""
        # Arrange
        timestamp = TimestampValue("20250619120000Z")
        
        # Act
        dt = timestamp.to_datetime()
        
        # Assert
        assert dt.year == 2025
        assert dt.month == 6
        assert dt.day == 19
        assert dt.hour == 12

    def test_timestamp_invalid_format(self):
        """Test timestamp with invalid format."""
        # Act & Assert
        with pytest.raises(ValueObjectError):
            TimestampValue("invalid_timestamp_format")

    def test_timestamp_comparison(self):
        """Test timestamp comparison."""
        # Arrange
        ts1 = TimestampValue("20250619120000Z")
        ts2 = TimestampValue("20250619130000Z")
        ts3 = TimestampValue("20250619120000Z")
        
        # Act & Assert
        assert ts1 < ts2
        assert ts1 == ts3
        assert ts2 > ts1
```

#### **DN Utilities Testing (test_dn_utils.py)**

```python
"""Unit tests for DN utility functions."""

import pytest
from typing import List

from ldap_core_shared.utils.dn_utils import (
    parse_dn,
    format_dn,
    normalize_dn,
    escape_dn_value,
    unescape_dn_value,
    is_valid_dn,
    get_dn_parent,
    get_dn_rdn,
    dn_components_to_dict
)
from ldap_core_shared.exceptions import DNUtilsError

class TestDNParsing:
    """Test DN parsing utilities."""

    def test_parse_dn_simple(self):
        """Test parsing simple DN."""
        # Act
        components = parse_dn("uid=john.doe,ou=users,dc=example,dc=com")
        
        # Assert
        assert len(components) == 3
        assert components[0] == ("uid", "john.doe")
        assert components[1] == ("ou", "users")
        assert components[2] == ("dc", "example")

    def test_parse_dn_with_spaces(self):
        """Test parsing DN with spaces."""
        # Act
        components = parse_dn("cn=John Doe, ou=users, dc=example, dc=com")
        
        # Assert
        assert len(components) == 3
        assert components[0] == ("cn", "John Doe")
        assert components[1] == ("ou", "users")
        assert components[2] == ("dc", "example")

    def test_parse_dn_with_escaped_characters(self):
        """Test parsing DN with escaped characters."""
        # Act
        components = parse_dn("cn=John\\, Doe+title=Manager,ou=users,dc=example,dc=com")
        
        # Assert
        assert len(components) == 3
        assert components[0] == ("cn", "John, Doe+title=Manager")
        assert components[1] == ("ou", "users")
        assert components[2] == ("dc", "example")

    def test_parse_dn_multi_valued_rdn(self):
        """Test parsing DN with multi-valued RDN."""
        # Act
        components = parse_dn("cn=John Doe+uid=john.doe,ou=users,dc=example,dc=com")
        
        # Assert
        assert len(components) == 3
        # First component should contain both cn and uid
        assert "John Doe" in components[0][1]
        assert "john.doe" in components[0][1]

    def test_parse_dn_invalid(self):
        """Test parsing invalid DN."""
        # Act & Assert
        with pytest.raises(DNUtilsError):
            parse_dn("invalid_dn_format")

class TestDNFormatting:
    """Test DN formatting utilities."""

    def test_format_dn_from_components(self):
        """Test formatting DN from components."""
        # Arrange
        components = [("uid", "john.doe"), ("ou", "users"), ("dc", "example"), ("dc", "com")]
        
        # Act
        dn = format_dn(components)
        
        # Assert
        assert dn == "uid=john.doe,ou=users,dc=example,dc=com"

    def test_format_dn_with_special_characters(self):
        """Test formatting DN with special characters."""
        # Arrange
        components = [("cn", "John, Doe"), ("ou", "users"), ("dc", "example"), ("dc", "com")]
        
        # Act
        dn = format_dn(components)
        
        # Assert
        assert "John\\, Doe" in dn or "John, Doe" in dn  # Should handle escaping

    def test_normalize_dn(self):
        """Test DN normalization."""
        # Act
        normalized = normalize_dn("  CN=John Doe , OU=Users , DC=Example , DC=Com  ")
        
        # Assert
        assert normalized == "cn=john doe,ou=users,dc=example,dc=com"

    def test_normalize_dn_case_insensitive(self):
        """Test case-insensitive DN normalization."""
        # Arrange
        dn1 = "uid=JOHN.DOE,ou=USERS,dc=EXAMPLE,dc=COM"
        dn2 = "uid=john.doe,ou=users,dc=example,dc=com"
        
        # Act
        norm1 = normalize_dn(dn1)
        norm2 = normalize_dn(dn2)
        
        # Assert
        assert norm1 == norm2

class TestDNEscaping:
    """Test DN escaping utilities."""

    def test_escape_dn_value_comma(self):
        """Test escaping comma in DN value."""
        # Act
        escaped = escape_dn_value("John, Doe")
        
        # Assert
        assert escaped == "John\\, Doe"

    def test_escape_dn_value_plus(self):
        """Test escaping plus sign in DN value."""
        # Act
        escaped = escape_dn_value("John+Manager")
        
        # Assert
        assert escaped == "John\\+Manager"

    def test_escape_dn_value_multiple_chars(self):
        """Test escaping multiple special characters."""
        # Act
        escaped = escape_dn_value("John, Doe+Manager<Admin>")
        
        # Assert
        assert "\\," in escaped
        assert "\\+" in escaped
        assert "\\<" in escaped
        assert "\\>" in escaped

    def test_unescape_dn_value(self):
        """Test unescaping DN value."""
        # Act
        unescaped = unescape_dn_value("John\\, Doe\\+Manager")
        
        # Assert
        assert unescaped == "John, Doe+Manager"

    def test_escape_unescape_roundtrip(self):
        """Test escape/unescape roundtrip."""
        # Arrange
        original = "John, Doe+Manager<Admin>#Hash"
        
        # Act
        escaped = escape_dn_value(original)
        unescaped = unescape_dn_value(escaped)
        
        # Assert
        assert unescaped == original

class TestDNValidation:
    """Test DN validation utilities."""

    def test_is_valid_dn_true(self):
        """Test valid DN recognition."""
        # Act & Assert
        assert is_valid_dn("uid=john.doe,ou=users,dc=example,dc=com")
        assert is_valid_dn("cn=John Doe,ou=users,dc=example,dc=com")
        assert is_valid_dn("cn=John\\, Doe+title=Manager,ou=users,dc=example,dc=com")

    def test_is_valid_dn_false(self):
        """Test invalid DN recognition."""
        # Act & Assert
        assert not is_valid_dn("invalid_dn_format")
        assert not is_valid_dn("uid=john.doe,")  # Trailing comma
        assert not is_valid_dn("=john.doe,ou=users,dc=example,dc=com")  # Missing attribute type

class TestDNUtilities:
    """Test DN utility functions."""

    def test_get_dn_parent(self):
        """Test getting parent DN."""
        # Act
        parent = get_dn_parent("uid=john.doe,ou=users,dc=example,dc=com")
        
        # Assert
        assert parent == "ou=users,dc=example,dc=com"

    def test_get_dn_rdn(self):
        """Test getting relative DN."""
        # Act
        rdn = get_dn_rdn("uid=john.doe,ou=users,dc=example,dc=com")
        
        # Assert
        assert rdn == "uid=john.doe"

    def test_get_dn_parent_root(self):
        """Test getting parent of root DN."""
        # Act
        parent = get_dn_parent("dc=com")
        
        # Assert
        assert parent == "" or parent is None

    def test_dn_components_to_dict(self):
        """Test converting DN components to dictionary."""
        # Arrange
        components = [("uid", "john.doe"), ("ou", "users"), ("dc", "example"), ("dc", "com")]
        
        # Act
        dn_dict = dn_components_to_dict(components)
        
        # Assert
        assert dn_dict["uid"] == "john.doe"
        assert dn_dict["ou"] == "users"
        assert dn_dict["dc"] == ["example", "com"]  # Multiple dc values should be in list

    def test_dn_components_to_dict_single_values(self):
        """Test converting DN components with single values."""
        # Arrange
        components = [("uid", "john.doe"), ("ou", "users")]
        
        # Act
        dn_dict = dn_components_to_dict(components)
        
        # Assert
        assert dn_dict["uid"] == "john.doe"
        assert dn_dict["ou"] == "users"
        assert isinstance(dn_dict["uid"], str)
        assert isinstance(dn_dict["ou"], str)
```

---

## 🔧 **Test Configuration**

### **Pytest Configuration (conftest.py)**

```python
"""Pytest configuration and shared fixtures for LDAP Core Shared tests."""

import pytest
import asyncio
from unittest.mock import Mock
from datetime import datetime, timezone
from typing import Dict, List, Any

from ldap_core_shared.domain.models import LDAPEntry, LDAPAttribute
from ldap_core_shared.domain.value_objects import DN, AttributeValue
from ldap_core_shared.events.domain_events import LDAPEntryCreated, LDAPEntryModified

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def sample_dn():
    """Sample DN for testing."""
    return DN("uid=john.doe,ou=users,dc=example,dc=com")

@pytest.fixture
def sample_attributes():
    """Sample LDAP attributes for testing."""
    return {
        "uid": [AttributeValue("john.doe")],
        "cn": [AttributeValue("John Doe")],
        "sn": [AttributeValue("Doe")],
        "givenName": [AttributeValue("John")],
        "mail": [AttributeValue("john.doe@example.com")],
        "objectClass": [
            AttributeValue("inetOrgPerson"),
            AttributeValue("organizationalPerson"),
            AttributeValue("person"),
            AttributeValue("top")
        ]
    }

@pytest.fixture
def sample_ldap_entry(sample_dn, sample_attributes):
    """Sample LDAP entry for testing."""
    return LDAPEntry(dn=sample_dn, attributes=sample_attributes)

@pytest.fixture
def sample_domain_events():
    """Sample domain events for testing."""
    dn = DN("uid=john.doe,ou=users,dc=example,dc=com")
    
    return [
        LDAPEntryCreated(
            entry_dn=dn,
            attributes={"uid": ["john.doe"], "cn": ["John Doe"]},
            timestamp=datetime.now(timezone.utc)
        ),
        LDAPEntryModified(
            entry_dn=dn,
            old_attributes={"cn": ["John Doe"]},
            new_attributes={"cn": ["John D. Doe"]},
            timestamp=datetime.now(timezone.utc)
        )
    ]

@pytest.fixture
def mock_event_handler():
    """Mock event handler for testing."""
    handler = Mock()
    handler.handle.return_value = None
    return handler

@pytest.fixture
def sample_dn_components():
    """Sample DN components for testing."""
    return [
        ("uid", "john.doe"),
        ("ou", "users"),
        ("dc", "example"),
        ("dc", "com")
    ]

@pytest.fixture
def complex_dn_samples():
    """Complex DN samples for testing."""
    return [
        "uid=john.doe,ou=users,dc=example,dc=com",
        "cn=John\\, Doe+title=Manager,ou=staff,dc=company,dc=com",
        "cn=Test User+uid=test,ou=special chars\\+test,dc=example,dc=com",
        "cn=Admin<root>,ou=administrators,dc=secure,dc=com",
        "cn=John#123,ou=users,dc=example,dc=com"
    ]

@pytest.fixture
def ldap_schema_samples():
    """Sample LDAP schema elements for testing."""
    return {
        "object_classes": [
            {
                "name": "person",
                "oid": "2.5.6.6",
                "description": "RFC2256: a person",
                "superior": "top",
                "structural": True,
                "required": ["sn", "cn"],
                "optional": ["userPassword", "telephoneNumber", "seeAlso", "description"]
            },
            {
                "name": "organizationalPerson",
                "oid": "2.5.6.7",
                "description": "RFC2256: an organizational person",
                "superior": "person",
                "structural": True,
                "optional": ["title", "x121Address", "registeredAddress", "destinationIndicator"]
            },
            {
                "name": "inetOrgPerson",
                "oid": "2.16.840.1.113730.3.2.2",
                "description": "RFC2798: Internet Organizational Person",
                "superior": "organizationalPerson",
                "structural": True,
                "optional": ["audio", "businessCategory", "carLicense", "departmentNumber", "displayName", "employeeNumber", "employeeType", "givenName", "homePhone", "homePostalAddress", "initials", "jpegPhoto", "labeledURI", "mail", "manager", "mobile", "o", "pager", "photo", "roomNumber", "secretary", "uid", "userCertificate", "x500uniqueIdentifier", "preferredLanguage", "userSMIMECertificate", "userPKCS12"]
            }
        ],
        "attribute_types": [
            {
                "name": "uid",
                "oid": "0.9.2342.19200300.100.1.1",
                "description": "RFC1274: user identifier",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": True
            },
            {
                "name": "cn",
                "oid": "2.5.4.3",
                "description": "RFC2256: common name(s) for which the entity is known by",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.15",
                "single_value": False
            },
            {
                "name": "mail",
                "oid": "0.9.2342.19200300.100.1.3",
                "description": "RFC1274: electronic mail address",
                "syntax": "1.3.6.1.4.1.1466.115.121.1.26",
                "single_value": False
            }
        ]
    }

@pytest.fixture
def performance_test_data():
    """Performance test data fixtures."""
    return {
        "large_dn_list": [
            f"uid=user{i:06d},ou=users,dc=example,dc=com"
            for i in range(10000)
        ],
        "complex_attributes": {
            f"attr{i}": [AttributeValue(f"value{j}") for j in range(100)]
            for i in range(100)
        }
    }
```

---

## 🔗 **Cross-References**

### **Component Documentation**

- [Component Overview](../README.md) - Complete LDAP Core Shared documentation
- [Source Implementation](../src/README.md) - Source code structure and patterns
- [Domain Models](../src/ldap_core_shared/domain/README.md) - Domain model documentation

### **Testing Documentation**

- [PyTest Documentation](https://docs.pytest.org/) - Python testing framework
- [Domain-Driven Design Testing](https://martinfowler.com/bliki/UnitTest.html) - DDD testing patterns
- [Value Object Testing](https://enterprisecraftsmanship.com/posts/value-objects-explained/) - Value object patterns

### **LDAP References**

- [LDAP Protocol Documentation](https://ldapwiki.com/wiki/LDAP%20Protocol) - LDAP protocol reference
- [Distinguished Names RFC](https://tools.ietf.org/html/rfc4514) - DN format specification
- [LDAP Schema RFC](https://tools.ietf.org/html/rfc4512) - LDAP schema specification

---

**📂 Module**: Test Suite | **🏠 Component**: [LDAP Core Shared](../README.md) | **Framework**: PyTest 7.0+ | **Updated**: 2025-06-19