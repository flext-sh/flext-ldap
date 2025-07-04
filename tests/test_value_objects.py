"""Module test_value_objects."""

from typing import Any

"""
Tests for value objects.

Comprehensive tests for LDAP value objects including DN manipulation,
migration plans, and schema analysis results.
"""

import pytest
from ldap_core_shared.domain.value_objects import (
    ConnectionProfile,
    DNComponent,
    LdapDn,
    LDAPObjectClass,
    MigrationPlan,
    MigrationStatus,
    SchemaAnalysisResult,
    SchemaCompatibility,
    TransformationRule,
)


class TestMigrationStatus:
    """Test migration status enumeration."""

    def test_all_statuses_available(self) -> Any:
        """Test all migration statuses are available."""
        assert MigrationStatus.PENDING == "pending"
        assert MigrationStatus.RUNNING == "running"
        assert MigrationStatus.COMPLETED == "completed"
        assert MigrationStatus.FAILED == "failed"
        assert MigrationStatus.CANCELLED == "cancelled"
        assert MigrationStatus.ROLLBACK == "rollback"


class TestLDAPObjectClass:
    """Test LDAP object class enumeration."""

    def test_standard_object_classes(self) -> Any:
        """Test standard LDAP object classes."""
        assert LDAPObjectClass.TOP == "top"
        assert LDAPObjectClass.PERSON == "person"
        assert LDAPObjectClass.INET_ORG_PERSON == "inetOrgPerson"
        assert LDAPObjectClass.ORGANIZATIONAL_UNIT == "organizationalUnit"

    def test_oracle_specific_classes(self) -> Any:
        """Test Oracle-specific object classes."""
        assert LDAPObjectClass.ORCL_USER == "orclUser"
        assert LDAPObjectClass.ORCL_GROUP == "orclGroup"
        assert LDAPObjectClass.ORCL_CONTEXT == "orclContext"
        assert LDAPObjectClass.ORCL_CONTAINER == "orclContainer"


class TestDNComponent:
    """Test DN component value object."""

    def test_valid_component_creation(self) -> Any:
        """Test creating valid DN component."""
        component = DNComponent(attribute="cn", value="john")

        assert component.attribute == "cn"
        assert component.value == "john"

    def test_attribute_normalization(self) -> Any:
        """Test attribute name normalization."""
        component = DNComponent(attribute="CN", value="john")

        assert component.attribute == "cn"  # Should be lowercase

    def test_invalid_attribute_name(self) -> Any:
        """Test validation of attribute names."""
        with pytest.raises(ValueError, match="Invalid attribute name"):
            DNComponent(attribute="123invalid", value="test")

        with pytest.raises(ValueError, match="Invalid attribute name"):
            DNComponent(attribute="attr with spaces", value="test")

        with pytest.raises(ValueError, match="Invalid attribute name"):
            DNComponent(attribute="attr@domain", value="test")

    def test_empty_value_validation(self) -> Any:
        """Test validation of empty values."""
        with pytest.raises(ValueError, match="DN component value cannot be empty"):
            DNComponent(attribute="cn", value="")

        with pytest.raises(ValueError, match="DN component value cannot be empty"):
            DNComponent(attribute="cn", value="   ")

    def test_value_trimming(self) -> Any:
        """Test value trimming."""
        component = DNComponent(attribute="cn", value="  john  ")

        assert component.value == "john"

    def test_string_representation(self) -> Any:
        """Test string representation."""
        component = DNComponent(attribute="cn", value="john")
        assert str(component) == "cn=john"

    def test_escaping_in_string_representation(self) -> Any:
        """Test escaping special characters."""
        component = DNComponent(attribute="cn", value="john,doe")
        assert str(component) == "cn=john\\,doe"

        component = DNComponent(attribute="cn", value="john\\test")
        assert str(component) == "cn=john\\\\test"


class TestLdapDn:
    """Test LDAP DN value object."""

    def test_simple_dn_creation(self) -> Any:
        """Test creating simple DN."""
        dn = LdapDn.from_string("cn=john,ou=users,dc=example,dc=com")

        assert len(dn.components) == 4
        assert dn.components[0].attribute == "cn"
        assert dn.components[0].value == "john"
        assert dn.components[1].attribute == "ou"
        assert dn.components[1].value == "users"

    def test_empty_dn_validation(self) -> Any:
        """Test validation of empty DN."""
        with pytest.raises(ValueError, match="DN cannot be empty"):
            LdapDn.from_string("")

        with pytest.raises(ValueError, match="DN cannot be empty"):
            LdapDn.from_string("   ")

    def test_invalid_dn_format(self) -> Any:
        """Test validation of invalid DN format."""
        with pytest.raises(ValueError, match="Invalid DN component"):
            LdapDn.from_string("invalid_dn_format")

        with pytest.raises(ValueError, match="Invalid DN component"):
            LdapDn.from_string("cn=john,invalid_component,dc=com")

    def test_string_representation(self) -> Any:
        """Test DN string representation."""
        dn = LdapDn.from_string("cn=john,ou=users,dc=example,dc=com")
        assert str(dn) == "cn=john,ou=users,dc=example,dc=com"

    def test_normalization(self) -> Any:
        """Test DN normalization."""
        dn = LdapDn.from_string("CN=John,OU=Users,DC=Example,DC=Com")
        normalized = dn.normalize()

        assert str(normalized) == "cn=John,ou=Users,dc=Example,dc=Com"

    def test_get_rdn(self) -> Any:
        """Test getting RDN."""
        dn = LdapDn.from_string("cn=john,ou=users,dc=example,dc=com")
        rdn = dn.get_rdn()

        assert rdn.attribute == "cn"
        assert rdn.value == "john"

    def test_get_parent_dn(self) -> Any:
        """Test getting parent DN."""
        dn = LdapDn.from_string("cn=john,ou=users,dc=example,dc=com")
        parent = dn.get_parent_dn()

        assert str(parent) == "ou=users,dc=example,dc=com"

    def test_get_parent_dn_single_component(self) -> Any:
        """Test getting parent DN of single component."""
        dn = LdapDn.from_string("dc=com")
        parent = dn.get_parent_dn()

        assert parent is None

    def test_is_child_of(self) -> Any:
        """Test child relationship checking."""
        child_dn = LdapDn.from_string("cn=john,ou=users,dc=example,dc=com")
        parent_dn = LdapDn.from_string("ou=users,dc=example,dc=com")
        root_dn = LdapDn.from_string("dc=example,dc=com")
        unrelated_dn = LdapDn.from_string("ou=groups,dc=example,dc=com")

        assert child_dn.is_child_of(parent_dn) is True
        assert child_dn.is_child_of(root_dn) is True
        assert child_dn.is_child_of(unrelated_dn) is False
        assert parent_dn.is_child_of(child_dn) is False

    def test_append_component(self) -> Any:
        """Test appending component to DN."""
        dn = LdapDn.from_string("ou=users,dc=example,dc=com")
        new_dn = dn.append_component("cn", "john")

        assert str(new_dn) == "cn=john,ou=users,dc=example,dc=com"
        # Original DN should be unchanged
        assert str(dn) == "ou=users,dc=example,dc=com"

    def test_replace_base_dn(self) -> Any:
        """Test replacing base DN."""
        dn = LdapDn.from_string("cn=john,ou=users,dc=example,dc=com")
        old_base = LdapDn.from_string("dc=example,dc=com")
        new_base = LdapDn.from_string("dc=newdomain,dc=org")

        new_dn = dn.replace_base_dn(old_base, new_base)

        assert str(new_dn) == "cn=john,ou=users,dc=newdomain,dc=org"

    def test_replace_base_dn_invalid(self) -> Any:
        """Test replacing base DN with invalid base."""
        dn = LdapDn.from_string("cn=john,ou=users,dc=example,dc=com")
        invalid_base = LdapDn.from_string("dc=other,dc=com")
        new_base = LdapDn.from_string("dc=newdomain,dc=org")

        with pytest.raises(
            ValueError,
            match="DN is not a child of the specified base DN",
        ):
            dn.replace_base_dn(invalid_base, new_base)


class TestConnectionProfile:
    """Test connection profile dataclass."""

    def test_valid_profile_creation(self) -> Any:
        """Test creating valid connection profile."""
        profile = ConnectionProfile(
            name="test-profile",
            host="ldap.example.com",
            port=389,
            bind_dn="cn=admin,dc=example,dc=com",
            password="secret",
            base_dn="dc=example,dc=com",
        )

        assert profile.name == "test-profile"
        assert profile.host == "ldap.example.com"
        assert profile.port == 389
        assert profile.use_ssl is False
        assert profile.timeout == 30

    def test_ssl_profile(self) -> Any:
        """Test SSL connection profile."""
        profile = ConnectionProfile(
            name="ssl-profile",
            host="ldaps.example.com",
            port=636,
            bind_dn="cn=admin,dc=example,dc=com",
            password="secret",
            base_dn="dc=example,dc=com",
            use_ssl=True,
        )

        assert profile.use_ssl is True
        assert profile.port == 636

    def test_empty_name_validation(self) -> Any:
        """Test validation of empty profile name."""
        with pytest.raises(ValueError, match="Profile name cannot be empty"):
            ConnectionProfile(
                name="",
                host="ldap.example.com",
                port=389,
                bind_dn="cn=admin,dc=example,dc=com",
                password="secret",
                base_dn="dc=example,dc=com",
            )

    def test_invalid_port_validation(self) -> Any:
        """Test port validation."""
        with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
            ConnectionProfile(
                name="test",
                host="ldap.example.com",
                port=0,
                bind_dn="cn=admin,dc=example,dc=com",
                password="secret",
                base_dn="dc=example,dc=com",
            )

    def test_invalid_timeout_validation(self) -> Any:
        """Test timeout validation."""
        with pytest.raises(ValueError, match="Timeout must be positive"):
            ConnectionProfile(
                name="test",
                host="ldap.example.com",
                port=389,
                bind_dn="cn=admin,dc=example,dc=com",
                password="secret",
                base_dn="dc=example,dc=com",
                timeout=0,
            )

    def test_ldap_url_generation(self) -> Any:
        """Test LDAP URL generation."""
        profile = ConnectionProfile(
            name="test",
            host="ldap.example.com",
            port=389,
            bind_dn="cn=admin,dc=example,dc=com",
            password="secret",
            base_dn="dc=example,dc=com",
        )

        assert profile.to_ldap_url() == "ldap://ldap.example.com:389"

        ssl_profile = ConnectionProfile(
            name="ssl-test",
            host="ldaps.example.com",
            port=636,
            bind_dn="cn=admin,dc=example,dc=com",
            password="secret",
            base_dn="dc=example,dc=com",
            use_ssl=True,
        )

        assert ssl_profile.to_ldap_url() == "ldaps://ldaps.example.com:636"


class TestTransformationRule:
    """Test transformation rule dataclass."""

    def test_valid_rule_creation(self) -> Any:
        """Test creating valid transformation rule."""
        rule = TransformationRule(
            name="User Migration",
            description="Transform user entries",
            source_pattern="cn={user},ou=People,dc=oracle,dc=com",
            target_pattern="cn={user},ou=users,dc=example,dc=com",
            attribute_mappings={"orclCommonAttribute": "commonName"},
            object_class_mappings={"orclUser": "inetOrgPerson"},
        )

        assert rule.name == "User Migration"
        assert rule.enabled is True
        assert "orclCommonAttribute" in rule.attribute_mappings
        assert "orclUser" in rule.object_class_mappings

    def test_empty_name_validation(self) -> Any:
        """Test validation of empty rule name."""
        with pytest.raises(ValueError, match="Rule name cannot be empty"):
            TransformationRule(
                name="",
                description="Test rule",
                source_pattern="test",
                target_pattern="test",
                attribute_mappings={},
                object_class_mappings={},
            )

    def test_empty_pattern_validation(self) -> Any:
        """Test validation of empty patterns."""
        with pytest.raises(ValueError, match="Source pattern cannot be empty"):
            TransformationRule(
                name="test",
                description="Test rule",
                source_pattern="",
                target_pattern="test",
                attribute_mappings={},
                object_class_mappings={},
            )

        with pytest.raises(ValueError, match="Target pattern cannot be empty"):
            TransformationRule(
                name="test",
                description="Test rule",
                source_pattern="test",
                target_pattern="",
                attribute_mappings={},
                object_class_mappings={},
            )


class TestSchemaAnalysisResult:
    """Test schema analysis result dataclass."""

    def test_compatible_schema(self) -> Any:
        """Test compatible schema result."""
        result = SchemaAnalysisResult(
            compatibility=SchemaCompatibility.FULL,
            required_mappings={},
            missing_object_classes=[],
            missing_attributes=[],
            warnings=[],
            recommendations=[],
        )

        assert result.compatibility == SchemaCompatibility.FULL
        assert result.is_migration_possible is True

    def test_incompatible_schema(self) -> Any:
        """Test incompatible schema result."""
        result = SchemaAnalysisResult(
            compatibility=SchemaCompatibility.INCOMPATIBLE,
            required_mappings={},
            missing_object_classes=["customObjectClass"],
            missing_attributes=["customAttribute"],
            warnings=["Schema incompatibility detected"],
            recommendations=["Update target schema"],
        )

        assert result.compatibility == SchemaCompatibility.INCOMPATIBLE
        assert result.is_migration_possible is False

    def test_requires_mapping_schema(self) -> Any:
        """Test schema that requires mapping."""
        result = SchemaAnalysisResult(
            compatibility=SchemaCompatibility.REQUIRES_MAPPING,
            required_mappings={"orclUser": "inetOrgPerson"},
            missing_object_classes=[],
            missing_attributes=[],
            warnings=["Object class mapping required"],
            recommendations=["Configure object class mappings"],
        )

        assert result.compatibility == SchemaCompatibility.REQUIRES_MAPPING
        assert result.is_migration_possible is True
        assert "orclUser" in result.required_mappings


class TestMigrationPlan:
    """Test migration plan dataclass."""

    def create_test_profiles(self) -> Any:
        """Create test connection profiles."""
        source = ConnectionProfile(
            name="source",
            host="source.example.com",
            port=389,
            bind_dn="cn=admin,dc=source,dc=com",
            password="secret",
            base_dn="dc=source,dc=com",
        )

        target = ConnectionProfile(
            name="target",
            host="target.example.com",
            port=389,
            bind_dn="cn=admin,dc=target,dc=com",
            password="secret",
            base_dn="dc=target,dc=com",
        )

        return source, target

    def create_test_schema_analysis(
        self,
        compatibility=SchemaCompatibility.FULL,
    ) -> Any:
        """Create test schema analysis result."""
        return SchemaAnalysisResult(
            compatibility=compatibility,
            required_mappings={},
            missing_object_classes=[],
            missing_attributes=[],
            warnings=[],
            recommendations=[],
        )

    def test_valid_plan_creation(self) -> Any:
        """Test creating valid migration plan."""
        source, target = self.create_test_profiles()
        schema_analysis = self.create_test_schema_analysis()

        plan = MigrationPlan(
            name="Test Migration",
            description="Test migration plan",
            source_profile=source,
            target_profile=target,
            transformation_rules=[],
            schema_analysis=schema_analysis,
            phases=["phase1", "phase2"],
        )

        assert plan.name == "Test Migration"
        assert plan.is_ready_for_execution is True

    def test_empty_name_validation(self) -> Any:
        """Test validation of empty plan name."""
        source, target = self.create_test_profiles()
        schema_analysis = self.create_test_schema_analysis()

        with pytest.raises(ValueError, match="Plan name cannot be empty"):
            MigrationPlan(
                name="",
                description="Test plan",
                source_profile=source,
                target_profile=target,
                transformation_rules=[],
                schema_analysis=schema_analysis,
                phases=["phase1"],
            )

    def test_empty_phases_validation(self) -> Any:
        """Test validation of empty phases."""
        source, target = self.create_test_profiles()
        schema_analysis = self.create_test_schema_analysis()

        with pytest.raises(ValueError, match="Plan must have at least one phase"):
            MigrationPlan(
                name="Test",
                description="Test plan",
                source_profile=source,
                target_profile=target,
                transformation_rules=[],
                schema_analysis=schema_analysis,
                phases=[],
            )

    def test_incompatible_schema_validation(self) -> Any:
        """Test validation with incompatible schema."""
        source, target = self.create_test_profiles()
        incompatible_schema = self.create_test_schema_analysis(
            SchemaCompatibility.INCOMPATIBLE,
        )

        with pytest.raises(
            ValueError,
            match="Migration plan cannot be created with incompatible schema",
        ):
            MigrationPlan(
                name="Test",
                description="Test plan",
                source_profile=source,
                target_profile=target,
                transformation_rules=[],
                schema_analysis=incompatible_schema,
                phases=["phase1"],
            )

    def test_ready_for_execution_with_rules(self) -> Any:
        """Test readiness with transformation rules."""
        source, target = self.create_test_profiles()
        schema_analysis = self.create_test_schema_analysis()

        rule = TransformationRule(
            name="test rule",
            description="test",
            source_pattern="test",
            target_pattern="test",
            attribute_mappings={},
            object_class_mappings={},
        )

        plan = MigrationPlan(
            name="Test",
            description="Test plan",
            source_profile=source,
            target_profile=target,
            transformation_rules=[rule],
            schema_analysis=schema_analysis,
            phases=["phase1"],
        )

        assert plan.is_ready_for_execution is True

    def test_not_ready_without_rules(self) -> Any:
        """Test not ready without transformation rules."""
        source, target = self.create_test_profiles()
        schema_analysis = self.create_test_schema_analysis()

        plan = MigrationPlan(
            name="Test",
            description="Test plan",
            source_profile=source,
            target_profile=target,
            transformation_rules=[],  # No rules
            schema_analysis=schema_analysis,
            phases=["phase1"],
        )

        assert plan.is_ready_for_execution is False
