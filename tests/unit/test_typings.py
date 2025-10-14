"""Comprehensive tests for FlextLdapTypes module.

Tests verify all type aliases, nested classes, and inheritance from FlextCore.Types.
For type definition modules, testing focuses on structure and accessibility of types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextCore

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.typings import FlextLdapTypes


class TestFlextLdapTypesStructure:
    """Test FlextLdapTypes structure and inheritance."""

    def test_extends_flextcore_types(self) -> None:
        """Verify FlextLdapTypes extends FlextCore.Types."""
        assert issubclass(FlextLdapTypes, FlextCore.Types)

    def test_has_ldap_domain_class(self) -> None:
        """Verify LdapDomain nested class exists."""
        assert hasattr(FlextLdapTypes, "LdapDomain")
        assert FlextLdapTypes.LdapDomain is not None

    def test_has_ldap_core_class(self) -> None:
        """Verify LdapCore nested class exists."""
        assert hasattr(FlextLdapTypes, "LdapCore")
        assert FlextLdapTypes.LdapCore is not None

    def test_has_ldap_entries_class(self) -> None:
        """Verify LdapEntries nested class exists."""
        assert hasattr(FlextLdapTypes, "LdapEntries")
        assert FlextLdapTypes.LdapEntries is not None

    def test_has_project_class(self) -> None:
        """Verify Project nested class exists and extends FlextCore.Types.Project."""
        assert hasattr(FlextLdapTypes, "Project")
        assert issubclass(FlextLdapTypes.Project, FlextCore.Types.Project)


class TestLdapDomainTypes:
    """Test LdapDomain type aliases."""

    def test_attribute_value_type_alias(self) -> None:
        """Verify AttributeValue type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "AttributeValue")

    def test_attribute_dict_type_alias(self) -> None:
        """Verify AttributeDict type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "AttributeDict")

    def test_modify_changes_type_alias(self) -> None:
        """Verify ModifyChanges type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "ModifyChanges")

    def test_search_filter_type_alias(self) -> None:
        """Verify SearchFilter type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "SearchFilter")

    def test_search_scope_type_alias(self) -> None:
        """Verify SearchScope type alias exists."""
        # Note: Python 3.13 type aliases are compile-time only, not runtime attributes
        assert hasattr(FlextLdapTypes.LdapDomain, "SearchScope")

    def test_search_result_type_alias(self) -> None:
        """Verify SearchResult type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "SearchResult")

    def test_server_uri_type_alias(self) -> None:
        """Verify ServerURI type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "ServerURI")

    def test_bind_dn_type_alias(self) -> None:
        """Verify BindDN type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "BindDN")

    def test_bind_password_type_alias(self) -> None:
        """Verify BindPassword type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "BindPassword")

    def test_distinguished_name_type_alias(self) -> None:
        """Verify DistinguishedName type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "DistinguishedName")

    def test_object_class_type_alias(self) -> None:
        """Verify ObjectClass type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "ObjectClass")

    def test_attribute_name_type_alias(self) -> None:
        """Verify AttributeName type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "AttributeName")

    def test_connection_state_type_alias(self) -> None:
        """Verify ConnectionState type alias exists."""
        # Note: Python 3.13 type aliases are compile-time only, not runtime attributes
        assert hasattr(FlextLdapTypes.LdapDomain, "ConnectionState")

    def test_operation_type_type_alias(self) -> None:
        """Verify OperationType type alias exists."""
        # Note: Python 3.13 type aliases are compile-time only, not runtime attributes
        assert hasattr(FlextLdapTypes.LdapDomain, "OperationType")

    def test_security_level_type_alias(self) -> None:
        """Verify SecurityLevel type alias exists."""
        # Note: Python 3.13 type aliases are compile-time only, not runtime attributes
        assert hasattr(FlextLdapTypes.LdapDomain, "SecurityLevel")

    def test_authentication_method_type_alias(self) -> None:
        """Verify AuthenticationMethod type alias exists."""
        # Note: Python 3.13 type aliases are compile-time only, not runtime attributes
        assert hasattr(FlextLdapTypes.LdapDomain, "AuthenticationMethod")

    def test_bulk_operation_type_alias(self) -> None:
        """Verify BulkOperation type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "BulkOperation")

    def test_search_configuration_type_alias(self) -> None:
        """Verify SearchConfiguration type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "SearchConfiguration")

    def test_entry_template_type_alias(self) -> None:
        """Verify EntryTemplate type alias exists."""
        assert hasattr(FlextLdapTypes.LdapDomain, "EntryTemplate")


class TestLdapCoreTypes:
    """Test LdapCore type aliases."""

    def test_ldap_config_value_type_alias(self) -> None:
        """Verify LdapConfigValue type alias exists."""
        assert hasattr(FlextLdapTypes.LdapCore, "LdapConfigValue")

    def test_ldap_attribute_value_type_alias(self) -> None:
        """Verify LdapAttributeValue type alias exists."""
        assert hasattr(FlextLdapTypes.LdapCore, "LdapAttributeValue")

    def test_ldap_entry_value_type_alias(self) -> None:
        """Verify LdapEntryValue type alias exists."""
        assert hasattr(FlextLdapTypes.LdapCore, "LdapEntryValue")


class TestLdapEntriesTypes:
    """Test LdapEntries type aliases."""

    def test_entry_attribute_value_type_alias(self) -> None:
        """Verify EntryAttributeValue type alias exists."""
        assert hasattr(FlextLdapTypes.LdapEntries, "EntryAttributeValue")

    def test_entry_attribute_dict_type_alias(self) -> None:
        """Verify EntryAttributeDict type alias exists."""
        assert hasattr(FlextLdapTypes.LdapEntries, "EntryAttributeDict")


class TestLdapProjectTypes:
    """Test Project type aliases."""

    def test_ldap_project_type_alias(self) -> None:
        """Verify LdapProjectType type alias exists."""
        # Note: Python 3.13 type aliases are compile-time only, not runtime attributes
        assert hasattr(FlextLdapTypes.Project, "LdapProjectType")

    def test_ldap_project_config_type_alias(self) -> None:
        """Verify LdapProjectConfig type alias exists."""
        assert hasattr(FlextLdapTypes.Project, "LdapProjectConfig")

    def test_directory_config_type_alias(self) -> None:
        """Verify DirectoryConfig type alias exists."""
        assert hasattr(FlextLdapTypes.Project, "DirectoryConfig")

    def test_authentication_config_type_alias(self) -> None:
        """Verify AuthenticationConfig type alias exists."""
        assert hasattr(FlextLdapTypes.Project, "AuthenticationConfig")

    def test_sync_config_type_alias(self) -> None:
        """Verify SyncConfig type alias exists."""
        assert hasattr(FlextLdapTypes.Project, "SyncConfig")


class TestFlextLdapTypesIntegration:
    """Integration tests for FlextLdapTypes with dependencies."""

    def test_uses_flextcore_types(self) -> None:
        """Verify FlextLdapTypes uses FlextCore.Types dependencies."""
        # Verify FlextCore.Types.StringList is accessible
        assert hasattr(FlextCore.Types, "StringList")
        # Verify FlextCore.Types.Dict is accessible
        assert hasattr(FlextCore.Types, "Dict")

    def test_uses_flextldap_constants_literal_types(self) -> None:
        """Verify FlextLdapTypes can access FlextLdapConstants.LiteralTypes class."""
        # Python 3.13 type aliases are compile-time only, not runtime attributes
        # We can only verify that the LiteralTypes class exists
        assert hasattr(FlextLdapConstants, "LiteralTypes")

    def test_no_circular_imports(self) -> None:
        """Verify no circular imports between typings and constants."""
        # This test passes if imports succeed
        from flext_ldap.constants import FlextLdapConstants as ConstCheck
        from flext_ldap.typings import FlextLdapTypes as TypeCheck

        assert ConstCheck is not None
        assert TypeCheck is not None

    def test_module_exports(self) -> None:
        """Verify module __all__ exports."""
        from flext_ldap import typings

        assert hasattr(typings, "__all__")
        assert "FlextLdapTypes" in typings.__all__


class TestFlextLdapTypesInstantiation:
    """Test FlextLdapTypes instantiation (though typically not instantiated)."""

    def test_can_instantiate_flextldap_types(self) -> None:
        """Verify FlextLdapTypes can be instantiated (inherits from FlextCore.Types)."""
        instance = FlextLdapTypes()
        assert instance is not None
        assert isinstance(instance, FlextCore.Types)
