"""Comprehensive tests for FlextLdapTypes module.

Tests verify all type aliases, nested classes, and inheritance from FlextTypes.
For type definition modules, testing focuses on structure and accessibility of types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextTypes

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.typings import FlextLdapTypes


class TestFlextLdapTypesStructure:
    """Test FlextLdapTypes structure and inheritance."""

    def test_extends_flextcore_types(self) -> None:
        """Verify FlextLdapTypes extends FlextTypes."""
        assert issubclass(FlextLdapTypes, FlextTypes)

    def test_has_annotated_ldap_class(self) -> None:
        """Verify AnnotatedLdap nested class exists."""
        assert hasattr(FlextLdapTypes, "AnnotatedLdap")
        assert FlextLdapTypes.AnnotatedLdap is not None

    def test_has_ldap3_protocols_class(self) -> None:
        """Verify Ldap3Protocols nested class exists."""
        assert hasattr(FlextLdapTypes, "Ldap3Protocols")
        assert FlextLdapTypes.Ldap3Protocols is not None


# NOTE: Type structure has been refactored to module-level type aliases using
# Python 3.13+ syntax. Nested class tests (LdapDomain, LdapCore, LdapEntries)
# have been removed as the architecture now uses flat module-level type definitions.
# Type validation is now handled through actual code usage and type checking with Pyrefly.
# See typings.py for current type alias definitions.


class TestFlextLdapTypesIntegration:
    """Integration tests for FlextLdapTypes with dependencies."""

    def test_uses_flextcore_types(self) -> None:
        """Verify FlextLdapTypes uses FlextTypes dependencies."""
        # Verify Pydantic v2 refactoring removed simple type aliases
        # Now use native Python types: list[str], dict[str, object]
        # Check for complex types that still exist
        assert hasattr(FlextTypes, "IntList")
        assert hasattr(FlextTypes, "FloatList")
        assert hasattr(FlextTypes, "NestedDict")

    def test_uses_flextldap_constants_literal_types(self) -> None:
        """Verify FlextLdapTypes can access FlextLdapConstants.Types class."""
        # After Pydantic v2 refactoring, all type aliases are in FlextLdapConstants.Types
        # Python 3.13 type aliases are compile-time only, not runtime attributes
        # We can only verify that the Types class exists
        assert hasattr(FlextLdapConstants, "Types")

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
        """Verify FlextLdapTypes can be instantiated (inherits from FlextTypes)."""
        instance = FlextLdapTypes()
        assert instance is not None
        assert isinstance(instance, FlextTypes)
