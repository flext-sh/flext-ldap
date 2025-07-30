"""Deprecation management for FLEXT LDAP.

Handles backward compatibility and migration warnings pointing users
to the new simplified import patterns.

Old complex paths still work but show clear guidance to simple alternatives.
"""

from __future__ import annotations

import warnings


class LDAPDeprecationWarning(DeprecationWarning):
    """Custom deprecation warning for LDAP-specific deprecations.

    Provides clear guidance to users on how to migrate from complex

    """


def warn_deprecated(
    old_path: str,
    new_path: str,
    version: str = "0.9.0",
) -> None:
    """Issue deprecation warning with migration guidance.

    Args:
        old_path: The deprecated import/usage path
        new_path: The new recommended path
        version: Version when the deprecated feature will be removed

    """
    warnings.warn(
        f"\n\n🚨 DEPRECATED COMPLEX PATH:\n"
        f"Using '{old_path}' is deprecated.\n\n"
        f"🎯 SIMPLE IMPORT SOLUTION:\n"
        f"Use: {new_path}\n\n"
        f"💡 PRODUCTIVITY TIP:\n"
        f"All FLEXT LDAP imports are now available at root level!\n"
        f"No more complex nested paths - just import what you need directly.\n\n"
        f"🔄 MIGRATION:\n"
        f"Support for complex paths will be removed in version {version}.\n"
        f"Use simple root-level imports for better developer experience.\n\n"
        f"Examples:\n"
        f"✅ from flext_ldap import LDAPClient, LDAPUser, LDAPGroup\n"
        f"✅ from flext_ldap import FlextLdapDistinguishedName, LDAPFilter\n"
        f"✅ from flext_ldap import LDAPService\n",
        LDAPDeprecationWarning,
        stacklevel=3,
    )


def warn_deprecated_path(
    old_path: str,
    recommendation: str,
    version: str = "0.9.0",
) -> None:
    """Issue deprecation warning for complex import paths.

    Args:
        old_path: The deprecated complex import path or pattern
        recommendation: Simple recommendation for replacement
        version: Version when support will be removed

    """
    warnings.warn(
        f"\n\n🚨 DEPRECATED COMPLEX PATH:\n"
        f"Using '{old_path}' is deprecated.\n\n"
        f"🎯 SIMPLE IMPORT SOLUTION:\n"
        f"{recommendation}\n\n"
        f"💡 PRODUCTIVITY TIP:\n"
        f"All FLEXT LDAP imports are now available at root level!\n"
        f"No more complex nested paths - just import what you need directly.\n\n"
        f"🔄 MIGRATION:\n"
        f"Support for complex paths will be removed in version {version}.\n"
        f"Use simple root-level imports for better developer experience.\n\n"
        f"Examples:\n"
        f"✅ from flext_ldap import LDAPClient\n"
        f"✅ from flext_ldap import LDAPUser, LDAPGroup\n"
        f"✅ from flext_ldap import FlextLdapDistinguishedName\n",
        LDAPDeprecationWarning,
        stacklevel=3,
    )
