"""Version metadata for flext ldap using centralized constants."""

from __future__ import annotations

from flext_ldap.constants import FlextLdapConstants

# Use centralized constants - no module-level constants
__version__ = FlextLdapConstants.Version.get_version()
__version_info__ = FlextLdapConstants.Version.get_version_info()

__all__ = ["__version__", "__version_info__"]
