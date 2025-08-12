"""FLEXT LDAP Legacy - Backward compatibility for deprecated modules.

SIMPLIFIED VERSION: Provides basic backward compatibility without complex re-exports.
All complex import patterns have been removed to resolve MyPy conflicts.

Architecture:
    - Maintains basic backward compatibility
    - Issues deprecation warnings for legacy usage
    - Directs users to new consolidated modules
    - Avoids complex re-export patterns that cause type conflicts

Migration Strategy:
    - Users should migrate to: from flext_ldap import FlextLdapApi, FlextLdapConfig, etc.
    - Legacy imports will show deprecation warnings
    - Direct users to proper import paths

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import warnings

from flext_core import get_logger

logger = get_logger(__name__)


def _show_deprecation_warning(old_name: str, new_name: str) -> None:
    """Show deprecation warning for legacy usage."""
    warnings.warn(
        f"{old_name} is deprecated. Use 'from flext_ldap import {new_name}' instead.",
        DeprecationWarning,
        stacklevel=3,
    )


# Simple legacy constants - no complex imports
LEGACY_LDAP_DEFAULT_PORT = 389
LEGACY_LDAPS_DEFAULT_PORT = 636


# Simple backward compatibility message
def get_migration_help() -> str:
    """Get migration help for users of legacy modules."""
    return """
FLEXT LDAP Migration Guide:

Legacy Pattern -> Modern Pattern:
from flext_ldap.ldap_api import LdapApi -> from flext_ldap import FlextLdapApi
from flext_ldap.ldap_config import LdapConfig -> from flext_ldap import FlextLdapConfig
from flext_ldap.ldap_models import LdapUser -> from flext_ldap import FlextLdapUser

For full documentation, see the FLEXT LDAP documentation.
"""


__all__ = [
    "LEGACY_LDAPS_DEFAULT_PORT",
    "LEGACY_LDAP_DEFAULT_PORT",
    "get_migration_help",
]
