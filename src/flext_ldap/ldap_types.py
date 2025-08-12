"""Legacy compatibility: re-export types from centralized `typings.py`.

This file remains for backward compatibility only. All definitions were
moved to `flext_ldap/typings.py`. Import from there going forward.
"""

from __future__ import annotations

from flext_ldap.typings import *  # noqa: F403 re-export centralized types
