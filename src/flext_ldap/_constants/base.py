"""Private constants base for flext-ldap.

Owns every plain-literal scalar constant value so the public ``constants.py``
facade module never declares a bare literal class attribute directly
(ENFORCE-079); the facade re-exports them via ``c.Ldap.*`` through
inheritance.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final


class FlextLdapConstantsBase:
    """Private constants owner for LDAP scalar defaults."""

    NAME: Final[str] = "FLEXT_LDAP"


__all__: list[str] = ["FlextLdapConstantsBase"]
