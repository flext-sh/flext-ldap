"""FLEXT-LDAP - Consolidated single-class LDAP operations.

Enterprise-grade LDAP operations consolidated into one main FlextLdap class
following FLEXT single-class-per-project standardization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldap.__version__ import __version__, __version_info__
from flext_ldap.api import FlextLdap

__all__ = [
    "FlextLdap",
    "__version__",
    "__version_info__",
]
