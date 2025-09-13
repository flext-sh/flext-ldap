"""LDAP Utilities module.

The absolute minimum utilities needed, using Python standard library and
flext-core instead of custom implementations.

All custom wrappers have been eliminated in favor of:
- Python standard library functions
- ldap3 library direct usage
- flext-core FlextUtilities
- Pydantic validators

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextTypes

# Export only what's actually needed - everything else uses standard libraries
__all__: FlextTypes.Core.StringList = []
