"""Domain-specific model test helpers for flext-ldap tests.

Re-exports generic helpers from flext-core and adds LDAP-specific patterns.
All generic patterns are now in flext_tests.FlextTestsUtilities.ModelTestHelpers.

**Modules Used:**
- flext_tests.FlextTestsUtilities.ModelTestHelpers: Generic model testing patterns
- flext_tests.ModelFactory: Protocol for factory methods

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsUtilities, ModelFactory

# Re-export from flext-core for backward compatibility
ModelTestHelpers = FlextTestsUtilities.ModelTestHelpers

__all__ = [
    "ModelFactory",
    "ModelTestHelpers",
]
