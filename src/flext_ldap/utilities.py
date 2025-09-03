"""FLEXT LDAP Utilities - Minimal utilities using libraries instead of custom code.

Following the mandate to PRIORIZE BIBLIOTECAS, this module now contains only
the absolute minimum utilities needed, using Python standard library and
flext-core instead of custom implementations.

All custom wrappers have been eliminated in favor of:
- Python standard library functions
- ldap3 library direct usage
- flext-core FlextUtilities
- Pydantic validators
"""

from __future__ import annotations

from flext_core import FlextLogger

logger = FlextLogger(__name__)

# Export only what's actually needed - everything else uses standard libraries
__all__: list[str] = []
