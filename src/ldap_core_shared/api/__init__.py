"""LDAP API Package - True Facade Pattern Implementation.

This package implements a proper Facade pattern by breaking down the monolithic
api.py into specialized modules, each with single responsibility.

ARCHITECTURE:
- api/config.py → LDAPConfig Value Object ✅
- api/results.py → Result[T] pattern ✅
- api/query.py → Query Builder pattern ✅
- api/operations.py → LDAP operations (delegates to existing subsystems) ✅
- api/validation.py → Schema validation (delegates to existing modules) ✅
- api/facade.py → True Facade (~400 lines, pure delegation) ✅

PRINCIPLES:
- Each module has single responsibility ✅
- Facade only delegates, no business logic ✅
- Maintains 100% API compatibility ✅
- Uses existing subsystem modules (connections, domain, etc.) ✅

REFACTORING COMPLETED:
- Phase 1: Extract config, results, query ✅
- Phase 2: Extract operations and validation ✅
- Phase 3: Create thin facade that delegates ✅
- Phase 4: Ready to replace monolithic api.py ✅
"""

# Re-export the extracted components for full compatibility
from ldap_core_shared.api.config import LDAPConfig

# Import the true facade
from ldap_core_shared.api.facade import (
    LDAP,
    connect,
    ldap_session,
    validate_ldap_config,
)
from ldap_core_shared.api.query import Query
from ldap_core_shared.api.results import Result

__all__ = [
    # Main facade and convenience functions
    "LDAP",                 # True Facade (pure delegation)
    # Core components
    "LDAPConfig",   # Value Object for configuration
    "Query",        # Builder Pattern for queries
    "Result",       # Value Object for results
    "connect",              # Factory method for quick connections
    "ldap_session",         # Context manager factory
    "validate_ldap_config",  # Configuration validation
]
