"""🚀 LDAP Core Shared - Unified Enterprise LDAP Library.

**Modern Python LDAP library with enterprise features and unified API**

**Key Features:**
- ✅ **Python 3.9+ Support**: Compatible with Python 3.9 through 3.13
- ⚡ **Unified API**: Single, clean interface for all LDAP operations
- 🛡️ **Enterprise Security**: SSL/TLS, SASL, and comprehensive authentication
- 🔄 **Migration Tools**: Oracle OID → OUD, Active Directory, OpenLDAP
- 📊 **Schema Management**: Automated discovery, comparison, and validation
- 🎯 **Zero-Complexity APIs**: Simple interfaces for complex operations
- 🔍 **LDIF Processing**: High-speed streaming for large datasets
- 📈 **Performance Monitoring**: Built-in metrics and health checking
- 🧪 **Type Safety**: Full type hints and Pydantic validation

**Quick Start:**
    Basic LDAP operations with unified API:

    >>> import asyncio
    >>> from ldap_core_shared import LDAP, LDAPConfig
    >>>
    >>> # Simple connection and search
    >>> async def basic_example():
    ...     config = LDAPConfig(
    ...         server="ldaps://ldap.company.com:636",
    ...         auth_dn="cn=admin,dc=company,dc=com",
    ...         auth_password="secret",
    ...         base_dn="dc=company,dc=com"
    ...     )
    ...     async with LDAP(config) as ldap:
    ...         users = await ldap.find_users_in_department("IT")
    ...         if users.success:
    ...             print(f"Found {len(users.data)} users")
    >>>
    >>> asyncio.run(basic_example())

**Fluent Queries:**
    Chainable query building:

    >>> async with LDAP(config) as ldap:
    ...     result = await (ldap.query()
    ...         .users()
    ...         .in_department("Engineering")
    ...         .with_title("*Manager*")
    ...         .enabled_only()
    ...         .select("cn", "mail", "title")
    ...         .limit(25)
    ...         .execute())

**Convenience Functions:**
    One-liner connections:

    >>> from ldap_core_shared import ldap_session
    >>>
    >>> async with ldap_session(
    ...     server="ldap://ldap.company.com",
    ...     auth_dn="cn=service,dc=company,dc=com",
    ...     auth_password="secret",
    ...     base_dn="dc=company,dc=com"
    ... ) as ldap:
    ...     user = await ldap.find_user_by_email("john@company.com")

**Compatibility:**
    - Python 3.9+ (tested on 3.9, 3.10, 3.11, 3.12, 3.13)
    - LDAP v2/v3 protocols (RFC 4511 compliant)
    - Oracle Internet Directory (OID), Oracle Unified Directory (OUD)
    - Active Directory, OpenLDAP, Apache DS, 389 Directory Server
    - Async/await and traditional synchronous patterns

**ARCHITECTURE:**
    True Facade Pattern implementation:
    - All API calls delegate to specialized modules in api/
    - Single responsibility per module
    - Clean separation of concerns
    - 100% backward compatibility maintained
"""

from __future__ import annotations

# ============================================================================
# 🎯 API EXPORTS - Pure delegation to api/ modules
# ============================================================================
# Import everything from the api package - True Facade Pattern
from ldap_core_shared.api import *

# Explicit imports for clear documentation and IDE support
from ldap_core_shared.api import (
    LDAP,
    LDAPConfig,
    Query,
    Result,
    connect,
    ldap_session,
    validate_ldap_config,
)
from ldap_core_shared.api import __all__ as _api_all

# Import version information from centralized module
from ldap_core_shared.version import (
    AUTHOR as __author__,
)
from ldap_core_shared.version import (
    AUTHOR_EMAIL as __email__,
)
from ldap_core_shared.version import (
    LICENSE as __license__,
)
from ldap_core_shared.version import (
    __version__,
)

# Define what gets exported when using "from ldap_core_shared import *"
__all__ = [
    # Version information
    "__version__",
    "__author__",
    "__email__",
    "__license__",
] + _api_all

# Module metadata
__refactored__ = True
__refactoring_date__ = "2025-06-26"
__pattern__ = "True Facade with pure delegation to api/"
