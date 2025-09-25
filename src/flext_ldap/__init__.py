"""Enterprise LDAP integration library for FLEXT ecosystem.

This module provides the main exports for the flext-ldap domain following
FLEXT architectural standards with proper domain separation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.__version__ import (
    __author__,
    __author_email__,
    __branch__,
    __build__,
    __commit__,
    __copyright__,
    __description__,
    __email__,
    __license__,
    __maintainer__,
    __maintainer_email__,
    __project__,
    __version__,
    __version_info__,
    __version_tuple__,
)
from flext_ldap.acl import (
    FlextLdapAclConstants,
    FlextLdapAclConverters,
    FlextLdapAclManager,
    FlextLdapAclModels,
    FlextLdapAclParsers,
)

# Main domain API - primary entry point
from flext_ldap.api import FlextLdapAPI

# Core domain components
from flext_ldap.clients import FlextLdapClient
from flext_ldap.config import FlextLdapConfig

# Constants and models
from flext_ldap.constants import FlextLdapConstants

# Advanced service components
from flext_ldap.domain_services import (
    FlextLdapDomainServices,
)
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.factory import FlextLdapFactory
from flext_ldap.mixins import FlextLdapMixins
from flext_ldap.models import FlextLdapModels

# Type system and protocols
from flext_ldap.protocols import FlextLdapProtocols

# Domain utilities
from flext_ldap.repositories import FlextLdapRepositories

# Generic universal compatibility components
from flext_ldap.schema import FlextLdapSchema
from flext_ldap.services import FlextLdapAdvancedService
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities
from flext_ldap.validations import FlextLdapValidations
from flext_ldap.workflows import (
    FlextLdapWorkflowOrchestrator,
)

# Advanced domain services

# Main domain exports following FLEXT standards
__all__ = [
    "FlextLdapAPI",
    "FlextLdapAclConstants",
    "FlextLdapAclConverters",
    "FlextLdapAclManager",
    "FlextLdapAclModels",
    "FlextLdapAclParsers",
    "FlextLdapAdvancedService",
    "FlextLdapClient",
    "FlextLdapConfig",
    "FlextLdapConstants",
    "FlextLdapDomainServices",
    "FlextLdapExceptions",
    "FlextLdapFactory",
    "FlextLdapMixins",
    "FlextLdapModels",
    "FlextLdapProtocols",
    "FlextLdapRepositories",
    "FlextLdapSchema",
    "FlextLdapTypes",
    "FlextLdapUtilities",
    "FlextLdapValidations",
    "FlextLdapWorkflowOrchestrator",
    "__author__",
    "__author_email__",
    "__branch__",
    "__build__",
    "__commit__",
    "__copyright__",
    "__description__",
    "__email__",
    "__license__",
    "__maintainer__",
    "__maintainer_email__",
    "__project__",
    "__version__",
    "__version_info__",
    "__version_tuple__",
]
