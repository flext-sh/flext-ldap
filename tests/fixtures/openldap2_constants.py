"""OpenLDAP 2 server test constants module.

Flat class containing OpenLDAP 2 server test constants.
Constants are defined at module level without type checking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_ldif.constants import FlextLdifConstants

from flext_ldap.constants import FlextLdapConstants


class OpenLDAP2:
    """Flat namespace for OpenLDAP 2 server test constants - no type checking."""

    # Server type - reuse production StrEnum from flext-ldif
    SERVER_TYPE = FlextLdifConstants.ServerTypes.OPENLDAP.value

    # LDAP connection defaults
    DEFAULT_HOST = "localhost"
    DEFAULT_PORT = 389
    DEFAULT_BASE_DN = "dc=example,dc=com"
    DEFAULT_BIND_DN = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
    DEFAULT_BIND_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD"

    # Search defaults - reuse production StrEnum
    DEFAULT_FILTER = "(objectClass=*)"
    DEFAULT_SCOPE = FlextLdapConstants.SearchScope.SUBTREE.value
    DEFAULT_ATTRIBUTES = ("objectClass", "cn")

    # Test entry defaults
    TEST_USER_CN = "testuser"
    TEST_USER_DN = f"uid={TEST_USER_CN},ou=people,{DEFAULT_BASE_DN}"
    TEST_GROUP_CN = "testgroup"
    TEST_GROUP_DN = f"cn={TEST_GROUP_CN},ou=groups,{DEFAULT_BASE_DN}"

    # Organizational Units
    OU_PEOPLE = "ou=people"
    OU_GROUPS = "ou=groups"
    OU_SYSTEM = "ou=system"

    OU_PEOPLE_DN = f"{OU_PEOPLE},{DEFAULT_BASE_DN}"
    OU_GROUPS_DN = f"{OU_GROUPS},{DEFAULT_BASE_DN}"
    OU_SYSTEM_DN = f"{OU_SYSTEM},{DEFAULT_BASE_DN}"
