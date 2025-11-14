"""Oracle Internet Directory server test constants module.

Flat class containing OID server test constants.
Constants are defined at module level without type checking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


class OID:
    """Flat namespace for OID server test constants - no type checking."""

    # Server type
    SERVER_TYPE = "oid"

    # LDAP connection defaults
    DEFAULT_HOST = "localhost"
    DEFAULT_PORT = 3060
    DEFAULT_BASE_DN = "dc=example,dc=com"
    DEFAULT_BIND_DN = "cn=orcladmin"
    DEFAULT_BIND_PASSWORD = "password"

    # Search defaults
    DEFAULT_FILTER = "(objectClass=*)"
    DEFAULT_SCOPE = "SUBTREE"
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
