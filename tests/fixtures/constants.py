"""Test constants for flext-ldap tests.

Flat class structure for reusable constants across all test modules.
No type checking, all constants defined at module level.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from tests.fixtures.general_constants import General
from tests.fixtures.oid_constants import OID
from tests.fixtures.openldap2_constants import OpenLDAP2
from tests.fixtures.oud_constants import OUD
from tests.fixtures.rfc_constants import RFC


class TestConstants:
    """Flat class with test constants for flext-ldap tests."""

    # Server types supported by flext-ldif quirks
    SERVER_TYPE_RFC = "rfc"
    SERVER_TYPE_GENERIC = "generic"
    SERVER_TYPE_OID = "oid"
    SERVER_TYPE_OUD = "oud"
    SERVER_TYPE_OPENLDAP2 = "openldap2"

    # Valid server types for testing (only those registered in quirks)
    VALID_SERVER_TYPES = (SERVER_TYPE_RFC, SERVER_TYPE_GENERIC)

    # LDAP connection defaults (using RFC constants as base)
    DEFAULT_HOST = RFC.DEFAULT_HOST
    DEFAULT_PORT = RFC.DEFAULT_PORT
    DEFAULT_BASE_DN = RFC.DEFAULT_BASE_DN
    DEFAULT_BIND_DN = RFC.DEFAULT_BIND_DN
    DEFAULT_BIND_PASSWORD = RFC.DEFAULT_BIND_PASSWORD

    # Search defaults
    DEFAULT_FILTER = RFC.DEFAULT_FILTER
    DEFAULT_SCOPE = RFC.DEFAULT_SCOPE
    DEFAULT_ATTRIBUTES = RFC.DEFAULT_ATTRIBUTES

    # Test entry defaults
    TEST_USER_CN = RFC.TEST_USER_CN
    TEST_USER_DN = RFC.TEST_USER_DN
    TEST_GROUP_CN = RFC.TEST_GROUP_CN
    TEST_GROUP_DN = RFC.TEST_GROUP_DN

    # Organizational Units
    OU_PEOPLE = RFC.OU_PEOPLE
    OU_GROUPS = RFC.OU_GROUPS
    OU_SYSTEM = RFC.OU_SYSTEM

    OU_PEOPLE_DN = RFC.OU_PEOPLE_DN
    OU_GROUPS_DN = RFC.OU_GROUPS_DN
    OU_SYSTEM_DN = RFC.OU_SYSTEM_DN


__all__ = ["OID", "OUD", "RFC", "General", "OpenLDAP2", "TestConstants"]
