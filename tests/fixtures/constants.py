"""Test constants for flext-ldap tests.

Hierarchical namespace structure for reusable constants across all test modules.
Organized by domain with nested classes for better organization and reuse.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from .general_constants import General
from .oid_constants import OID
from .openldap2_constants import OpenLDAP2
from .oud_constants import OUD
from .rfc_constants import RFC


class TestConstants:
    """Hierarchical test constants for flext-ldap tests with domain-based organization."""

    # Top-level shortcuts for common constants
    DEFAULT_BASE_DN: ClassVar[str] = RFC.DEFAULT_BASE_DN
    DEFAULT_HOST: ClassVar[str] = RFC.DEFAULT_HOST
    DEFAULT_PORT: ClassVar[int] = RFC.DEFAULT_PORT
    DEFAULT_BIND_DN: ClassVar[str] = RFC.DEFAULT_BIND_DN
    DEFAULT_BIND_PASSWORD: ClassVar[str] = RFC.DEFAULT_BIND_PASSWORD
    DEFAULT_FILTER: ClassVar[str] = RFC.DEFAULT_FILTER
    DEFAULT_SCOPE: ClassVar[str] = RFC.DEFAULT_SCOPE
    DEFAULT_ATTRIBUTES: ClassVar[tuple[str, ...]] = RFC.DEFAULT_ATTRIBUTES
    TEST_USER_CN: ClassVar[str] = RFC.TEST_USER_CN
    TEST_USER_DN: ClassVar[str] = RFC.TEST_USER_DN
    TEST_GROUP_CN: ClassVar[str] = RFC.TEST_GROUP_CN
    TEST_GROUP_DN: ClassVar[str] = RFC.TEST_GROUP_DN

    class ServerTypes:
        """Server type constants for LDAP server variants."""

        RFC = "rfc"
        GENERIC = "generic"
        OID = "oid"
        OUD = "oud"
        OPENLDAP2 = "openldap2"

        # Valid server types for testing (only those registered in quirks)
        VALID = (RFC, GENERIC)

    class Connection:
        """LDAP connection-related constants."""

        DEFAULT_HOST = RFC.DEFAULT_HOST
        DEFAULT_PORT = RFC.DEFAULT_PORT
        DEFAULT_BIND_DN = RFC.DEFAULT_BIND_DN
        DEFAULT_BIND_PASSWORD = RFC.DEFAULT_BIND_PASSWORD

        # SSL/TLS configurations
        SSL_ENABLED = True
        SSL_DISABLED = False
        TLS_ENABLED = True
        TLS_DISABLED = False

        # Connection timeouts
        FAST_TIMEOUT = 5
        NORMAL_TIMEOUT = 30
        SLOW_TIMEOUT = 300

    class Directory:
        """Directory structure and DN constants."""

        BASE_DN = RFC.DEFAULT_BASE_DN
        FILTER_ALL = RFC.DEFAULT_FILTER
        SCOPE_SUBTREE = RFC.DEFAULT_SCOPE
        SCOPE_ONELEVEL = "ONELEVEL"
        SCOPE_BASE = "BASE"

        class OrganizationalUnits:
            """Organizational unit constants."""

            PEOPLE = RFC.OU_PEOPLE
            GROUPS = RFC.OU_GROUPS
            SYSTEM = RFC.OU_SYSTEM

            PEOPLE_DN = RFC.OU_PEOPLE_DN
            GROUPS_DN = RFC.OU_GROUPS_DN
            SYSTEM_DN = RFC.OU_SYSTEM_DN

        class TestEntries:
            """Test entry constants."""

            USER_CN = RFC.TEST_USER_CN
            USER_DN = RFC.TEST_USER_DN
            GROUP_CN = RFC.TEST_GROUP_CN
            GROUP_DN = RFC.TEST_GROUP_DN

    class Attributes:
        """LDAP attribute constants."""

        COMMON: ClassVar[list[str]] = (
            list(RFC.DEFAULT_ATTRIBUTES) if RFC.DEFAULT_ATTRIBUTES else []
        )
        USER_ATTRIBUTES: ClassVar[list[str]] = [
            "cn",
            "sn",
            "givenName",
            "uid",
            "mail",
            "userPassword",
        ]
        GROUP_ATTRIBUTES: ClassVar[list[str]] = ["cn", "member", "description"]
        SYSTEM_ATTRIBUTES: ClassVar[list[str]] = ["cn", "description", "objectClass"]

    class Operations:
        """LDAP operation constants."""

        ADD = "add"
        MODIFY = "modify"
        DELETE = "delete"
        SEARCH = "search"
        BIND = "bind"
        UNBIND = "unbind"

        # Operation result codes
        SUCCESS = 0
        FAILURE = 1
        PARTIAL_SUCCESS = 2


__all__ = ["OID", "OUD", "RFC", "General", "OpenLDAP2", "TestConstants"]
