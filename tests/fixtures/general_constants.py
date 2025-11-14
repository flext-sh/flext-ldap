"""General test constants module.

Flat class containing general test constants used across all server types.
Constants are defined at module level without type checking.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


class General:
    """Flat namespace for general test constants - no type checking."""

    # Common OIDs
    OID_CN = "2.5.4.3"
    OID_SN = "2.5.4.4"
    OID_OBJECTCLASS = "2.5.4.0"
    OID_PERSON = "2.5.6.6"

    # Common names
    NAME_CN = "cn"
    NAME_SN = "sn"
    NAME_OBJECTCLASS = "objectClass"
    NAME_PERSON = "person"

    # Common DNs
    DN_TEST = "cn=test,dc=example,dc=com"
    DN_EXAMPLE = "dc=example,dc=com"
    DN_SCHEMA = "cn=schema"

    # Common syntax OIDs
    SYNTAX_DIRECTORY_STRING = "1.3.6.1.4.1.1466.115.115.121.1.15"
    SYNTAX_BOOLEAN = "1.3.6.1.4.1.1466.115.121.1.7"
    SYNTAX_INTEGER = "1.3.6.1.4.1.1466.115.121.1.27"

    # Test values
    VALUE_TEST = "test"
    VALUE_USER = "user"
    VALUE_USER1 = "user1"
    VALUE_USER2 = "user2"

    # Error messages
    ERROR_MISSING_OID = "Missing OID"
    ERROR_INVALID_FORMAT = "Invalid format"
    ERROR_PARSE_FAILED = "Parse failed"
