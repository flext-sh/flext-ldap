"""Test data for LDAP testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from flext_core import FlextCore

# Sample LDAP entries for testing
SAMPLE_USER_ENTRY: dict[str, object] = {
    "dn": "cn=testuser,ou=people,dc=flext,dc=local",
    "attributes": {
        "cn": ["testuser"],
        "sn": ["User"],
        "givenName": ["Test"],
        "uid": ["testuser"],
        "mail": ["testuser@internal.invalid"],
        "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
        "userPassword": ["test123"],
    },
}

SAMPLE_GROUP_ENTRY: dict[str, object] = {
    "dn": "cn=testgroup,ou=groups,dc=flext,dc=local",
    "attributes": {
        "cn": ["testgroup"],
        "description": ["Test Group"],
        "objectClass": ["groupOfNames", "top"],
        "member": ["cn=testuser,ou=people,dc=flext,dc=local"],
    },
}

# Multiple test users for comprehensive testing
TEST_USERS: list[FlextCore.Types.Dict] = [
    {
        "dn": "cn=alice,ou=people,dc=flext,dc=local",
        "attributes": {
            "cn": ["alice"],
            "sn": ["Smith"],
            "givenName": ["Alice"],
            "uid": ["alice"],
            "mail": ["alice@internal.invalid"],
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "userPassword": ["alice123"],
        },
    },
    {
        "dn": "cn=bob,ou=people,dc=flext,dc=local",
        "attributes": {
            "cn": ["bob"],
            "sn": ["Jones"],
            "givenName": ["Bob"],
            "uid": ["bob"],
            "mail": ["bob@internal.invalid"],
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "userPassword": ["bob123"],
        },
    },
    {
        "dn": "cn=charlie,ou=people,dc=flext,dc=local",
        "attributes": {
            "cn": ["charlie"],
            "sn": ["Brown"],
            "givenName": ["Charlie"],
            "uid": ["charlie"],
            "mail": ["charlie@internal.invalid"],
            "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
            "userPassword": ["charlie123"],
        },
    },
]

TEST_GROUPS: list[FlextCore.Types.Dict] = [
    {
        "dn": "cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=flext,dc=local",
        "attributes": {
            "cn": ["REDACTED_LDAP_BIND_PASSWORDs"],
            "description": ["Administrators Group"],
            "objectClass": ["groupOfNames", "top"],
            "member": ["cn=alice,ou=people,dc=flext,dc=local"],
        },
    },
    {
        "dn": "cn=users,ou=groups,dc=flext,dc=local",
        "attributes": {
            "cn": ["users"],
            "description": ["Regular Users Group"],
            "objectClass": ["groupOfNames", "top"],
            "member": [
                "cn=bob,ou=people,dc=flext,dc=local",
                "cn=charlie,ou=people,dc=flext,dc=local",
            ],
        },
    },
]

# Test organizational units
TEST_OUS: list[FlextCore.Types.Dict] = [
    {
        "dn": "ou=people,dc=flext,dc=local",
        "attributes": {
            "ou": ["people"],
            "objectClass": ["organizationalUnit", "top"],
            "description": ["People organizational unit"],
        },
    },
    {
        "dn": "ou=groups,dc=flext,dc=local",
        "attributes": {
            "ou": ["groups"],
            "objectClass": ["organizationalUnit", "top"],
            "description": ["Groups organizational unit"],
        },
    },
]

# Invalid test data for error handling tests
INVALID_ENTRIES: list[FlextCore.Types.Dict] = [
    {
        "dn": "",  # Empty DN
        "attributes": {"cn": ["invalid"]},
    },
    {
        "dn": "invalid-dn",  # Malformed DN
        "attributes": {"cn": ["invalid"]},
    },
    {
        "dn": "cn=test,dc=invalid,dc=com",
        "attributes": {},  # Empty attributes
    },
]

# Search filter test data
TEST_FILTERS: FlextCore.Types.StringDict = {
    "all_users": "(objectClass=person)",
    "all_groups": "(objectClass=groupOfNames)",
    "specific_user": "(uid=testuser)",
    "email_filter": "(mail=*@internal.invalid)",
    "complex_filter": "(&(objectClass=person)(mail=*@internal.invalid))",
    "or_filter": "(|(uid=alice)(uid=bob))",
    "not_filter": "(&(objectClass=person)(!(uid=REDACTED_LDAP_BIND_PASSWORD)))",
}

# Expected search results
EXPECTED_SEARCH_RESULTS: dict[str, FlextCore.Types.StringList] = {
    "all_users": [
        "cn=alice,ou=people,dc=flext,dc=local",
        "cn=bob,ou=people,dc=flext,dc=local",
        "cn=charlie,ou=people,dc=flext,dc=local",
    ],
    "all_groups": [
        "cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=flext,dc=local",
        "cn=users,ou=groups,dc=flext,dc=local",
    ],
}

# ACL test data
SAMPLE_ACL_DATA: dict[str, object] = {
    "unified_acl": {
        "target": "dc=example,dc=com",
        "permissions": [
            {
                "subject": "uid=REDACTED_LDAP_BIND_PASSWORD,ou=people,dc=example,dc=com",
                "subject_type": "user",
                "permissions": ["read", "write", "delete"],
                "scope": "subtree",
            },
            {
                "subject": "cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com",
                "subject_type": "group",
                "permissions": ["read", "write"],
                "scope": "subtree",
            },
        ],
    },
    "openldap_aci": 'target="ldap:///dc=example,dc=com" version 3.0; acl "REDACTED_LDAP_BIND_PASSWORD access"; allow (read,write,delete) userdn="ldap:///uid=REDACTED_LDAP_BIND_PASSWORD,ou=people,dc=example,dc=com";',
    "oracle_aci": 'target="dc=example,dc=com" version 3.0; acl "REDACTED_LDAP_BIND_PASSWORD access"; allow (read,write,delete) userdn="uid=REDACTED_LDAP_BIND_PASSWORD,ou=people,dc=example,dc=com";',
    "invalid_acl": "invalid acl format",
    "empty_acl": "",
}

# ACL test cases for comprehensive testing
ACL_TEST_CASES: list[FlextCore.Types.Dict] = [
    {
        "name": "user_read_access",
        "unified": {
            "target": "ou=people,dc=example,dc=com",
            "permissions": [
                {
                    "subject": "uid=user1,ou=people,dc=example,dc=com",
                    "subject_type": "user",
                    "permissions": ["read"],
                    "scope": "subtree",
                }
            ],
        },
        "expected_openldap": 'target="ldap:///ou=people,dc=example,dc=com" version 3.0; acl "user read access"; allow (read) userdn="ldap:///uid=user1,ou=people,dc=example,dc=com";',
        "expected_oracle": 'target="ou=people,dc=example,dc=com" version 3.0; acl "user read access"; allow (read) userdn="uid=user1,ou=people,dc=example,dc=com";',
    },
    {
        "name": "group_write_access",
        "unified": {
            "target": "ou=groups,dc=example,dc=com",
            "permissions": [
                {
                    "subject": "cn=editors,ou=groups,dc=example,dc=com",
                    "subject_type": "group",
                    "permissions": ["read", "write"],
                    "scope": "subtree",
                }
            ],
        },
        "expected_openldap": 'target="ldap:///ou=groups,dc=example,dc=com" version 3.0; acl "group write access"; allow (read,write) groupdn="ldap:///cn=editors,ou=groups,dc=example,dc=com";',
        "expected_oracle": 'target="ou=groups,dc=example,dc=com" version 3.0; acl "group write access"; allow (read,write) groupdn="cn=editors,ou=groups,dc=example,dc=com";',
    },
    {
        "name": "anonymous_access",
        "unified": {
            "target": "dc=example,dc=com",
            "permissions": [
                {
                    "subject": "anonymous",
                    "subject_type": "anonymous",
                    "permissions": ["read"],
                    "scope": "subtree",
                }
            ],
        },
        "expected_openldap": 'target="ldap:///dc=example,dc=com" version 3.0; acl "anonymous access"; allow (read) userdn="ldap:///anonymous";',
        "expected_oracle": 'target="dc=example,dc=com" version 3.0; acl "anonymous access"; allow (read) userdn="anonymous";',
    },
]

# Invalid ACL test cases
INVALID_ACL_CASES: list[FlextCore.Types.Dict] = [
    {
        "name": "missing_target",
        "unified": {
            "permissions": [
                {
                    "subject": "uid=user1,ou=people,dc=example,dc=com",
                    "subject_type": "user",
                    "permissions": ["read"],
                    "scope": "subtree",
                }
            ]
        },
    },
    {
        "name": "missing_permissions",
        "unified": {"target": "dc=example,dc=com", "permissions": []},
    },
    {
        "name": "invalid_subject_type",
        "unified": {
            "target": "dc=example,dc=com",
            "permissions": [
                {
                    "subject": "uid=user1,ou=people,dc=example,dc=com",
                    "subject_type": "invalid_type",
                    "permissions": ["read"],
                    "scope": "subtree",
                }
            ],
        },
    },
    {
        "name": "invalid_permissions",
        "unified": {
            "target": "dc=example,dc=com",
            "permissions": [
                {
                    "subject": "uid=user1,ou=people,dc=example,dc=com",
                    "subject_type": "user",
                    "permissions": ["invalid_permission"],
                    "scope": "subtree",
                }
            ],
        },
    },
]
