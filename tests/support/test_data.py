"""Test data for LDAP testing."""

from typing import Any

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
TEST_USERS: list[dict[str, object]] = [
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

TEST_GROUPS: list[dict[str, object]] = [
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
TEST_OUS: list[dict[str, object]] = [
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
INVALID_ENTRIES: list[dict[str, object]] = [
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
TEST_FILTERS: dict[str, str] = {
    "all_users": "(objectClass=person)",
    "all_groups": "(objectClass=groupOfNames)",
    "specific_user": "(uid=testuser)",
    "email_filter": "(mail=*@internal.invalid)",
    "complex_filter": "(&(objectClass=person)(mail=*@internal.invalid))",
    "or_filter": "(|(uid=alice)(uid=bob))",
    "not_filter": "(&(objectClass=person)(!(uid=REDACTED_LDAP_BIND_PASSWORD)))",
}

# Expected search results
EXPECTED_SEARCH_RESULTS: dict[str, list[str]] = {
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
