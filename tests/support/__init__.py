"""Test support utilities for FLEXT LDAP testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from . import fixtures, helpers, shared_ldap_fixtures, test_data

ldap_connection = fixtures.ldap_connection
real_ldap_server = fixtures.real_ldap_server
test_group_data = fixtures.test_group_data
test_user_data = fixtures.test_user_data

cleanup_test_entries = helpers.cleanup_test_entries
create_test_group = helpers.create_test_group
create_test_user = helpers.create_test_user

check_docker_available = shared_ldap_fixtures.check_docker_available
skip_if_no_docker = shared_ldap_fixtures.skip_if_no_docker

SAMPLE_ACL_DATA = test_data.SAMPLE_ACL_DATA
SAMPLE_GROUP_ENTRY = test_data.SAMPLE_GROUP_ENTRY
SAMPLE_USER_ENTRY = test_data.SAMPLE_USER_ENTRY
TEST_GROUPS = test_data.TEST_GROUPS
TEST_USERS = test_data.TEST_USERS

__all__ = [
    "SAMPLE_ACL_DATA",
    "SAMPLE_GROUP_ENTRY",
    "SAMPLE_USER_ENTRY",
    "TEST_GROUPS",
    "TEST_USERS",
    "check_docker_available",
    "cleanup_test_entries",
    "create_test_group",
    "create_test_user",
    "ldap_connection",
    "real_ldap_server",
    "skip_if_no_docker",
    "test_group_data",
    "test_user_data",
]
