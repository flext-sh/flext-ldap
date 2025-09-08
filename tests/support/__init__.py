"""Test support utilities for FLEXT LDAP testing.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from .fixtures import (
    real_ldap_server,
    ldap_connection,
    test_user_data,
    test_group_data,
    multiple_test_users,
    multiple_test_groups,
    test_ldap_config,
    event_loop,
    ldap_api,
    clean_ldap_state,
)
from .helpers import (
    create_test_user,
    create_test_group,
    cleanup_test_entries,
    verify_entry_exists,
    search_entries,
)
from .ldap_server import (
    LdapTestServer,
    get_test_ldap_config,
    wait_for_ldap_server,
)
from .test_data import (
    SAMPLE_USER_ENTRY,
    SAMPLE_GROUP_ENTRY,
    TEST_USERS,
    TEST_GROUPS,
    TEST_OUS,
    INVALID_ENTRIES,
    TEST_FILTERS,
    EXPECTED_SEARCH_RESULTS,
)

__all__ = [
    # Fixtures
    "real_ldap_server",
    "ldap_connection",
    "test_user_data",
    "test_group_data",
    # Helpers
    "create_test_user",
    "create_test_group",
    "cleanup_test_entries",
    "verify_entry_exists",
    "wait_for_ldap_server",
    # LDAP Server
    "LdapTestServer",
    "get_test_ldap_config",
    # Test Data
    "SAMPLE_USER_ENTRY",
    "SAMPLE_GROUP_ENTRY",
    "TEST_USERS",
    "TEST_GROUPS",
]
