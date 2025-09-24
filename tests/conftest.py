"""Test configuration for flext-ldap.

This module imports all test fixtures and provides global test configuration.
"""

# Import shared LDAP fixtures from docker directory
import sys
from pathlib import Path
from typing import Any

# Add docker directory to path to import shared fixtures
docker_path = Path(__file__).parent.parent.parent / "docker"
sys.path.insert(0, str(docker_path))

try:
    from shared_ldap_fixtures import (
        shared_ldap_config,
        shared_ldap_container,
        shared_ldap_container_manager,
        shared_ldif_data,
        skip_if_no_docker,
    )
except ImportError:
    # Fallback if shared fixtures are not available
    shared_ldap_config: Any = None
    shared_ldap_container: Any = None
    shared_ldap_container_manager: Any = None
    shared_ldif_data: Any = None
    skip_if_no_docker: Any = None

from .support.fixtures import (  # noqa: E402
    clean_ldap_container,
    clean_ldap_state,
    custom_event_loop,
    flext_ldap_api,
    flext_ldap_config,
    flext_ldap_validations,
    ldap_api,
    ldap_connection,
    multiple_test_groups,
    multiple_test_users,
    real_ldap_server,
    sample_connection_config,
    sample_valid_dn,
    sample_valid_email,
    sample_valid_filter,
    shared_ldap_client,
    shared_ldap_connection_config,
    test_group_data,
    test_ldap_config,
    test_user_data,
)

__all__ = [
    "clean_ldap_container",
    "clean_ldap_state",
    "custom_event_loop",
    "flext_ldap_api",
    "flext_ldap_config",
    "flext_ldap_validations",
    "ldap_api",
    "ldap_connection",
    "multiple_test_groups",
    "multiple_test_users",
    "real_ldap_server",
    "sample_connection_config",
    "sample_valid_dn",
    "sample_valid_email",
    "sample_valid_filter",
    "shared_ldap_client",
    "shared_ldap_config",
    "shared_ldap_connection_config",
    "shared_ldap_container",
    "shared_ldap_container_manager",
    "shared_ldif_data",
    "skip_if_no_docker",
    "test_group_data",
    "test_ldap_config",
    "test_user_data",
]
