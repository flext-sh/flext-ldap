from __future__ import annotations

from flext_tests import FlextTestsUtilities

from flext_ldap import FlextLdapUtilities
from tests._utilities.docker_infra import _DockerInfraUtils
from tests._utilities.fixture_loaders import _FixtureLoaderUtils


class TestsFlextLdapUtilities(FlextTestsUtilities, FlextLdapUtilities):
    """Utilities for flext-ldap tests - extends u and FlextLdapUtilities.

    Architecture: Extends both u and FlextLdapUtilities with flext-ldap-specific utility methods.
    All generic utilities from u and production utilities from FlextLdapUtilities are available through inheritance.

    Rules:
    - NEVER redeclare utilities from u or FlextLdapUtilities
    - Only flext-ldap-specific utilities allowed
    - All generic utilities come from u
    - All production utilities come from FlextLdapUtilities
    """

    class Ldap(FlextLdapUtilities.Ldap):
        """LDAP test utilities."""

        class Tests(_DockerInfraUtils, _FixtureLoaderUtils):
            """flext-ldap-specific test utilities namespace.

            Composed via MRO from:
            - _DockerInfraUtils: FileLock, DNSTracker, get_docker_control,
              get_admin_credentials, ensure_basic_ldap_structure
            - _FixtureLoaderUtils: Fixtures (load_json, load_ldif, etc.)

            Access: u.Ldap.Tests.*
            """


u = TestsFlextLdapUtilities

__all__ = ["TestsFlextLdapUtilities", "u"]
