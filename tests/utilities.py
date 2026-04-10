from __future__ import annotations

from flext_tests import FlextTestsUtilities

from flext_core import r
from flext_ldap import FlextLdapProtocols, FlextLdapUtilities
from tests import c, m, p, t


class TestsFlextLdapUtilities(FlextTestsUtilities, FlextLdapUtilities):
    """Utilities for flext-ldap tests - extends TestsFlextUtilities and FlextLdapUtilities.

    Architecture: Extends both TestsFlextUtilities and FlextLdapUtilities with flext-ldap-specific utility methods.
    All generic utilities from TestsFlextUtilities and production utilities from FlextLdapUtilities are available through inheritance.
    """

    class Ldap(FlextLdapUtilities.Ldap):
        """LDAP test utilities."""

        class Tests:
            """flext-ldap-specific test utilities namespace."""

            class SmokeFactories:
                """Factory methods for smoke test data generation."""

                @staticmethod
                def create_ldap3_server(
                    ldap_container: t.Ldap.Tests.LdapContainerDict,
                ) -> p.Ldap.Ldap3Server:
                    """Factory for ldap3 Server objects."""
                    server_url = ldap_container["server_url"]
                    if not isinstance(server_url, str):
                        server_url = str(server_url)
                    return FlextLdapUtilities.Ldap.create_server_from_url(server_url)

                @staticmethod
                def create_ldap3_connection(
                    server: p.Ldap.Ldap3Server,
                    ldap_container: t.Ldap.Tests.LdapContainerDict,
                ) -> p.Ldap.Ldap3Connection:
                    """Factory for ldap3 Connection objects."""
                    bind_dn = ldap_container["bind_dn"]
                    password = ldap_container["password"]
                    if not isinstance(bind_dn, str):
                        bind_dn = str(bind_dn)
                    if not isinstance(password, str):
                        password = str(password)
                    return FlextLdapUtilities.Ldap.create_connection(
                        server,
                        user=bind_dn,
                        password=password,
                    )

                @staticmethod
                def create_connection_config(
                    ldap_container: t.Ldap.Tests.LdapContainerDict,
                ) -> m.Ldap.ConnectionConfig:
                    """Factory for ConnectionConfig objects."""
                    host = ldap_container["host"]
                    port = ldap_container["port"]
                    use_ssl = ldap_container["use_ssl"]
                    bind_dn = ldap_container["bind_dn"]
                    password = ldap_container["password"]
                    if not isinstance(host, str):
                        host = str(host)
                    if not isinstance(port, int):
                        port = (
                            int(port)
                            if isinstance(port, (str, float))
                            else c.Ldap.ConnectionDefaults.PORT
                        )
                    if not isinstance(use_ssl, bool):
                        use_ssl = bool(use_ssl)
                    if not isinstance(bind_dn, str):
                        bind_dn = str(bind_dn)
                    if not isinstance(password, str):
                        password = str(password)
                    return m.Ldap.ConnectionConfig(
                        host=host,
                        port=port,
                        use_ssl=use_ssl,
                        bind_dn=bind_dn,
                        bind_password=password,
                    )

            class SmokeAssertions:
                """Assertion helpers for smoke tests."""

                @staticmethod
                def assert_connection_bound(connection: p.Ldap.Ldap3Connection) -> None:
                    """Assert that LDAP connection is bound."""
                    bound = getattr(connection, "bound", False)
                    assert bound, "LDAP server not responding to bind"

                @staticmethod
                def assert_server_info_available(
                    connection: p.Ldap.Ldap3Connection,
                ) -> None:
                    """Assert that LDAP server info is available."""
                    server = getattr(connection, "server", None)
                    assert server is not None, "LDAP connection has no server"
                    info = getattr(server, "info", None)
                    assert info is not None, "LDAP server info not available"
                    naming_contexts = getattr(info, "naming_contexts", None)
                    assert naming_contexts is not None, (
                        "LDAP naming contexts not available"
                    )

                @staticmethod
                def assert_api_instantiated(api: p.Ldap.LdapClient | None) -> None:
                    """Assert that ldap API is instantiated."""
                    assert api is not None, "ldap API instantiation failed"

                @staticmethod
                def assert_models_accessible() -> None:
                    """Assert that m (FlextLdapModels) class is accessible."""
                    assert m is not None, "m (FlextLdapModels) not accessible"

                @staticmethod
                def assert_connection_success(result: r[bool]) -> None:
                    """Assert that connection operation succeeded."""
                    assert result.is_success, f"Connection failed: {result.error}"

            @staticmethod
            def single_phase_cb(
                _a: int,
                _b: int,
                _c: str,
                _d: FlextLdapProtocols.Ldap.LdapBatchStats,
            ) -> None:
                """Test callback with 4 parameters (single-phase)."""

            @staticmethod
            def multi_phase_cb(
                _a: str,
                _b: int,
                _c: int,
                _d: str,
                _e: FlextLdapProtocols.Ldap.LdapBatchStats,
            ) -> None:
                """Test callback with 5 parameters (multi-phase)."""


u = TestsFlextLdapUtilities

__all__ = ["TestsFlextLdapUtilities", "u"]
