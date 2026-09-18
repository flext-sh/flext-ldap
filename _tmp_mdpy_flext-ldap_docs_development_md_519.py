# from flext-ldap_docs/development.md:519
from __future__ import annotations

# tests/conftest.py
import pytest
from flext_tests import tk
from flext_cli import u
from flext_core import FlextSettings
from Flext_ldap import FlextLdapSettings, set_flext_ldap.settings

@pytest.fixture(scope="session")
def ldap_server():
    """Docker LDAP server for integration tests using tk."""
    docker_manager = tk()

    # Start LDAP container using tk
    container_result = docker_manager.run_container(
        image="osixia/openldap:1.5.0",
        name="flext-ldap-test-server",
        ports={"389/tcp": 3390},
        environment={
            "LDAP_ORGANISATION": "FLEXT Test",
            "LDAP_DOMAIN": "internal.invalid",
            "LDAP_ADMIN_PASSWORD": "REDACTED_LDAP_BIND_PASSWORD123",
        },
        detach=True,
        remove=True,
    )

    if container_result.failure:
        pytest.skip(f"Failed to start LDAP container: {container_result.error}")

    container_id = container_result.unwrap()

    # Wait for server to be ready using tk health check
    health_result = docker_manager.wait_for_container_health(
        container_name="flext-ldap-test-server",
        health_command="ldapsearch -x -H ldap://localhost:389 -b '' -s base",
        timeout=30
    )

    if health_result.failure:
        pytest.skip(f"LDAP server not ready: {health_result.error}")

    # Configure flext-ldap for testing
    test_config = FlextLdapSettings(
        host="localhost",
        port=3390,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        base_dn="dc=flext,dc=local"
    )
    set_flext_ldap.settings(test_config)

    yield container_id

    # Cleanup using tk
    docker_manager.stop_container("flext-ldap-test-server", remove=True)

@pytest.fixture
def authenticated_user():
    """Fixture for authenticated user tests."""
    api = ldap

    # Create test user
    create_request = FlextLdapEntities.CreateUserRequest(
        dn="cn=auth.test,ou=users,dc=flext,dc=local",
        uid="auth.test",
        cn="Auth Test",
        sn="Test",
        password="auth123"
    )

    create_result = api.create_user(create_request)
    assert create_result.success

    yield create_result.unwrap()

    # Cleanup user
    api.delete_user("cn=auth.test,ou=users,dc=flext,dc=local")```
______________________________________________________________________

## Documentation Standards

### Code Documentation

