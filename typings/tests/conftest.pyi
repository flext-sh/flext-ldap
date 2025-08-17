from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager

import pytest
from _typeshed import Incomplete
from docker.models.containers import Container

from flext_ldap import FlextLdapClient

docker: object | None
OPENLDAP_IMAGE: str
OPENLDAP_CONTAINER_NAME: str
OPENLDAP_PORT: int
OPENLDAP_ADMIN_PASSWORD: str
OPENLDAP_DOMAIN: str
OPENLDAP_BASE_DN: Incomplete
OPENLDAP_ADMIN_DN: Incomplete
TEST_ENV_VARS: Incomplete

class OpenLDAPContainerManager:
    client: Incomplete
    container: object | None
    def __init__(self) -> None: ...
    def start_container(self) -> object: ...
    def stop_container(self) -> None: ...
    def is_container_running(self) -> bool: ...
    def get_logs(self) -> str: ...

def docker_openldap_container() -> Generator[Container]: ...
@pytest.fixture
def ldap_test_config(docker_openldap_container: Container) -> dict[str, object]: ...
@pytest.fixture
async def clean_ldap_container(
    ldap_test_config: dict[str, object],
) -> dict[str, object]: ...
@asynccontextmanager
async def temporary_ldap_entry(
    client: FlextLdapClient,
    connection_id: str,
    dn: str,
    attributes: dict[str, list[str]],
) -> AsyncGenerator[str]: ...
def pytest_configure(config: pytest.Config) -> None: ...
def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None: ...
