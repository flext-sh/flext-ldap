from _typeshed import Incomplete
from flext_core import FlextContainer, FlextDomainService, FlextResult, FlextTypes

from flext_ldap.adapters import (
    FlextLdapDirectoryAdapterInterface as FlextLdapDirectoryAdapterInterface,
    FlextLdapDirectoryService as FlextLdapDirectoryService,
    FlextLdapDirectoryServiceInterface as FlextLdapDirectoryServiceInterface,
)
from flext_ldap.models import FlextLdapCreateUserRequest, FlextLdapUser
from flext_ldap.types import (
    FlextLdapDirectoryConnectionProtocol as FlextLdapDirectoryConnectionProtocol,
    FlextLdapDirectoryEntryProtocol as FlextLdapDirectoryEntryProtocol,
)

__all__ = [
    "DirectoryAdapterInterface",
    "DirectoryConnectionProtocol",
    "DirectoryEntryProtocol",
    "DirectoryServiceInterface",
    "FlextLdapApplicationService",
    "FlextLdapBaseService",
    "FlextLdapDirectoryAdapter",
    "FlextLdapDirectoryAdapterInterface",
    "FlextLdapDirectoryConnectionProtocol",
    "FlextLdapDirectoryEntryProtocol",
    "FlextLdapDirectoryService",
    "FlextLdapDirectoryServiceInterface",
    "FlextLdapService",
]

class FlextLdapBaseService(FlextDomainService[None]):
    def __init__(
        self, /, container: FlextContainer | None = None, **data: object
    ) -> None: ...
    def start(self) -> FlextResult[None]: ...
    def stop(self) -> FlextResult[None]: ...
    def health_check(self) -> FlextResult[FlextTypes.Core.JsonDict]: ...
    @property
    def container(self) -> FlextContainer: ...
    @property
    def is_running(self) -> bool: ...
    def execute(self) -> FlextResult[None]: ...

class DirectoryOperationResult:
    SUCCESS: bool
    FAILURE: bool

class FlextLdapApplicationService:
    def __init__(self, config: object | None = None) -> None: ...
    def is_connected(self) -> bool: ...
    async def connect(
        self, server_url: str, bind_dn: str, bind_password: str
    ) -> FlextResult[bool]: ...
    async def disconnect(self) -> FlextResult[bool]: ...
    async def create_user(
        self, request: FlextLdapCreateUserRequest
    ) -> FlextResult[FlextLdapUser]: ...
    async def find_user_by_uid(self, uid: str) -> FlextResult[object | None]: ...

FlextLdapDirectoryAdapter: Incomplete

class FlextLdapService(FlextLdapApplicationService): ...

DirectoryConnectionProtocol = FlextLdapDirectoryConnectionProtocol
DirectoryEntryProtocol = FlextLdapDirectoryEntryProtocol
DirectoryServiceInterface = FlextLdapDirectoryServiceInterface
DirectoryAdapterInterface = FlextLdapDirectoryAdapterInterface
