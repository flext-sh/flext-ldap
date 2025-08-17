from abc import ABC, abstractmethod
from collections.abc import Callable as Callable, Coroutine

from _typeshed import Incomplete
from flext_core import FlextResult, FlextTypes as FlextTypes
from pydantic import BaseModel

from flext_ldap.constants import (
    FlextLdapConnectionConstants as FlextLdapConnectionConstants,
)
from flext_ldap.infrastructure import FlextLdapClient as FlextLdapClient
from flext_ldap.types import (
    FlextLdapDirectoryEntryProtocol as FlextLdapDirectoryEntryProtocol,
)
from flext_ldap.utils import FlextLdapValidationHelpers as FlextLdapValidationHelpers

logger: Incomplete

class DirectoryEntry(BaseModel):
    dn: str
    attributes: dict[str, list[str]]
    @classmethod
    def validate_dn(cls, v: str) -> str: ...

class ConnectionConfig(BaseModel):
    server_uri: str
    bind_dn: str | None
    bind_password: str | None
    timeout: int
    use_ssl: bool

class OperationResult(BaseModel):
    success: bool
    data: object | None
    error_message: str | None
    @classmethod
    def validate_error_message(cls, v: str | None, info: object) -> str | None: ...

class ConnectionServiceInterface(ABC):
    @abstractmethod
    async def establish_connection(
        self, config: ConnectionConfig
    ) -> OperationResult: ...
    @abstractmethod
    async def terminate_connection(self) -> OperationResult: ...
    @abstractmethod
    def is_connected(self) -> bool: ...

class SearchServiceInterface(ABC):
    @abstractmethod
    async def search_entries(
        self, base_dn: str, search_filter: str, attributes: list[str] | None = None
    ) -> OperationResult: ...

class EntryServiceInterface(ABC):
    @abstractmethod
    async def add_entry(self, entry: DirectoryEntry) -> OperationResult: ...
    @abstractmethod
    async def modify_entry(
        self, dn: str, modifications: dict[str, object]
    ) -> OperationResult: ...
    @abstractmethod
    async def delete_entry(self, dn: str) -> OperationResult: ...

class OperationExecutor:
    async def execute_operation(
        self,
        operation_type: str,
        validation_func: Callable[[], str | None],
        operation_func: Callable[[], Coroutine[object, object, OperationResult]],
    ) -> OperationResult: ...

class FlextLdapConnectionService(ConnectionServiceInterface, OperationExecutor):
    def __init__(self, ldap_client: FlextLdapClient) -> None: ...
    async def establish_connection(
        self, config: ConnectionConfig
    ) -> OperationResult: ...
    async def terminate_connection(self) -> OperationResult: ...
    def is_connected(self) -> bool: ...

class FlextLdapSearchService(SearchServiceInterface):
    def __init__(self, ldap_client: FlextLdapClient) -> None: ...
    async def search_entries(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        attributes: list[str] | None = None,
    ) -> OperationResult: ...

class FlextLdapEntryService(EntryServiceInterface, OperationExecutor):
    def __init__(self, ldap_client: FlextLdapClient) -> None: ...
    async def add_entry(self, entry: DirectoryEntry) -> OperationResult: ...
    async def modify_entry(
        self, dn: str, modifications: dict[str, object]
    ) -> OperationResult: ...
    async def delete_entry(self, dn: str) -> OperationResult: ...

class FlextLdapDirectoryEntry:
    dn: Incomplete
    attributes: dict[str, list[str]]
    def __init__(self, dn: str, attributes: FlextTypes.Core.JsonDict) -> None: ...
    def get_attribute_values(self, name: str) -> list[str]: ...

class FlextLdapDirectoryServiceInterface(ABC):
    @abstractmethod
    async def connect(
        self,
        server_url: str,
        *,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> FlextResult[bool]: ...
    @abstractmethod
    def search_users(
        self, search_filter: str, base_dn: str = "", attributes: list[str] | None = None
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]: ...

class FlextLdapDirectoryAdapterInterface(ABC):
    @abstractmethod
    def get_directory_service(self) -> FlextLdapDirectoryServiceInterface: ...

class FlextLdapDirectoryService(FlextLdapDirectoryServiceInterface):
    def __init__(self) -> None: ...
    async def connect(
        self,
        server_url: str,
        *,
        bind_dn: str | None = None,
        password: str | None = None,
    ) -> FlextResult[bool]: ...
    def search_users(
        self, search_filter: str, base_dn: str = "", attributes: list[str] | None = None
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]: ...

class FlextLdapDirectoryAdapter(FlextLdapDirectoryAdapterInterface):
    def __init__(self) -> None: ...
    def get_directory_service(self) -> FlextLdapDirectoryServiceInterface: ...

def create_directory_service() -> FlextLdapDirectoryService: ...
def create_directory_adapter() -> FlextLdapDirectoryAdapter: ...
