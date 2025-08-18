from typing import ParamSpec, Protocol, TypeVar

from flext_core import FlextResult

__all__ = [
    "_P",
    "_R",
    "_T",
    "AsyncCallable",
    "ConnectionConfig",
    "DirectoryAuthConfig",
    "ErrorPatternData",
    "FlextLdapConnectionProtocol",
    "FlextLdapDirectoryConnectionProtocol",
    "FlextLdapDirectoryEntryProtocol",
    "FlextLdapRepositoryProtocol",
    "FlextTypesCore",
    "JsonDict",
    "LdapAttributeDict",
    "LdapAttributeValue",
    "LdapConnectionConfig",
    "LdapSearchResult",
    "SchemaData",
    "SearchResult",
    "SecurityEventData",
    "TLdapAttributeValue",
    "TLdapAttributes",
    "TLdapConnectionId",
    "TLdapDn",
    "TLdapEntryData",
    "TLdapFilter",
    "TLdapScope",
    "TLdapSearchResult",
    "TLdapSessionId",
    "TLdapUri",
    "UserRequest",
]

type LdapAttributeValue = str | bytes | list[str] | list[bytes]
type LdapAttributeDict = dict[str, LdapAttributeValue]
type LdapSearchResult = dict[str, LdapAttributeValue]
type TLdapDn = str
type TLdapUri = str
type TLdapFilter = str
type TLdapSessionId = str
type TLdapScope = str
type TLdapConnectionId = str
type TLdapAttributeValue = LdapAttributeValue
type TLdapAttributes = LdapAttributeDict
type TLdapEntryData = LdapSearchResult
type TLdapSearchResult = list[LdapSearchResult] | list[dict[str, object]]
type LdapConnectionConfig = dict[str, object]
type SecurityEventData = dict[str, object]
type ErrorPatternData = dict[str, object]
type SchemaData = dict[str, object]
type DirectoryAuthConfig = dict[str, object]
type ConnectionConfig = dict[str, object]
type UserRequest = dict[str, object]
type SearchResult = dict[str, object]
_P = ParamSpec("_P")
_R = TypeVar("_R")
_T = TypeVar("_T")
type JsonDict = dict[str, object]
type FlextTypesCore = dict[str, object]

class AsyncCallable(Protocol):
    def __call__(self, *args: object, **kwargs: object) -> None: ...

class FlextLdapConnectionProtocol(Protocol):
    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[None]: ...
    async def disconnect(self) -> FlextResult[None]: ...
    async def search(
        self,
        base_dn: str,
        search_filter: str,
        scope: str = "subtree",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[LdapSearchResult]]: ...

class FlextLdapRepositoryProtocol(Protocol):
    async def find_by_dn(self, dn: str) -> FlextResult[LdapSearchResult | None]: ...
    async def save(self, entry_data: LdapAttributeDict) -> FlextResult[None]: ...
    async def delete(self, dn: str) -> FlextResult[None]: ...

class FlextLdapDirectoryConnectionProtocol(Protocol):
    def is_connected(self) -> bool: ...
    async def bind(self, dn: str, password: str) -> FlextResult[None]: ...

class FlextLdapDirectoryEntryProtocol(Protocol):
    @property
    def dn(self) -> str: ...
    @property
    def attributes(self) -> dict[str, list[str]]: ...
    def get_attribute_values(self, name: str) -> list[str]: ...
