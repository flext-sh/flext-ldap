from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from _typeshed import Incomplete
from flext_core import FlextResult
from pydantic import BaseModel

from flext_ldap.config import (
    FlextLdapConnectionConfig as FlextLdapConnectionConfig,
    FlextLdapSettings as FlextLdapSettings,
)
from flext_ldap.constants import FlextLdapDefaultValues as FlextLdapDefaultValues
from flext_ldap.exceptions import FlextLdapConnectionError as FlextLdapConnectionError
from flext_ldap.infrastructure import FlextLdapClient as FlextLdapClient
from flext_ldap.models import (
    FlextLdapCreateUserRequest as FlextLdapCreateUserRequest,
    FlextLdapEntry as FlextLdapEntry,
    FlextLdapGroup as FlextLdapGroup,
    FlextLdapUser as FlextLdapUser,
)
from flext_ldap.utils import (
    FlextLdapValidationHelpers as FlextLdapValidationHelpers,
    flext_ldap_validate_dn as flext_ldap_validate_dn,
)

logger: Incomplete

class FlextLdapSearchParams(BaseModel):
    session_id: str | None
    base_dn: str
    search_filter: str
    attributes: list[str] | None
    scope: str
    size_limit: int
    time_limit: int
    @classmethod
    def validate_filter(cls, v: str) -> str: ...

class FlextLdapExportParams(BaseModel):
    session_id: str
    output_file: str
    base_dn: str
    search_filter: str
    include_operational: bool
    encoding: str
    @classmethod
    def validate_output_file(cls, v: str) -> str: ...

class SearchParameters(BaseModel):
    base_dn: str
    search_filter: str
    scope: str
    attributes: list[str] | None
    size_limit: int
    time_limit: int
    @classmethod
    def validate_filter(cls, v: str) -> str: ...

class ConnectionParameters(BaseModel):
    server_uri: str
    bind_dn: str | None
    bind_password: str | None
    timeout: int
    @classmethod
    def validate_uri(cls, v: str) -> str: ...

class GroupCreationParameters(BaseModel):
    dn: str
    cn: str
    description: str | None
    members: list[str]
    @classmethod
    def validate_dn(cls, v: str) -> str: ...
    @classmethod
    def validate_cn(cls, v: str) -> str: ...

class ExportParameters(BaseModel):
    output_file: Path
    base_dn: str
    search_filter: str
    include_operational: bool
    @classmethod
    def validate_base_dn(cls, v: str) -> str: ...

class SearchServiceInterface:
    async def perform_search(
        self, session_id: str, params: SearchParameters
    ) -> FlextResult[list[FlextLdapEntry]]: ...

class ConnectionServiceInterface:
    async def establish_connection(
        self, params: ConnectionParameters
    ) -> FlextResult[str]: ...
    async def terminate_connection(self, session_id: str) -> FlextResult[bool]: ...

class EntryServiceInterface:
    async def create_user_entry(
        self, request: FlextLdapCreateUserRequest
    ) -> FlextResult[FlextLdapUser]: ...
    async def create_group_entry(
        self, params: GroupCreationParameters
    ) -> FlextResult[FlextLdapGroup]: ...

class ExportServiceInterface:
    async def export_to_ldif(self, params: ExportParameters) -> FlextResult[str]: ...

class FlextLdapSearchService(SearchServiceInterface):
    def __init__(self, client: FlextLdapClient) -> None: ...
    async def perform_search(
        self, session_id: str, params: SearchParameters
    ) -> FlextResult[list[FlextLdapEntry]]: ...

class FlextLdapConnectionService(ConnectionServiceInterface):
    def __init__(self, client: FlextLdapClient) -> None: ...
    async def establish_connection(
        self, params: ConnectionParameters
    ) -> FlextResult[str]: ...
    async def terminate_connection(self, session_id: str) -> FlextResult[bool]: ...

class FlextLdapEntryService(EntryServiceInterface):
    def __init__(self, client: FlextLdapClient) -> None: ...
    async def create_user_entry(
        self, request: FlextLdapCreateUserRequest
    ) -> FlextResult[FlextLdapUser]: ...
    async def create_group_entry(
        self, params: GroupCreationParameters
    ) -> FlextResult[FlextLdapGroup]: ...

class FlextLdapExportService(ExportServiceInterface):
    def __init__(self, client: FlextLdapClient) -> None: ...
    async def export_to_ldif(self, params: ExportParameters) -> FlextResult[str]: ...

class FlextLdapApi:
    def __init__(self, config: FlextLdapSettings | None = None) -> None: ...
    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
        *,
        connection_timeout: int = 30,
    ) -> FlextResult[str]: ...
    async def disconnect(self, session_id: str) -> FlextResult[bool]: ...
    @asynccontextmanager
    async def connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> AsyncIterator[str]: ...
    async def search(
        self,
        params: SearchParameters | None = None,
        *,
        session_id: str | None = None,
        base_dn: str = "",
        search_filter: str = "(objectClass=*)",
        attributes: list[str] | None = None,
        **options: object,
    ) -> FlextResult[list[FlextLdapEntry]]: ...
    async def create_user(
        self, user_request: FlextLdapCreateUserRequest
    ) -> FlextResult[FlextLdapUser]: ...
    async def create_group(
        self,
        session_id: str,
        dn: str,
        cn: str,
        description: str | None = None,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLdapGroup]: ...
    async def create_entry(
        self, dn: str, attributes: dict[str, list[str]]
    ) -> FlextResult[FlextLdapEntry]: ...
    async def delete_entry(self, dn: str) -> FlextResult[None]: ...
    async def export_search_to_ldif(
        self,
        params: FlextLdapExportParams | None = None,
        *,
        session_id: str | None = None,
        output_file: str | Path | None = None,
        base_dn: str | None = None,
        search_filter: str = "(objectClass=*)",
        include_operational: bool = False,
    ) -> FlextResult[str]: ...
    async def import_ldif_file(
        self, session_id: str, ldif_file_path: str
    ) -> FlextResult[int]: ...
    async def modify_entry(
        self, session_id: str, dn: str, modifications: dict[str, list[str] | str]
    ) -> FlextResult[bool]: ...

def get_ldap_api(config: FlextLdapSettings | None = None) -> FlextLdapApi: ...
def create_ldap_api(
    server_uri: str, *, use_ssl: bool = False, timeout: int = 30
) -> FlextLdapApi: ...
