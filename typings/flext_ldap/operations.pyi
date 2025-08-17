from _typeshed import Incomplete
from flext_core import FlextResult

from flext_ldap.models import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapUser,
)

__all__ = [
    "FlextLdapConnectionOperations",
    "FlextLdapEntryOperations",
    "FlextLdapGroupOperations",
    "FlextLdapOperations",
    "FlextLdapOperationsBase",
    "FlextLdapSearchOperations",
    "FlextLdapUserOperations",
]

class FlextLdapOperationsBase:
    def __init__(self) -> None: ...

class FlextLdapConnectionOperations(FlextLdapOperationsBase):
    def __init__(self) -> None: ...
    async def create_connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        _bind_password: str | None = None,
        timeout_seconds: int = 30,
    ) -> FlextResult[str]: ...
    async def close_connection(self, connection_id: str) -> FlextResult[None]: ...
    def get_connection_info(
        self, connection_id: str
    ) -> FlextResult[dict[str, object]]: ...
    def list_active_connections(self) -> FlextResult[list[dict[str, object]]]: ...

class FlextLdapSearchOperations(FlextLdapOperationsBase):
    async def search_entries(
        self,
        connection_id: str,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        scope: str = "subtree",
        attributes: list[str] | None = None,
        size_limit: int = 1000,
        time_limit: int = 30,
    ) -> FlextResult[list[FlextLdapEntry]]: ...
    async def search_users(
        self,
        connection_id: str,
        base_dn: str,
        filter_criteria: dict[str, str] | None = None,
        size_limit: int = 1000,
    ) -> FlextResult[list[FlextLdapUser]]: ...
    async def search_groups(
        self,
        connection_id: str,
        base_dn: str,
        filter_criteria: dict[str, str] | None = None,
        size_limit: int = 1000,
    ) -> FlextResult[list[FlextLdapGroup]]: ...
    async def get_entry_by_dn(
        self, connection_id: str, dn: str, attributes: list[str] | None = None
    ) -> FlextResult[FlextLdapEntry]: ...

class FlextLdapEntryOperations(FlextLdapOperationsBase):
    async def create_entry(
        self,
        connection_id: str,
        dn: str,
        object_classes: list[str],
        attributes: dict[str, object],
    ) -> FlextResult[FlextLdapEntry]: ...
    async def modify_entry(
        self, connection_id: str, dn: str, modifications: dict[str, object]
    ) -> FlextResult[None]: ...
    async def delete_entry(self, connection_id: str, dn: str) -> FlextResult[None]: ...

class FlextLdapUserOperations(FlextLdapOperationsBase):
    MIN_PASSWORD_LENGTH: int
    def __init__(self) -> None: ...
    async def create_user(
        self, connection_id: str, user_request: FlextLdapCreateUserRequest
    ) -> FlextResult[FlextLdapUser]: ...
    async def update_user_password(
        self, connection_id: str, user_dn: str, new_password: str
    ) -> FlextResult[None]: ...
    async def update_user_email(
        self, connection_id: str, user_dn: str, email: str
    ) -> FlextResult[None]: ...
    async def activate_user(
        self, connection_id: str, user_dn: str
    ) -> FlextResult[None]: ...
    async def deactivate_user(
        self, connection_id: str, user_dn: str
    ) -> FlextResult[None]: ...

class FlextLdapGroupOperations(FlextLdapOperationsBase):
    def __init__(self) -> None: ...
    async def create_group(
        self,
        connection_id: str,
        dn: str,
        cn: str,
        description: str | None = None,
        initial_members: list[str] | None = None,
    ) -> FlextResult[FlextLdapGroup]: ...
    async def add_group_member(
        self, connection_id: str, group_dn: str, member_dn: str
    ) -> FlextResult[None]: ...
    async def remove_group_member(
        self, connection_id: str, group_dn: str, member_dn: str
    ) -> FlextResult[None]: ...
    async def get_group_members(
        self, connection_id: str, group_dn: str
    ) -> FlextResult[list[str]]: ...
    async def update_group_description(
        self, connection_id: str, group_dn: str, description: str
    ) -> FlextResult[None]: ...

class FlextLdapOperations(FlextLdapOperationsBase):
    connections: Incomplete
    search: Incomplete
    entries: Incomplete
    users: Incomplete
    groups: Incomplete
    def __init__(self) -> None: ...
    async def create_connection_and_bind(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[str]: ...
    async def search_and_get_first(
        self,
        connection_id: str,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
    ) -> FlextResult[FlextLdapEntry | None]: ...
    async def cleanup_connection(self, connection_id: str) -> None: ...
