from collections.abc import Iterable, Mapping, Sequence
from typing import Literal

ALL: Literal["ALL"]
NONE: Literal["NONE"]
ALL_ATTRIBUTES: Sequence[str]
BASE: Literal["BASE"]
LEVEL: Literal["LEVEL"]
SUBTREE: Literal["SUBTREE"]
MODIFY_REPLACE: int
SIMPLE: str

class Tls:
    def __init__(
        self,
        *,
        validate: int | None = ...,
        version: int | None = ...,
        ca_certs_file: str | None = ...,
        local_private_key_file: str | None = ...,
        local_certificate_file: str | None = ...,
    ) -> None: ...

class Server:
    def __init__(
        self,
        host: str,
        *,
        port: int | None = ...,
        use_ssl: bool | None = ...,
        get_info: object | None = ...,
        tls: Tls | None = ...,
        connect_timeout: int | None = ...,
    ) -> None: ...

class Attribute:
    values: list[str]

class Entry:
    entry_dn: str
    entry_attributes: Mapping[str, object] | list[str]

    def __getitem__(self, key: str) -> Attribute: ...

class Connection:
    bound: bool
    result: Mapping[str, object]
    entries: Sequence[Entry]
    server: Server
    last_error: str

    def __init__(
        self,
        server: Server | None = ...,
        *,
        user: str | None = ...,
        password: str | None = ...,
        auto_bind: bool | str | None = ...,
        read_only: bool | None = ...,
        client_strategy: object | None = ...,
        authentication: str | None = ...,
        check_names: bool | None = ...,
        raise_exceptions: bool | None = ...,
    ) -> None: ...
    def open(self) -> bool: ...
    def start_tls(self) -> bool: ...
    def bind(self) -> bool: ...
    def rebind(self, user: str, password: str | None = ...) -> bool: ...
    def unbind(self) -> bool: ...
    def search(
        self,
        search_base: str,
        search_filter: str,
        *,
        search_scope: str = ...,
        attributes: Iterable[str] | Literal["*", "ALL_ATTRIBUTES"] | None = ...,
        size_limit: int | None = ...,
        time_limit: int | None = ...,
    ) -> bool: ...
    def add(
        self,
        dn: str,
        *,
        attributes: Mapping[str, object] | None = ...,
    ) -> bool: ...
    def modify(
        self,
        dn: str,
        changes: Mapping[str, object],
    ) -> bool: ...
    def delete(self, dn: str) -> bool: ...

__all__ = [
    "ALL",
    "ALL_ATTRIBUTES",
    "BASE",
    "LEVEL",
    "MODIFY_REPLACE",
    "NONE",
    "SIMPLE",
    "SUBTREE",
    "Attribute",
    "Connection",
    "Entry",
    "Server",
    "Tls",
]
