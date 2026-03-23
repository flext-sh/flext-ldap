from collections.abc import Mapping, Sequence

from flext_core import t

BASE: int

class LDAPError(Exception): ...

LDAPException = LDAPError

class Server:
    def __init__(
        self,
        host: str,
        port: int = ...,
        use_ssl: bool = ...,
        get_info: t.Container = ...,
        **kwargs: t.Scalar,
    ) -> None: ...

class Connection:
    result: Mapping[str, t.Container]
    entries: Sequence[t.Container]
    bound: bool

    def __init__(
        self,
        server: Server,
        user: str | None = ...,
        password: str | None = ...,
        auto_bind: bool = ...,
        auto_range: bool = ...,
        check_names: bool = ...,
        read_only: bool = ...,
        raise_exceptions: bool = ...,
        client_strategy: t.Container = ...,
        **kwargs: t.Scalar,
    ) -> None: ...
    def add(
        self,
        dn: str,
        object_class: Sequence[str] | str | None = ...,
        attributes: Mapping[str, t.Container] | None = ...,
    ) -> bool: ...
    def modify(
        self,
        dn: str,
        changes: Mapping[str, Sequence[tuple[int, Sequence[str]]]],
    ) -> bool: ...
    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: int | str = ...,
        attributes: Sequence[str] | str = ...,
        size_limit: int = ...,
        time_limit: int = ...,
    ) -> bool: ...
    def delete(self, dn: str) -> bool: ...
    def unbind(self) -> bool: ...
    def bind(self) -> bool: ...
    def start_tls(self) -> bool: ...
