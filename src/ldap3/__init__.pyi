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
        get_info=...,
        **kwargs: t.Scalar,
    ) -> None: ...

class Connection:
    result: dict[str, object]
    entries: list[object]
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
        client_strategy=...,
        **kwargs: t.Scalar,
    ) -> None: ...
    def add(
        self,
        dn: str,
        object_class: list[str] | str | None = ...,
        attributes: dict[str, object] | None = ...,
    ) -> bool: ...
    def modify(self, dn: str, changes) -> bool: ...
    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: int | str = ...,
        attributes: list[str] | str = ...,
        size_limit: int = ...,
        time_limit: int = ...,
    ) -> bool: ...
    def delete(self, dn: str) -> bool: ...
    def unbind(self) -> bool: ...
    def bind(self) -> bool: ...
    def start_tls(self) -> bool: ...
