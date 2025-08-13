# Constants
ALL: int
SUBTREE: int
LEVEL: int
BASE: int
SUBORDINATES: int
MOCK_SYNC: str
SIMPLE: str

# Modification operations
MODIFY_ADD: int
MODIFY_DELETE: int
MODIFY_REPLACE: int

# Exceptions
class LdapError(Exception): ...

# Classes
class Server:
    def __init__(
        self,
        host: str,
        port: int | None = None,
        use_ssl: bool = False,
        get_info: int | None = None,
        connect_timeout: int | None = None,
    ) -> None: ...

class Connection:
    server: Server
    user: str | None
    bound: bool
    entries: list[Entry]

    def __init__(
        self,
        server: Server,
        user: str | None = None,
        password: str | None = None,
        auto_bind: bool = False,
        authentication: str | None = None,
        client_strategy: str | None = None,
        raise_exceptions: bool = False,
    ) -> None: ...
    def bind(self) -> bool: ...
    def unbind(self) -> bool: ...
    def search(
        self,
        search_base: str,
        search_filter: str,
        search_scope: int | str = ...,
        attributes: list[str] | None = None,
        size_limit: int = 0,
        time_limit: int = 0,
    ) -> bool: ...
    def add(
        self,
        dn: str,
        object_class: str | list[str] | None = None,
        attributes: dict[str, object] | None = None,
    ) -> bool: ...
    def modify(
        self,
        dn: str,
        changes: dict[str, list[tuple[int, list[str] | str]]],
    ) -> bool: ...
    def delete(self, dn: str) -> bool: ...

class Entry:
    entry_dn: str
    entry_attributes_as_dict: dict[str, list[str]]
    entry_attributes: list[str]

    def __getitem__(self, key: str) -> Attribute: ...

class Attribute:
    values: list[str]

    def __init__(self, key: str, values: list[str]) -> None: ...
