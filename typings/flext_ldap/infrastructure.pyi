import ssl
from abc import ABC, abstractmethod
from datetime import datetime

from _typeshed import Incomplete
from flext_core import FlextResult
from ldap3 import Connection as Ldap3Connection

from flext_ldap.types import LdapAttributeDict, LdapSearchResult

__all__ = [
    "FlextLDAPConnectionManager",
    "FlextLdapCertificateValidationService",
    "FlextLdapClient",
    "FlextLdapConnectionRepositoryImpl",
    "FlextLdapConverter",
    "FlextLdapDataType",
    "FlextLdapErrorCorrelationService",
    "FlextLdapEventObserver",
    "FlextLdapInfrastructure",
    "FlextLdapObservableClient",
    "FlextLdapPagedSearchStrategy",
    "FlextLdapPerformanceObserver",
    "FlextLdapSchemaDiscoveryService",
    "FlextLdapSearchStrategy",
    "FlextLdapSecurityEventLogger",
    "FlextLdapSecurityObserver",
    "FlextLdapStandardSearchStrategy",
    "FlextLdapStrategyContext",
    "FlextLdapUserRepositoryImpl",
]

Connection = Ldap3Connection

class ConvenienceSearchParameters:
    connection_id: Incomplete
    base_dn: Incomplete
    search_filter: Incomplete
    scope: Incomplete
    attributes: Incomplete
    size_limit: Incomplete
    time_limit: Incomplete
    def __init__(
        self,
        connection_id: str,
        base_dn: object,
        search_filter: object,
        *,
        scope: object = "subtree",
        attributes: list[str] | None = None,
        size_limit: int = 1000,
        time_limit: int = 30,
    ) -> None: ...

class FlextLdapClient:
    def __init__(self, config: object | None = None) -> None: ...
    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[None]: ...
    async def disconnect(
        self, *args: object, **kwargs: object
    ) -> FlextResult[None]: ...
    async def create_entry(
        self, connection_id: str, dn: object, attributes: dict[str, list[str]]
    ) -> FlextResult[None]: ...
    async def disconnect_convenience(self, connection_id: str) -> FlextResult[None]: ...
    def is_connected(self) -> bool: ...
    async def search_convenience(
        self,
        connection_id: str,
        base_dn: object,
        search_filter: object,
        *,
        scope: object = "subtree",
        attributes: list[str] | None = None,
        size_limit: int = 1000,
        time_limit: int = 30,
    ) -> FlextResult[list[LdapSearchResult]]: ...
    async def search(
        self, *args: object, **kwargs: object
    ) -> FlextResult[list[LdapSearchResult]]: ...
    async def add_entry(
        self, dn: str, attributes: dict[str, list[str]]
    ) -> FlextResult[None]: ...
    async def modify_entry(
        self, dn: str, modifications: dict[str, list[str]]
    ) -> FlextResult[None]: ...
    async def delete_entry(self, *args: object) -> FlextResult[None]: ...

class FlextLDAPConnectionManager:
    def __init__(self, max_connections: int = 10) -> None: ...
    async def get_connection(
        self,
        connection_id: str,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[FlextLdapClient]: ...
    async def release_connection(self, connection_id: str) -> FlextResult[None]: ...

class FlextLdapCertificateValidationService:
    def __init__(self) -> None: ...
    def validate_certificate(
        self, cert_data: bytes, hostname: str
    ) -> FlextResult[None]: ...
    def create_ssl_context(
        self, verify_mode: ssl.VerifyMode = ...
    ) -> ssl.SSLContext: ...

class FlextLdapSchemaDiscoveryService:
    def __init__(self, client: FlextLdapClient) -> None: ...
    async def discover_schema(
        self, base_dn: str = ""
    ) -> FlextResult[dict[str, object]]: ...
    def validate_entry_against_schema(
        self, object_classes: list[str], attributes: dict[str, list[str]]
    ) -> FlextResult[None]: ...

class FlextLdapSecurityEventLogger:
    def __init__(self) -> None: ...
    def log_authentication_attempt(
        self, bind_dn: str, *, success: bool, source_ip: str | None = None
    ) -> None: ...
    def log_authorization_check(
        self, user_dn: str, operation: str, resource_dn: str, *, granted: bool
    ) -> None: ...
    def log_data_access(
        self,
        user_dn: str,
        operation: str,
        target_dn: str,
        attributes: list[str] | None = None,
    ) -> None: ...
    def get_security_events(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        event_type: str | None = None,
    ) -> list[dict[str, object]]: ...

class FlextLdapErrorCorrelationService:
    def __init__(self) -> None: ...
    def correlate_error(
        self,
        error_message: str,
        operation: str,
        context: dict[str, object] | None = None,
    ) -> FlextResult[dict[str, object]]: ...

class FlextLdapConnectionRepositoryImpl:
    def __init__(self, client: FlextLdapClient) -> None: ...
    async def test_connection(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[dict[str, object]]: ...

class FlextLdapUserRepositoryImpl:
    def __init__(self, client: FlextLdapClient) -> None: ...
    async def find_user_by_uid(
        self, uid: str, base_dn: str
    ) -> FlextResult[LdapSearchResult | None]: ...
    async def save_user(self, user_data: LdapAttributeDict) -> FlextResult[None]: ...

class FlextLdapInfrastructure:
    connection_manager: Incomplete
    certificate_validator: Incomplete
    security_logger: Incomplete
    error_correlator: Incomplete
    schema_discovery: Incomplete
    connection_repository: Incomplete
    user_repository: Incomplete
    def __init__(self) -> None: ...
    async def create_authenticated_client(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[FlextLdapClient]: ...
    async def perform_health_check(self) -> FlextResult[dict[str, object]]: ...

class FlextLdapSearchStrategy(ABC):
    @abstractmethod
    async def execute_search(
        self,
        client: FlextLdapClient,
        base_dn: str,
        search_filter: str,
        **kwargs: object,
    ) -> FlextResult[list[LdapSearchResult]]: ...

class FlextLdapStandardSearchStrategy(FlextLdapSearchStrategy):
    async def execute_search(
        self,
        client: FlextLdapClient,
        base_dn: str,
        search_filter: str,
        **kwargs: object,
    ) -> FlextResult[list[LdapSearchResult]]: ...

class FlextLdapPagedSearchStrategy(FlextLdapSearchStrategy):
    page_size: Incomplete
    def __init__(self, page_size: int = 1000) -> None: ...
    async def execute_search(
        self,
        client: FlextLdapClient,
        base_dn: str,
        search_filter: str,
        **kwargs: object,
    ) -> FlextResult[list[LdapSearchResult]]: ...

class FlextLdapEventObserver(ABC):
    @abstractmethod
    async def on_connection_established(
        self, server_uri: str, bind_dn: str | None
    ) -> None: ...
    @abstractmethod
    async def on_connection_failed(self, server_uri: str, error: str) -> None: ...
    @abstractmethod
    async def on_search_performed(
        self, base_dn: str, search_filter: str, result_count: int
    ) -> None: ...
    @abstractmethod
    async def on_entry_added(
        self, dn: str, attributes: dict[str, list[str]]
    ) -> None: ...

class FlextLdapSecurityObserver(FlextLdapEventObserver):
    security_logger: Incomplete
    def __init__(self, security_logger: FlextLdapSecurityEventLogger) -> None: ...
    async def on_connection_established(
        self, server_uri: str, bind_dn: str | None
    ) -> None: ...
    async def on_connection_failed(self, server_uri: str, error: str) -> None: ...
    async def on_search_performed(
        self, base_dn: str, search_filter: str, result_count: int
    ) -> None: ...
    async def on_entry_added(
        self, dn: str, attributes: dict[str, list[str]]
    ) -> None: ...

class FlextLdapPerformanceObserver(FlextLdapEventObserver):
    def __init__(self) -> None: ...
    async def on_connection_established(
        self, server_uri: str, bind_dn: str | None
    ) -> None: ...
    async def on_connection_failed(self, server_uri: str, error: str) -> None: ...
    async def on_search_performed(
        self, base_dn: str, search_filter: str, result_count: int
    ) -> None: ...
    async def on_entry_added(
        self, dn: str, attributes: dict[str, list[str]]
    ) -> None: ...
    def get_performance_metrics(self) -> dict[str, object]: ...

class FlextLdapObservableClient(FlextLdapClient):
    def __init__(self, config: object | None = None) -> None: ...
    def add_observer(self, observer: FlextLdapEventObserver) -> None: ...
    def remove_observer(self, observer: FlextLdapEventObserver) -> None: ...
    async def connect(
        self,
        server_uri: str,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[None]: ...
    async def add_entry(
        self, dn: str, attributes: dict[str, list[str]]
    ) -> FlextResult[None]: ...

class FlextLdapStrategyContext:
    def __init__(self, strategy: FlextLdapSearchStrategy) -> None: ...
    def set_strategy(self, strategy: FlextLdapSearchStrategy) -> None: ...
    async def execute_search(
        self,
        client: FlextLdapClient,
        base_dn: str,
        search_filter: str,
        **kwargs: object,
    ) -> FlextResult[list[LdapSearchResult]]: ...

class FlextLdapDataType:
    STRING: str
    INTEGER: str
    BOOLEAN: str
    BINARY: str

class FlextLdapConverter:
    @staticmethod
    def to_string(value: object) -> str: ...
    @staticmethod
    def to_integer(value: object) -> int: ...
    @staticmethod
    def to_boolean(value: object) -> bool: ...
    def detect_type(self, value: object) -> str: ...
    def convert_to_dn(self, value: str, base_dn: str) -> str: ...
