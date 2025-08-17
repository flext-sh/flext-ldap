import re
from datetime import datetime
from enum import Enum, StrEnum
from typing import ClassVar, Final

from _typeshed import Incomplete
from flext_core import (
    FlextEntity,
    FlextEntityId,
    FlextEntityStatus,
    FlextLDAPConfig,
    FlextLogLevel,
    FlextModel,
    FlextResult,
    FlextValue,
)
from pydantic import SecretStr, computed_field

from flext_ldap.constants import (
    FlextLdapProtocolConstants as FlextLdapProtocolConstants,
)
from flext_ldap.types import LdapAttributeDict, LdapAttributeValue, LdapSearchResult

__all__ = [
    "CreateUserRequest",
    "FlextLdapAttributesValue",
    "FlextLdapAuthConfig",
    "FlextLdapConnection",
    "FlextLdapConnectionConfig",
    "FlextLdapConstants",
    "FlextLdapCreateUserRequest",
    "FlextLdapDataType",
    "FlextLdapDefaults",
    "FlextLdapDistinguishedName",
    "FlextLdapEntityStatus",
    "FlextLdapEntry",
    "FlextLdapEntryBuilder",
    "FlextLdapEntryFactory",
    "FlextLdapExtendedEntry",
    "FlextLdapFilter",
    "FlextLdapFilterValue",
    "FlextLdapGroup",
    "FlextLdapGroupBuilder",
    "FlextLdapLoggingConfig",
    "FlextLdapObjectClass",
    "FlextLdapObjectClasses",
    "FlextLdapOperationResult",
    "FlextLdapProtocolConstants",
    "FlextLdapScope",
    "FlextLdapScope",
    "FlextLdapScopeEnum",
    "FlextLdapSearchConfig",
    "FlextLdapSearchRequest",
    "FlextLdapSearchResponse",
    "FlextLdapSettings",
    "FlextLdapUri",
    "FlextLdapUser",
    "FlextLdapUserBuilder",
    "LDAPEntry",
    "LDAPFilter",
    "LDAPGroup",
    "LDAPScope",
    "LDAPUser",
    "create_development_config",
    "create_production_config",
    "create_test_config",
]

class FlextLdapDataType(Enum):
    STRING = ...
    INTEGER = ...
    BOOLEAN = ...
    BINARY = ...
    DATETIME = ...
    DN = ...
    EMAIL = ...
    PHONE = ...
    UUID = ...
    URL = ...
    IP_ADDRESS = ...
    MAC_ADDRESS = ...
    CERTIFICATE = ...
    class PasswordDataType(StrEnum):
        PASSWORD_FIELD_TYPE = ...

    UNKNOWN: str

class FlextLdapScopeEnum(StrEnum):
    BASE = "base"
    ONE_LEVEL = "onelevel"
    SUBTREE = "subtree"
    ONE = "onelevel"
    SUB = "subtree"

FlextLdapEntityStatus = FlextEntityStatus
LDAPScope = FlextLdapScopeEnum

class LdapAttributeProcessor:
    @staticmethod
    def coerce_attribute_value(value: object) -> str | list[str]: ...
    @staticmethod
    def normalize_attributes(attrs: dict[str, object]) -> dict[str, object]: ...

class LdapDomainValidator:
    @staticmethod
    def validate_common_name(
        cn_field: str | None, attributes: dict[str, object], entity_type: str
    ) -> FlextResult[None]: ...
    @staticmethod
    def validate_required_object_classes(
        object_classes: list[str], required_classes: list[str], entity_type: str
    ) -> FlextResult[None]: ...

class FlextLdapDistinguishedName(FlextValue):
    model_config: Incomplete
    value: str
    DN_PATTERN: ClassVar[re.Pattern[str]]
    @classmethod
    def validate_dn_format(cls, v: str) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...
    @computed_field
    def parent_dn(self) -> str | None: ...
    @computed_field
    def rdn(self) -> str: ...
    def is_descendant_of(self, parent_dn: str | FlextLdapDistinguishedName) -> bool: ...
    @classmethod
    def create(cls, value: str) -> FlextResult[FlextLdapDistinguishedName]: ...

class FlextLdapScope(FlextValue):
    scope: str
    VALID_SCOPES: ClassVar[set[str]]
    @classmethod
    def validate_scope(cls, value: str) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...
    @classmethod
    def create(cls, scope: str) -> FlextResult[FlextLdapScope]: ...
    @classmethod
    def base(cls) -> FlextLdapScope: ...
    @classmethod
    def one(cls) -> FlextLdapScope: ...
    @classmethod
    def sub(cls) -> FlextLdapScope: ...

class FlextLdapFilter(FlextValue):
    model_config: Incomplete
    value: str
    FILTER_PATTERN: ClassVar[re.Pattern[str]]
    @classmethod
    def validate_filter_format(cls, v: str) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...
    @classmethod
    def create(cls, value: str) -> FlextResult[FlextLdapFilter]: ...

class FlextLdapUri(FlextValue):
    value: str
    @classmethod
    def validate_uri_format(cls, v: str) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...
    @computed_field
    def scheme(self) -> str: ...
    @computed_field
    def hostname(self) -> str | None: ...
    @computed_field
    def port(self) -> int | None: ...

class FlextLdapObjectClass(FlextValue):
    name: str
    @classmethod
    def validate_name(cls, v: str) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...

class FlextLdapAttributesValue(FlextValue):
    attributes: dict[str, object]
    def validate_business_rules(self) -> FlextResult[None]: ...
    def get_single_value(self, name: str) -> str | None: ...
    def get_values(self, name: str) -> list[str]: ...

class FlextLdapCreateUserRequest(FlextModel):
    dn: str
    uid: str
    cn: str
    sn: str
    given_name: str | None
    mail: str | None
    user_password: str | None
    object_classes: list[str]
    additional_attributes: dict[str, list[str]]
    @classmethod
    def validate_dn(cls, v: str) -> str: ...
    @classmethod
    def validate_email(cls, v: str | None) -> str | None: ...
    def to_ldap_attributes(self) -> dict[str, str | list[str]]: ...

class FlextLdapSearchRequest(FlextModel):
    base_dn: str
    scope: FlextLdapScopeEnum
    filter_str: str
    attributes: list[str] | None
    size_limit: int
    time_limit: int
    @classmethod
    def validate_base_dn(cls, v: str) -> str: ...
    @classmethod
    def validate_filter(cls, v: str) -> str: ...

class FlextLdapSearchResponse(FlextModel):
    entries: list[LdapSearchResult]
    total_count: int
    has_more: bool
    search_time_ms: float

class FlextLdapEntry(FlextEntity):
    id: FlextEntityId
    dn: str
    object_classes: list[str]
    attributes: dict[str, object]
    status: FlextEntityStatus
    @classmethod
    def validate_dn_format(cls, v: str) -> str: ...
    def validate_business_rules(self) -> FlextResult[None]: ...
    def add_object_class(self, object_class: str) -> FlextResult[None]: ...
    def get_attribute_values(self, name: str) -> list[str]: ...
    def get_single_attribute_value(self, name: str) -> str | None: ...
    def get_attribute(self, name: str) -> str | None: ...
    def has_attribute(self, name: str) -> bool: ...
    def set_attribute(self, name: str, values: list[str] | str) -> None: ...
    def add_attribute_value(self, name: str, value: str) -> None: ...
    def is_descendant_of(self, parent_dn: str) -> bool: ...
    @computed_field
    def rdn(self) -> str: ...
    @computed_field
    def parent_dn(self) -> str | None: ...

class FlextLdapUser(FlextLdapEntry):
    uid: str | None
    cn: str | None
    sn: str | None
    given_name: str | None
    mail: str | None
    object_classes: Incomplete
    def model_post_init(self, __context: object, /) -> None: ...
    def validate_business_rules(self) -> FlextResult[None]: ...
    def set_password(self, password: str) -> FlextResult[None]: ...
    def set_email(self, email: str) -> FlextResult[None]: ...
    def is_active(self) -> bool: ...
    def lock_account(self) -> FlextLdapUser: ...
    def unlock_account(self) -> FlextLdapUser: ...
    status: Incomplete
    def activate(self) -> None: ...
    def deactivate(self) -> None: ...

class FlextLdapGroup(FlextLdapEntry):
    cn: str | None
    description: str | None
    members: list[str]
    object_classes: Incomplete
    def model_post_init(self, __context: object, /) -> None: ...
    def validate_business_rules(self) -> FlextResult[None]: ...
    def add_member(self, member_dn: str) -> FlextLdapGroup: ...
    def remove_member(self, member_dn: str) -> FlextLdapGroup: ...
    def has_member(self, member_dn: str) -> bool: ...
    def get_member_count(self) -> int: ...
    def is_empty(self) -> bool: ...

class FlextLdapConnection(FlextEntity):
    server_uri: str
    bind_dn: str | None
    is_connected: bool
    connection_time: datetime | None
    last_activity: datetime | None
    def validate_business_rules(self) -> FlextResult[None]: ...
    def connect(self) -> FlextResult[None]: ...
    def disconnect(self) -> None: ...
    def update_activity(self) -> None: ...
    def get_connection_duration(self) -> float | None: ...

class FlextLdapEntryBuilder:
    def __init__(self) -> None: ...
    def dn(self, distinguished_name: str) -> FlextLdapEntryBuilder: ...
    def object_class(self, object_class: str) -> FlextLdapEntryBuilder: ...
    def object_classes(self, *object_classes: str) -> FlextLdapEntryBuilder: ...
    def attribute(self, name: str, value: str | list[str]) -> FlextLdapEntryBuilder: ...
    def multi_valued_attribute(
        self, name: str, *values: str
    ) -> FlextLdapEntryBuilder: ...
    def status(self, status: FlextEntityStatus) -> FlextLdapEntryBuilder: ...
    def build(self) -> FlextResult[FlextLdapEntry]: ...

class FlextLdapUserBuilder(FlextLdapEntryBuilder):
    def __init__(self) -> None: ...
    def uid(self, user_id: str) -> FlextLdapUserBuilder: ...
    def common_name(self, common_name: str) -> FlextLdapUserBuilder: ...
    def surname(self, surname: str) -> FlextLdapUserBuilder: ...
    def given_name(self, given_name: str) -> FlextLdapUserBuilder: ...
    def email(self, email_address: str) -> FlextLdapUserBuilder: ...
    def password(self, password: str) -> FlextLdapUserBuilder: ...
    def build_user(self) -> FlextResult[FlextLdapUser]: ...

class FlextLdapGroupBuilder(FlextLdapEntryBuilder):
    def __init__(self) -> None: ...
    def common_name(self, common_name: str) -> FlextLdapGroupBuilder: ...
    def description(self, description: str) -> FlextLdapGroupBuilder: ...
    def member(self, member_dn: str) -> FlextLdapGroupBuilder: ...
    def members(self, *member_dns: str) -> FlextLdapGroupBuilder: ...
    def build_group(self) -> FlextResult[FlextLdapGroup]: ...

class FlextLdapEntryFactory:
    @staticmethod
    def create_user_entry(
        dn: str, uid: str, common_name: str, surname: str, email: str | None = None
    ) -> FlextResult[FlextLdapUser]: ...
    @staticmethod
    def create_group_entry(
        dn: str,
        common_name: str,
        description: str | None = None,
        members: list[str] | None = None,
    ) -> FlextResult[FlextLdapGroup]: ...
    @staticmethod
    def create_organizational_unit(
        dn: str, ou_name: str, description: str | None = None
    ) -> FlextResult[FlextLdapEntry]: ...

class FlextLdapExtendedEntry(FlextLdapEntry):
    source_server: str | None
    last_modified: datetime | None
    schema_version: str | None
    extensions: LdapAttributeDict
    def add_extension(self, key: str, value: LdapAttributeValue) -> None: ...
    def get_extension(
        self, key: str, default: LdapAttributeValue | None = None
    ) -> LdapAttributeValue | None: ...
    def has_extension(self, key: str) -> bool: ...
    def update_last_modified(self) -> None: ...

LDAPEntry = FlextLdapExtendedEntry
LDAPFilter = FlextLdapFilter
FlextLdapFilterValue = FlextLdapFilter
CreateUserRequest = FlextLdapCreateUserRequest
LDAPUser = FlextLdapUser
LDAPGroup = FlextLdapGroup

class FlextLdapOperationResult(StrEnum):
    SUCCESS = "0"
    OPERATIONS_ERROR = "1"
    PROTOCOL_ERROR = "2"
    TIME_LIMIT_EXCEEDED = "3"
    SIZE_LIMIT_EXCEEDED = "4"
    COMPARE_FALSE = "5"
    COMPARE_TRUE = "6"
    AUTH_METHOD_NOT_SUPPORTED = "7"
    STRONGER_AUTH_REQUIRED = "8"
    PARTIAL_RESULTS = "9"
    REFERRAL = "10"
    ADMIN_LIMIT_EXCEEDED = "11"
    UNAVAILABLE_CRITICAL_EXTENSION = "12"
    CONFIDENTIALITY_REQUIRED = "13"
    SASL_BIND_IN_PROGRESS = "14"
    NO_SUCH_ATTRIBUTE = "16"
    UNDEFINED_ATTRIBUTE_TYPE = "17"
    INAPPROPRIATE_MATCHING = "18"
    CONSTRAINT_VIOLATION = "19"
    ATTRIBUTE_OR_VALUE_EXISTS = "20"
    INVALID_ATTRIBUTE_SYNTAX = "21"
    NO_SUCH_OBJECT = "32"
    ALIAS_PROBLEM = "33"
    INVALID_DN_SYNTAX = "34"
    IS_LEAF = "35"
    ALIAS_DEREFERENCING_PROBLEM = "36"
    INAPPROPRIATE_AUTHENTICATION = "48"
    INVALID_CREDENTIALS = "49"
    INSUFFICIENT_ACCESS_RIGHTS = "50"
    BUSY = "51"
    UNAVAILABLE = "52"
    UNWILLING_TO_PERFORM = "53"
    LOOP_DETECT = "54"
    NAMING_VIOLATION = "64"
    OBJECT_CLASS_VIOLATION = "65"
    NOT_ALLOWED_ON_NON_LEAF = "66"
    NOT_ALLOWED_ON_RDN = "67"
    ENTRY_ALREADY_EXISTS = "68"
    OBJECT_CLASS_MODS_PROHIBITED = "69"
    RESULTS_TOO_LARGE = "70"
    AFFECTS_MULTIPLE_DSAS = "71"
    OTHER = "80"

class FlextLdapObjectClasses:
    TOP: Final[str]
    PERSON: Final[str]
    ORGANIZATIONAL_PERSON: Final[str]
    INET_ORG_PERSON: Final[str]
    GROUP_OF_NAMES: Final[str]
    GROUP_OF_UNIQUE_NAMES: Final[str]
    POSIX_GROUP: Final[str]
    ORGANIZATION: Final[str]
    ORGANIZATIONAL_UNIT: Final[str]
    DOMAIN_COMPONENT: Final[str]
    APPLICATION: Final[str]
    DEVICE: Final[str]
    POSIX_ACCOUNT: Final[str]
    SHADOW_ACCOUNT: Final[str]
    MAIL_RECIPIENT: Final[str]

class FlextLdapAttributes:
    CN: Final[str]
    SN: Final[str]
    GIVEN_NAME: Final[str]
    DISPLAY_NAME: Final[str]
    INITIALS: Final[str]
    UID: Final[str]
    USER_ID: Final[str]
    EMPLOYEE_ID: Final[str]
    EMPLOYEE_NUMBER: Final[str]
    MAIL: Final[str]
    TELEPHONE_NUMBER: Final[str]
    MOBILE: Final[str]
    FAX_NUMBER: Final[str]
    POSTAL_ADDRESS: Final[str]
    class AuthFields:
        USER_PASSWORD_ATTR: Final[str]

    USER_CERTIFICATE: Final[str]
    MEMBER: Final[str]
    UNIQUE_MEMBER: Final[str]
    MEMBER_UID: Final[str]
    ORG: Final[str]
    OU: Final[str]
    DC: Final[str]
    TITLE: Final[str]
    DEPARTMENT: Final[str]
    OBJECT_CLASS: Final[str]
    CREATE_TIMESTAMP: Final[str]
    MODIFY_TIMESTAMP: Final[str]
    CREATORS_NAME: Final[str]
    MODIFIERS_NAME: Final[str]
    LDAP_SYNTAXES: Final[str]
    ATTRIBUTE_TYPES: Final[str]
    OBJECT_CLASSES: Final[str]
    MATCHING_RULES: Final[str]

class FlextLdapDefaults:
    DEFAULT_HOST: Final[str]
    DEFAULT_PORT: Final[int]
    DEFAULT_SSL_PORT: Final[int]
    DEFAULT_TIMEOUT: Final[int]
    DEFAULT_CONNECT_TIMEOUT: Final[int]
    DEFAULT_SEARCH_SCOPE: Final[str]
    DEFAULT_SIZE_LIMIT: Final[int]
    DEFAULT_TIME_LIMIT: Final[int]
    DEFAULT_PAGE_SIZE: Final[int]
    MAX_PAGE_SIZE: Final[int]
    MAX_TIMEOUT_SECONDS: Final[int]
    DEFAULT_POOL_SIZE: Final[int]
    DEFAULT_MAX_POOL_SIZE: Final[int]
    MAX_POOL_SIZE: Final[int]
    DEFAULT_POOL_TIMEOUT: Final[int]
    DEFAULT_USE_SSL: Final[bool]
    DEFAULT_USE_TLS: Final[bool]
    DEFAULT_VALIDATE_CERT: Final[bool]
    DEFAULT_CA_CERTS_FILE: Final[str | None]
    DEFAULT_MAX_RETRIES: Final[int]
    DEFAULT_RETRY_DELAY: Final[float]
    DEFAULT_BACKOFF_FACTOR: Final[float]
    DEFAULT_LOG_LEVEL: Final[str]
    DEFAULT_ENABLE_LOGGING: Final[bool]
    DEFAULT_LOG_OPERATIONS: Final[bool]
    DEFAULT_LOG_RESULTS: Final[bool]

class FlextLdapConnectionConfig(FlextLDAPConfig):
    model_config: Incomplete
    server: str
    port: int
    bind_dn: str
    bind_password: SecretStr
    search_base: str
    timeout: int
    connect_timeout: int
    use_ssl: bool
    use_tls: bool
    validate_cert: bool
    ca_certs_file: str | None
    enable_connection_pooling: bool
    pool_size: int
    max_pool_size: int
    pool_timeout: int
    max_retries: int
    retry_delay: float
    backoff_factor: float
    @classmethod
    def validate_port_number(cls, v: int) -> int: ...
    @classmethod
    def validate_max_pool_size(cls, v: int) -> int: ...
    @property
    def server_uri(self) -> str: ...
    @property
    def is_authenticated(self) -> bool: ...
    @property
    def is_secure(self) -> bool: ...
    def with_server(
        self, host: str, port: int | None = None
    ) -> FlextLdapConnectionConfig: ...
    def with_timeout(self, timeout: int) -> FlextLdapConnectionConfig: ...
    @property
    def host(self) -> str: ...
    @property
    def timeout_seconds(self) -> int: ...
    def validate_business_rules(self) -> FlextResult[None]: ...
    def with_auth(
        self, bind_dn: str, bind_password: str
    ) -> FlextLdapConnectionConfig: ...
    def with_ssl(self, *, use_ssl: bool = True) -> FlextLdapConnectionConfig: ...
    def validate_domain_rules(self) -> FlextResult[None]: ...

class FlextLdapSearchConfig(FlextModel):
    default_scope: FlextLdapScopeEnum
    default_size_limit: int
    default_time_limit: int
    default_page_size: int
    enable_referral_following: bool
    max_referral_hops: int

class FlextLdapLoggingConfig(FlextModel):
    enable_logging: bool
    log_level: FlextLogLevel
    log_operations: bool
    log_results: bool
    log_performance: bool
    log_security_events: bool
    sensitive_attributes: list[str]
    enable_connection_logging: bool
    enable_operation_logging: bool
    log_sensitive_data: bool
    structured_logging: bool

class FlextLdapSettings(FlextModel):
    model_config: Incomplete
    default_connection: FlextLdapConnectionConfig | None
    search: FlextLdapSearchConfig
    logging: FlextLdapLoggingConfig
    enable_caching: bool
    cache_ttl: int
    enable_debug_mode: bool
    enable_test_mode: bool
    def validate_configuration(self) -> FlextResult[None]: ...
    def get_effective_connection(
        self, override: FlextLdapConnectionConfig | None = None
    ) -> FlextLdapConnectionConfig: ...
    @property
    def connection(self) -> FlextLdapConnectionConfig | None: ...
    @connection.setter
    def connection(self, value: FlextLdapConnectionConfig | None) -> None: ...
    def validate_domain_rules(self) -> FlextResult[None]: ...

class FlextLdapConstants:
    Protocol = FlextLdapProtocolConstants
    Scope = FlextLdapScopeEnum
    ResultCodes = FlextLdapOperationResult
    ObjectClasses = FlextLdapObjectClasses
    Attributes = FlextLdapAttributes
    Defaults = FlextLdapDefaults
    LDAP_PORT: Incomplete
    LDAPS_PORT: Incomplete
    DEFAULT_TIMEOUT: Incomplete
    DEFAULT_TIMEOUT_SECONDS: Incomplete
    MAX_TIMEOUT_SECONDS: Incomplete
    DEFAULT_POOL_SIZE: Incomplete
    MAX_POOL_SIZE: Incomplete
    DEFAULT_PAGE_SIZE: Incomplete
    MAX_PAGE_SIZE: Incomplete
    DEFAULT_SIZE_LIMIT: Incomplete
    PERSON: Incomplete
    INET_ORG_PERSON: Incomplete
    GROUP_OF_NAMES: Incomplete
    CN: Incomplete
    UID: Incomplete
    MAIL: Incomplete
    MEMBER: Incomplete

class FlextLdapAuthConfig(FlextModel):
    server: str
    search_base: str
    bind_dn: str
    bind_password: SecretStr | None
    use_anonymous_bind: bool
    sasl_mechanism: str | None
    model_config: Incomplete
    def validate_business_rules(self) -> FlextResult[None]: ...

def create_development_config(
    host: str = "localhost",
    port: int = 389,
    timeout: int = 10,
    *,
    enable_debug: bool = True,
) -> FlextLdapSettings: ...
def create_production_config(
    host: str,
    port: int = 636,
    bind_dn: str | None = None,
    bind_password: str | None = None,
    *,
    use_ssl: bool = True,
    pool_size: int = 20,
) -> FlextLdapSettings: ...
def create_test_config(*, enable_mock: bool = False) -> FlextLdapSettings: ...
