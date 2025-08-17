from enum import StrEnum
from typing import ClassVar, Final

from _typeshed import Incomplete

__all__ = [
    "COMMON_NAME",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_PORT",
    "DEFAULT_SIZE_LIMIT",
    "DEFAULT_SSL_PORT",
    "GIVEN_NAME",
    "GROUP_OF_NAMES",
    "INET_ORG_PERSON",
    "LDAP",
    "LDAPS",
    "MAIL",
    "OBJECT_CLASS",
    "ORGANIZATIONAL_PERSON",
    "PERSON",
    "SCOPE_BASE",
    "SCOPE_CHILDREN",
    "SCOPE_ONE",
    "SCOPE_SUB",
    "SURNAME",
    "USER_ID",
    "FlextLdapAttributeConstants",
    "FlextLdapConnectionConstants",
    "FlextLdapConnectionType",
    "FlextLdapConstants",
    "FlextLdapConverterConstants",
    "FlextLdapDefaultValues",
    "FlextLdapDnConstants",
    "FlextLdapErrorConstants",
    "FlextLdapFilterConstants",
    "FlextLdapObjectClassConstants",
    "FlextLdapObservabilityConstants",
    "FlextLdapOperationMessages",
    "FlextLdapSchemaDiscoveryConstants",
    "FlextLdapScope",
]

class FlextLdapProtocolConstants:
    LDAP_VERSION_2: Final[int]
    LDAP_VERSION_3: Final[int]
    DEFAULT_LDAP_VERSION: Final[int]
    DEFAULT_LDAP_PORT: Final[int]
    DEFAULT_LDAPS_PORT: Final[int]
    DEFAULT_GLOBAL_CATALOG_PORT: Final[int]
    DEFAULT_GLOBAL_CATALOG_SSL_PORT: Final[int]
    LDAP_URL_PREFIX: Final[str]
    LDAPS_URL_PREFIX: Final[str]
    LDAPI_URL_PREFIX: Final[str]
    AUTH_SIMPLE: Final[str]
    AUTH_SASL: Final[str]
    AUTH_ANONYMOUS: Final[str]
    SASL_PLAIN: Final[str]
    SASL_DIGEST_MD5: Final[str]
    SASL_GSSAPI: Final[str]
    SASL_EXTERNAL: Final[str]
    SECURITY_TLS: Final[str]
    SECURITY_SSL: Final[str]
    SECURITY_START_TLS: Final[str]
    MSG_BIND_REQUEST: Final[int]
    MSG_BIND_RESPONSE: Final[int]
    MSG_UNBIND_REQUEST: Final[int]
    MSG_SEARCH_REQUEST: Final[int]
    MSG_SEARCH_RESULT_ENTRY: Final[int]
    MSG_SEARCH_RESULT_DONE: Final[int]
    MSG_MODIFY_REQUEST: Final[int]
    MSG_MODIFY_RESPONSE: Final[int]
    MSG_ADD_REQUEST: Final[int]
    MSG_ADD_RESPONSE: Final[int]
    MSG_DELETE_REQUEST: Final[int]
    MSG_DELETE_RESPONSE: Final[int]

class FlextLdapScope(StrEnum):
    BASE = "base"
    ONE = "onelevel"
    SUB = "subtree"
    CHILDREN = "children"
    ONELEVEL = ONE
    SUBTREE = SUB
    @classmethod
    def get_ldap3_scope(cls, scope: FlextLdapScope) -> int: ...
    def get_description(self) -> str: ...

class FlextLdapConnectionType(StrEnum):
    LDAP = "ldap"
    LDAPS = "ldaps"
    LDAPI = "ldapi"

class FlextLdapDerefAliases(StrEnum):
    NEVER = "never"
    IN_SEARCHING = "search"
    FINDING_BASE = "base"
    ALWAYS = "always"

class FlextLdapConnectionConstants:
    DEFAULT_TIMEOUT: Final[int]
    MAX_RETRIES: Final[int]
    CONNECTION_TIMEOUT: Final[int]
    DEFAULT_HOST: Final[str]
    DEFAULT_PORT: Final[int]
    DEFAULT_SSL_PORT: Final[int]
    DEFAULT_BIND_DN: Final[str]
    DEFAULT_BASE_DN: Final[str]
    DEFAULT_CONNECT_TIMEOUT: Final[int]
    DEFAULT_READ_TIMEOUT: Final[int]
    DEFAULT_WRITE_TIMEOUT: Final[int]
    FAST_TIMEOUT: Final[int]
    SLOW_TIMEOUT: Final[int]
    DEFAULT_POOL_SIZE: Final[int]
    MIN_POOL_SIZE: Final[int]
    MAX_POOL_SIZE: Final[int]
    POOL_RESET_INTERVAL: Final[int]
    DEFAULT_SIZE_LIMIT: Final[int]
    DEFAULT_TIME_LIMIT: Final[int]
    MAX_SIZE_LIMIT: Final[int]
    MAX_TIME_LIMIT: Final[int]
    UNLIMITED: Final[int]
    DEFAULT_PAGE_SIZE: Final[int]
    MIN_PAGE_SIZE: Final[int]
    MAX_PAGE_SIZE: Final[int]
    DEFAULT_RETRY_COUNT: Final[int]
    DEFAULT_RETRY_DELAY: Final[float]
    MAX_RETRY_COUNT: Final[int]
    MAX_RETRY_DELAY: Final[float]

class FlextLdapAttributeConstants:
    OBJECT_CLASS: Final[str]
    DISTINGUISHED_NAME: Final[str]
    COMMON_NAME: Final[str]
    SURNAME: Final[str]
    GIVEN_NAME: Final[str]
    DISPLAY_NAME: Final[str]
    DESCRIPTION: Final[str]
    USER_ID: Final[str]
    MAIL: Final[str]
    class AuthFields:
        USER_PASSWORD_ATTR: Final[str]

    TELEPHONE_NUMBER: Final[str]
    FACSIMILE_TELEPHONE_NUMBER: Final[str]
    MOBILE: Final[str]
    POSTAL_ADDRESS: Final[str]
    POSTAL_CODE: Final[str]
    STREET_ADDRESS: Final[str]
    LOCALITY_NAME: Final[str]
    STATE_OR_PROVINCE: Final[str]
    COUNTRY_NAME: Final[str]
    ORGANIZATION: Final[str]
    ORGANIZATIONAL_UNIT: Final[str]
    TITLE: Final[str]
    BUSINESS_CATEGORY: Final[str]
    EMPLOYEE_NUMBER: Final[str]
    EMPLOYEE_TYPE: Final[str]
    DEPARTMENT_NUMBER: Final[str]
    ROOM_NUMBER: Final[str]
    MEMBER: Final[str]
    UNIQUE_MEMBER: Final[str]
    MEMBER_OF: Final[str]
    OWNER: Final[str]
    ROLE_OCCUPANT: Final[str]
    USER_CERTIFICATE: Final[str]
    CA_CERTIFICATE: Final[str]
    CERTIFICATE_REVOCATION_LIST: Final[str]
    CREATE_TIMESTAMP: Final[str]
    MODIFY_TIMESTAMP: Final[str]
    CREATORS_NAME: Final[str]
    MODIFIERS_NAME: Final[str]
    ENTRY_UUID: Final[str]
    ENTRY_CSN: Final[str]
    SAM_ACCOUNT_NAME: Final[str]
    USER_PRINCIPAL_NAME: Final[str]
    OBJECT_GUID: Final[str]
    OBJECT_SID: Final[str]
    WHEN_CREATED: Final[str]
    WHEN_CHANGED: Final[str]
    NS_UNIQUE_ID: Final[str]
    NS_ACCOUNT_LOCK: Final[str]
    class PasswordPolicy:
        PASSWORD_EXPIRY_TIME_ATTR: Final[str]

    @classmethod
    def get_person_attributes(cls) -> list[str]: ...
    @classmethod
    def get_group_attributes(cls) -> list[str]: ...
    @classmethod
    def get_operational_attributes(cls) -> list[str]: ...

class FlextLdapObjectClassConstants:
    TOP: Final[str]
    PERSON: Final[str]
    ORGANIZATIONAL_PERSON: Final[str]
    INET_ORG_PERSON: Final[str]
    GROUP_OF_NAMES: Final[str]
    GROUP_OF_UNIQUE_NAMES: Final[str]
    ORGANIZATIONAL_UNIT: Final[str]
    ORGANIZATION: Final[str]
    DOMAIN_COMPONENT: Final[str]
    POSIX_ACCOUNT: Final[str]
    POSIX_GROUP: Final[str]
    SIMPLE_SECURITY_OBJECT: Final[str]
    APPLICATION_PROCESS: Final[str]
    USER: Final[str]
    COMPUTER: Final[str]
    CONTAINER: Final[str]
    NS_ORG_PERSON: Final[str]
    NS_ACCOUNT: Final[str]

class FlextLdapFilterConstants:
    PRESENT_FILTER: Final[str]
    EQUALS_FILTER: Final[str]
    AND_FILTER: Final[str]
    OR_FILTER: Final[str]
    NOT_FILTER: Final[str]
    WILDCARD_FILTER: Final[str]
    SUBSTRING_FILTER: Final[str]
    APPROX_FILTER: Final[str]
    GREATER_EQUAL_FILTER: Final[str]
    LESS_EQUAL_FILTER: Final[str]
    ALL_OBJECTS: Final[str]
    ALL_USERS: Final[str]
    ALL_INET_ORG_PERSONS: Final[str]
    ALL_GROUPS: Final[str]
    ALL_POSIX_GROUPS: Final[str]
    ALL_ORGANIZATIONAL_UNITS: Final[str]
    ACTIVE_OBJECTS: Final[str]
    ENABLED_ACCOUNTS: Final[str]
    USERS_WITH_EMAIL: Final[str]
    USERS_WITHOUT_EMAIL: Final[str]
    EXPIRED_ACCOUNTS: Final[str]
    NON_EMPTY_GROUPS: Final[str]
    EMPTY_GROUPS: Final[str]

class FlextLdapConverterConstants:
    LDAP_TIME_FORMAT_LONG: Final[int]
    LDAP_TIME_FORMAT_SHORT: Final[int]

class FlextLdapDnConstants:
    COMPONENT_SEPARATOR: Final[str]
    ATTRIBUTE_SEPARATOR: Final[str]
    MULTI_VALUE_SEPARATOR: Final[str]
    ESCAPE_CHARS: Final[frozenset[str]]
    HEX_ESCAPE_PATTERN: Final[str]
    COMMON_NAME_PREFIX: Final[str]
    USER_PREFIX: Final[str]
    GROUP_PREFIX: Final[str]
    ORGANIZATIONAL_UNIT_PREFIX: Final[str]
    ORGANIZATION_PREFIX: Final[str]
    DOMAIN_COMPONENT_PREFIX: Final[str]
    LOCALITY_PREFIX: Final[str]
    STATE_PREFIX: Final[str]
    COUNTRY_PREFIX: Final[str]
    MAX_DN_LENGTH: Final[int]
    MAX_RDN_LENGTH: Final[int]
    MAX_ATTRIBUTE_NAME_LENGTH: Final[int]
    MAX_ATTRIBUTE_VALUE_LENGTH: Final[int]

class FlextLdapErrorConstants:
    SUCCESS: Final[int]
    OPERATIONS_ERROR: Final[int]
    PROTOCOL_ERROR: Final[int]
    TIME_LIMIT_EXCEEDED: Final[int]
    SIZE_LIMIT_EXCEEDED: Final[int]
    COMPARE_FALSE: Final[int]
    COMPARE_TRUE: Final[int]
    AUTH_METHOD_NOT_SUPPORTED: Final[int]
    STRONGER_AUTH_REQUIRED: Final[int]
    PARTIAL_RESULTS: Final[int]
    REFERRAL: Final[int]
    ADMIN_LIMIT_EXCEEDED: Final[int]
    UNAVAILABLE_CRITICAL_EXTENSION: Final[int]
    CONFIDENTIALITY_REQUIRED: Final[int]
    SASL_BIND_IN_PROGRESS: Final[int]
    NO_SUCH_ATTRIBUTE: Final[int]
    UNDEFINED_ATTRIBUTE_TYPE: Final[int]
    INAPPROPRIATE_MATCHING: Final[int]
    CONSTRAINT_VIOLATION: Final[int]
    ATTRIBUTE_OR_VALUE_EXISTS: Final[int]
    INVALID_ATTRIBUTE_SYNTAX: Final[int]
    NO_SUCH_OBJECT: Final[int]
    ALIAS_PROBLEM: Final[int]
    INVALID_DN_SYNTAX: Final[int]
    IS_LEAF: Final[int]
    ALIAS_DEREFERENCING_PROBLEM: Final[int]
    INAPPROPRIATE_AUTHENTICATION: Final[int]
    INVALID_CREDENTIALS: Final[int]
    INSUFFICIENT_ACCESS_RIGHTS: Final[int]
    BUSY: Final[int]
    UNAVAILABLE: Final[int]
    UNWILLING_TO_PERFORM: Final[int]
    LOOP_DETECT: Final[int]
    NAMING_VIOLATION: Final[int]
    OBJECT_CLASS_VIOLATION: Final[int]
    NOT_ALLOWED_ON_NON_LEAF: Final[int]
    NOT_ALLOWED_ON_RDN: Final[int]
    ENTRY_ALREADY_EXISTS: Final[int]
    OBJECT_CLASS_MODS_PROHIBITED: Final[int]
    AFFECTS_MULTIPLE_DSAS: Final[int]
    OTHER: Final[int]
    FLEXT_LDAP_CONNECTION_FAILED: Final[str]
    FLEXT_LDAP_BIND_FAILED: Final[str]
    FLEXT_LDAP_SEARCH_FAILED: Final[str]
    FLEXT_LDAP_MODIFY_FAILED: Final[str]
    FLEXT_LDAP_ADD_FAILED: Final[str]
    FLEXT_LDAP_DELETE_FAILED: Final[str]
    FLEXT_LDAP_INVALID_DN: Final[str]
    FLEXT_LDAP_INVALID_FILTER: Final[str]
    FLEXT_LDAP_ENTRY_NOT_FOUND: Final[str]
    FLEXT_LDAP_ENTRY_EXISTS: Final[str]
    CONNECTION_ERRORS: Final[frozenset[int]]
    AUTHENTICATION_ERRORS: Final[frozenset[int]]
    AUTHORIZATION_ERRORS: Final[frozenset[int]]
    DATA_ERRORS: Final[frozenset[int]]
    ERROR_MESSAGES: ClassVar[dict[str, str]]
    @classmethod
    def get_error_category(cls, result_code: int) -> str: ...
    @classmethod
    def is_retryable_error(cls, result_code: int) -> bool: ...

class FlextLdapObservabilityConstants:
    CONNECTION_COUNT: Final[str]
    OPERATION_COUNT: Final[str]
    OPERATION_DURATION: Final[str]
    ERROR_COUNT: Final[str]
    SEARCH_RESULT_SIZE: Final[str]
    POOL_UTILIZATION: Final[str]
    EVENT_AUTHENTICATION: Final[str]
    EVENT_AUTHORIZATION: Final[str]
    EVENT_SEARCH: Final[str]
    EVENT_MODIFY: Final[str]
    EVENT_ADD: Final[str]
    EVENT_DELETE: Final[str]
    EVENT_CONNECTION: Final[str]
    SCHEMA_CACHE_TTL: Final[int]
    SCHEMA_REFRESH_INTERVAL: Final[int]
    MAX_SCHEMA_ENTRIES: Final[int]
    MAX_DISCOVERY_HISTORY: Final[int]
    AUDIT_AUTHENTICATION: Final[str]
    AUDIT_DATA_ACCESS: Final[str]
    AUDIT_CONFIGURATION: Final[str]
    AUDIT_SECURITY: Final[str]

class FlextLdapIntegrationConstants:
    LDIF_EXPORT_BATCH_SIZE: Final[int]
    LDIF_IMPORT_BATCH_SIZE: Final[int]
    LDIF_MAX_FILE_SIZE: Final[int]
    LDIF_DEFAULT_ENCODING: Final[str]
    OBSERVABILITY_ENABLED: Final[bool]
    METRICS_COLLECTION_INTERVAL: Final[int]
    EVENT_BUFFER_SIZE: Final[int]
    AUTH_TOKEN_VALIDATION_ENABLED: Final[bool]
    AUTH_SESSION_TIMEOUT: Final[int]
    AUTH_PASSWORD_POLICY_ENABLED: Final[bool]
    RESULT_CACHING_ENABLED: Final[bool]
    RESULT_CACHE_TTL: Final[int]
    DI_CONTAINER_SCOPE: Final[str]

class FlextLdapValidationConstants:
    MAX_FILTER_LENGTH: Final[int]
    MAX_FILTER_NESTING_DEPTH: Final[int]
    MAX_ATTRIBUTES_PER_ENTRY: Final[int]
    MAX_VALUES_PER_ATTRIBUTE: Final[int]
    MAX_ENTRY_SIZE: Final[int]
    DN_COMPONENT_PATTERN: Final[str]
    USERNAME_PATTERN: Final[str]
    EMAIL_PATTERN: Final[str]
    MIN_PASSWORD_LENGTH: Final[int]
    MAX_PASSWORD_LENGTH: Final[int]
    REQUIRE_PASSWORD_COMPLEXITY: Final[bool]

class FlextLdapValidationMessages:
    HOST_CANNOT_BE_EMPTY: Final[str]
    PORT_RANGE_ERROR: Final[str]
    CONNECTION_FAILED: Final[str]
    CONNECTION_FAILED_WITH_ERROR: Final[str]
    CONNECTION_FAILED_INVALID_SCHEME: Final[str]
    CONNECTION_FAILED_INVALID_HOST: Final[str]
    BIND_FAILED: Final[str]
    AUTHENTICATION_FAILED: Final[str]
    FAILED_TO_CONNECT: Final[str]
    INVALID_DN_FORMAT: Final[str]
    INVALID_DN_ERROR: Final[str]
    DN_VALIDATION_FAILED: Final[str]
    INVALID_SEARCH_FILTER: Final[str]
    FILTER_VALIDATION_FAILED: Final[str]
    INVALID_SERVER_URI: Final[str]
    URI_VALIDATION_FAILED: Final[str]
    SESSION_ID_REQUIRED: Final[str]
    SESSION_ID_REQUIRED_FOR_OPERATION: Final[str]
    UNKNOWN_SESSION: Final[str]
    SEARCH_FAILED: Final[str]
    SEARCH_FAILED_WITH_ERROR: Final[str]
    SEARCH_FOR_EXPORT_FAILED: Final[str]
    ADD_FAILED: Final[str]
    MODIFY_FAILED: Final[str]
    DELETE_FAILED: Final[str]
    ENTRY_CREATION_ERROR: Final[str]
    USER_CREATION_FAILED: Final[str]
    UID_REQUIRED: Final[str]
    COMMON_NAME_REQUIRED: Final[str]
    SURNAME_REQUIRED: Final[str]
    GROUP_CREATION_FAILED: Final[str]
    OUTPUT_FILE_REQUIRED: Final[str]
    BASE_DN_REQUIRED: Final[str]
    LDIF_EXPORT_FAILED: Final[str]
    EXPORT_ERROR: Final[str]
    LDIF_FILE_NOT_FOUND: Final[str]
    LDIF_PARSE_FAILED: Final[str]
    LDIF_IMPORT_ERROR: Final[str]
    UNKNOWN_VALIDATION_ERROR: Final[str]
    VALIDATION_FAILED_FOR_FIELD: Final[str]
    ATTRIBUTES_CANNOT_BE_EMPTY: Final[str]
    FIELD_CANNOT_BE_EMPTY: Final[str]
    DN_FIELD_NAME: Final[str]
    SEARCH_FILTER_FIELD_NAME: Final[str]
    COMMON_NAME_FIELD_NAME: Final[str]
    FILE_PATH_FIELD_NAME: Final[str]
    URI_FIELD_NAME: Final[str]
    BASE_DN_FIELD_NAME: Final[str]
    INVALID_URI_SCHEME: Final[str]
    CONNECTION_FAILED_WITH_CONTEXT: Final[str]
    VALIDATION_FAILED: Final[str]
    ENTRY_MUST_HAVE_OBJECT_CLASS: Final[str]
    OPERATION_FAILED: Final[str]
    FAILED_TO_OPERATION: Final[str]
    FAILED_TO_WRITE_FILE: Final[str]
    LDAP_CONNECTION_FAILED: Final[str]
    CONNECTION_FAILED_GENERIC: Final[str]
    INVALID_DN_WITH_CONTEXT: Final[str]
    SERVICE_ALREADY_RUNNING: Final[str]
    SERVICE_NOT_RUNNING: Final[str]
    FAILED_TO_START_SERVICE: Final[str]
    FAILED_TO_STOP_SERVICE: Final[str]
    HEALTH_CHECK_FAILED: Final[str]
    SPECIFICATION_FAILED: Final[str]
    INVALID_USER_MISSING_ATTRIBUTES: Final[str]
    PASSWORD_FIELD_TYPE: Final[str]
    FAILED_TO_READ_FILE: Final[str]
    CONFIGURATION_ERROR: Final[str]
    MAX_POOL_SIZE_ERROR: Final[str]
    CACHE_TTL_POSITIVE: Final[str]
    DEFAULT_CONNECTION_MUST_SPECIFY_SERVER: Final[str]
    DISCONNECT_FAILED: Final[str]
    TERMINATION_ERROR: Final[str]

class FlextLdapOperationMessages:
    CONNECTION_CREATED: Final[str]
    CONNECTION_CLOSED: Final[str]
    CONNECTION_ESTABLISHED: Final[str]
    CONNECTION_TERMINATED: Final[str]
    LDAP_SEARCH_COMPLETED: Final[str]
    USER_SEARCH_COMPLETED: Final[str]
    GROUP_SEARCH_COMPLETED: Final[str]
    SEARCH_OPERATION_FAILED: Final[str]
    ENTRY_CREATED: Final[str]
    USER_ENTRY_CREATED: Final[str]
    GROUP_ENTRY_CREATED: Final[str]
    ENTRY_MODIFIED: Final[str]
    ENTRY_DELETED: Final[str]
    SEARCH_SERVICE_INITIALIZED: Final[str]
    CONNECTION_SERVICE_INITIALIZED: Final[str]
    ENTRY_SERVICE_INITIALIZED: Final[str]
    EXPORT_SERVICE_INITIALIZED: Final[str]
    API_INITIALIZED: Final[str]
    EXPORT_COMPLETED: Final[str]
    IMPORT_COMPLETED: Final[str]
    OPERATION_EXCEPTION: Final[str]
    CONNECTION_ESTABLISHMENT_FAILED: Final[str]
    CONNECTION_TERMINATION_FAILED: Final[str]
    SEARCH_OPERATION_EXCEPTION: Final[str]
    USER_CREATION_EXCEPTION: Final[str]
    GROUP_CREATION_EXCEPTION: Final[str]
    ENTRY_MODIFICATION_EXCEPTION: Final[str]
    OPERATION_CONTEXT: Final[str]
    LDAP_CODE_CONTEXT: Final[str]
    CONTEXT_INFO: Final[str]
    SERVER_URI_KEY: Final[str]
    TIMEOUT_KEY: Final[str]
    RETRY_COUNT_KEY: Final[str]
    CONNECTION_OPERATION: Final[str]

class FlextLdapDefaultValues:
    DEFAULT_SEARCH_FILTER: Final[str]
    DEFAULT_SEARCH_SCOPE: Final[str]
    DEFAULT_SEARCH_BASE: Final[str]
    DEFAULT_ENCODING: Final[str]
    DEFAULT_LDIF_ENCODING: Final[str]
    DEFAULT_USER_OBJECT_CLASSES: Final[list[str]]
    DEFAULT_GROUP_OBJECT_CLASSES: Final[list[str]]
    DEFAULT_OU_OBJECT_CLASSES: Final[list[str]]
    DEFAULT_USER_ATTRIBUTES: Final[list[str]]
    DEFAULT_GROUP_ATTRIBUTES: Final[list[str]]
    DEFAULT_ALL_ATTRIBUTES: Final[str]
    DEFAULT_OPERATIONAL_ATTRIBUTES: Final[str]
    SESSION_PREFIX: Final[str]
    DUMMY_MEMBER_DN: Final[str]
    REDACTED_VALUE: Final[str]
    LDIF_FILE_EXTENSION: Final[str]
    DEFAULT_LDIF_LINE_SEPARATOR: Final[str]
    LDIF_ENTRY_SEPARATOR: Final[str]
    DEFAULT_TIMEOUT_SECONDS: Final[int]
    DEFAULT_CONNECTION_TIMEOUT: Final[int]
    DEFAULT_SIZE_LIMIT: Final[int]
    DEFAULT_TIME_LIMIT: Final[int]
    STRING_FIELD_TYPE: Final[str]
    INTEGER_FIELD_TYPE: Final[str]
    BOOLEAN_FIELD_TYPE: Final[str]
    BINARY_FIELD_TYPE: Final[str]
    DATETIME_FIELD_TYPE: Final[str]
    DN_FIELD_TYPE: Final[str]
    EMAIL_FIELD_TYPE: Final[str]
    PHONE_FIELD_TYPE: Final[str]
    UUID_FIELD_TYPE: Final[str]
    URL_FIELD_TYPE: Final[str]
    IP_ADDRESS_FIELD_TYPE: Final[str]
    MAC_ADDRESS_FIELD_TYPE: Final[str]
    CERTIFICATE_FIELD_TYPE: Final[str]
    DEFAULT_SERVICE_NAME: Final[str]
    DEFAULT_SERVICE_VERSION: Final[str]
    SERVICE_STATUS_RUNNING: Final[str]
    SERVICE_STATUS_STOPPED: Final[str]
    DEPENDENCY_FLEXT_CORE: Final[str]
    DEPENDENCY_LDAP3: Final[str]
    DEFAULT_SCHEME_LDAPS: Final[str]
    DEFAULT_SCHEME_LDAP: Final[str]
    VALID_LDAP_USER_NAME: Final[str]
    VALID_LDAP_USER_DESCRIPTION: Final[str]

class FlextLdapSchemaDiscoveryConstants:
    class Discovery:
        SCHEMA_CACHE_TTL: int
        SCHEMA_REFRESH_INTERVAL: int
        MAX_SCHEMA_ENTRIES: int
        MAX_DISCOVERY_HISTORY: int

DEFAULT_PORT: Incomplete
DEFAULT_SSL_PORT: Incomplete
DEFAULT_PAGE_SIZE: Incomplete
DEFAULT_SIZE_LIMIT: Incomplete
OBJECT_CLASS: Incomplete
COMMON_NAME: Incomplete
USER_ID: Incomplete
MAIL: Incomplete
SURNAME: Incomplete
GIVEN_NAME: Incomplete
PERSON: Incomplete
INET_ORG_PERSON: Incomplete
ORGANIZATIONAL_PERSON: Incomplete
GROUP_OF_NAMES: Incomplete
SCOPE_BASE: Incomplete
SCOPE_ONE: Incomplete
SCOPE_SUB: Incomplete
SCOPE_CHILDREN: Incomplete
LDAP: Incomplete
LDAPS: Incomplete

class FlextLdapConstants:
    DEFAULT_TIMEOUT_SECONDS: int
    MAX_TIMEOUT_SECONDS: int
    DEFAULT_POOL_SIZE: int
    MAX_POOL_SIZE: int
    DEFAULT_PAGE_SIZE: int
    MAX_PAGE_SIZE: int
