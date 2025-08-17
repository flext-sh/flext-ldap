from typing import ClassVar

from _typeshed import Incomplete
from flext_core import FlextError as FlextException

__all__ = [
    "FlextLdapAuthenticationError",
    "FlextLdapConfigurationError",
    "FlextLdapConnectionError",
    "FlextLdapException",
    "FlextLdapExceptionFactory",
    "FlextLdapGroupError",
    "FlextLdapOperationError",
    "FlextLdapSearchError",
    "FlextLdapTypeError",
    "FlextLdapUserError",
    "FlextLdapValidationError",
]

class FlextLdapException(FlextException):
    ldap_result_code: Incomplete
    ldap_context: Incomplete
    operation: Incomplete
    def __init__(
        self,
        message: str,
        *,
        ldap_result_code: str | None = None,
        ldap_context: dict[str, object] | None = None,
        operation: str | None = None,
    ) -> None: ...

class FlextLdapConnectionError(FlextLdapException):
    def __init__(
        self,
        message: str,
        *,
        server_uri: str | None = None,
        timeout: int | None = None,
        retry_count: int | None = None,
    ) -> None: ...

class FlextLdapAuthenticationError(FlextLdapException):
    def __init__(
        self,
        message: str,
        *,
        bind_dn: str | None = None,
        auth_method: str | None = None,
        ldap_result_code: str | None = None,
    ) -> None: ...

class FlextLdapSearchError(FlextLdapException):
    def __init__(
        self,
        message: str,
        *,
        base_dn: str | None = None,
        search_filter: str | None = None,
        scope: str | None = None,
        ldap_result_code: str | None = None,
    ) -> None: ...

class FlextLdapOperationError(FlextLdapException):
    def __init__(
        self,
        message: str,
        *,
        target_dn: str | None = None,
        operation_type: str | None = None,
        ldap_result_code: str | None = None,
    ) -> None: ...

class FlextLdapUserError(FlextLdapException):
    def __init__(
        self,
        message: str,
        *,
        user_dn: str | None = None,
        uid: str | None = None,
        validation_field: str | None = None,
    ) -> None: ...

class FlextLdapGroupError(FlextLdapException):
    def __init__(
        self,
        message: str,
        *,
        group_dn: str | None = None,
        group_cn: str | None = None,
        member_dn: str | None = None,
    ) -> None: ...

class FlextLdapValidationError(FlextLdapException):
    def __init__(
        self,
        message: str,
        *,
        field_name: str | None = None,
        field_value: str | None = None,
        validation_rule: str | None = None,
    ) -> None: ...

class FlextLdapConfigurationError(FlextLdapException):
    def __init__(
        self,
        message: str,
        *,
        config_section: str | None = None,
        config_key: str | None = None,
    ) -> None: ...

class FlextLdapTypeError(FlextLdapException):
    def __init__(
        self,
        message: str,
        *,
        expected_type: str | None = None,
        actual_type: str | None = None,
        attribute_name: str | None = None,
    ) -> None: ...

class FlextLdapExceptionFactory:
    LDAP_RESULT_CODES: ClassVar[dict[str, str]]
    @classmethod
    def connection_failed(
        cls,
        server_uri: str,
        error: str,
        *,
        timeout: int | None = None,
        retry_count: int | None = None,
    ) -> FlextLdapConnectionError: ...
    @classmethod
    def authentication_failed(
        cls, bind_dn: str, ldap_result_code: str | None = None
    ) -> FlextLdapAuthenticationError: ...
    @classmethod
    def search_failed(
        cls,
        base_dn: str,
        search_filter: str,
        error: str,
        *,
        ldap_result_code: str | None = None,
    ) -> FlextLdapSearchError: ...
    @classmethod
    def user_creation_failed(
        cls,
        user_dn: str,
        error: str,
        *,
        uid: str | None = None,
        ldap_result_code: str | None = None,
    ) -> FlextLdapUserError: ...
    @classmethod
    def validation_failed(
        cls,
        field_name: str,
        error: str,
        *,
        field_value: str | None = None,
        validation_rule: str | None = None,
    ) -> FlextLdapValidationError: ...
    @classmethod
    def configuration_error(
        cls, config_key: str, error: str, *, config_section: str | None = None
    ) -> FlextLdapConfigurationError: ...
