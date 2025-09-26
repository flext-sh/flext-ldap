"""LDAP-specific exceptions for flext-ldap library.

This module provides LDAP domain-specific exception classes extending
flext-core exception patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypedDict, Unpack, override

from flext_core import FlextExceptions


class FlextLdapExceptions(FlextExceptions):
    """LDAP-specific exceptions extending FlextExceptions.

    Provides LDAP domain-specific exception classes for all LDAP operation
    error scenarios while maintaining compatibility with flext-core
    exception hierarchy.

    All LDAP exceptions inherit from FlextExceptions.BaseError and include
    proper error codes, context, and correlation tracking.
    """

    @override
    def __init__(self) -> None:
        """Initialize LDAP exceptions with container and logger."""
        super().__init__()
        self._container = None
        self._logger = None

    def connection_error(
        self,
        message: str,
        server_uri: str,
        ldap_code: int | None = None,
    ) -> Exception:
        """Create connection error."""
        return self.LdapConnectionError(
            message, server_uri=server_uri, ldap_code=ldap_code
        )

    def authentication_error(self, message: str, bind_dn: str) -> Exception:
        """Create authentication error."""
        return self.LdapAuthenticationError(message, bind_dn=bind_dn)

    def search_error(
        self,
        message: str,
        filter_str: str,
        base_dn: str,
        context: str | None = None,
    ) -> Exception:
        """Create search error."""
        return self.LdapSearchError(
            message, base_dn=base_dn, filter_str=filter_str, search_context=context
        )

    def operation_error(
        self, message: str, dn: str, target: str | None = None
    ) -> Exception:
        """Create operation error."""
        full_message = f"{message} (target: {target})" if target else message
        return self.LdapModifyError(full_message, dn=dn)

    def validation_error(
        self,
        message: str,
        value: str,
        field: str | None = None,
    ) -> Exception:
        """Create validation error."""
        full_message = f"{message} (value: {value})"
        if field:
            full_message += f" (field: {field})"
        return self.LdapValidationError(full_message, ldap_field=field)

    def configuration_error(
        self,
        message: str,
        config_key: str,
        section: str | None = None,
    ) -> Exception:
        """Create configuration error."""
        return self.LdapConfigurationError(
            message, ldap_config_key=config_key, section=section
        )

    def type_error(
        self,
        message: str,
        value: str,
        expected_type: str,
        actual_type: str | None = None,
    ) -> Exception:
        """Create type error."""
        # Include type information in the error message
        type_info = f"Expected {expected_type}"
        if actual_type:
            type_info += f", got {actual_type}"
        full_message = f"{message} ({type_info})"
        return self.LdapValidationError(full_message, ldap_field=value)

    def ldap_error(
        self,
        message: str,
        operation: str,
        ldap_code: int | None = None,
    ) -> Exception:
        """Create LDAP error."""
        # Include operation and LDAP code in the error message
        full_message = f"{message} (Operation: {operation}"
        if ldap_code is not None:
            full_message += f", LDAP Code: {ldap_code}"
        full_message += ")"
        return self.LdapModifyError(full_message, dn=None)

    def user_error(
        self,
        message: str,
        username: str,
        operation: str | None = None,
        reason: str | None = None,
    ) -> Exception:
        """Create user error."""
        # Include operation and reason in the error message
        full_message = f"{message} (User: {username}"
        if operation:
            full_message += f", Operation: {operation}"
        if reason:
            full_message += f", Reason: {reason}"
        full_message += ")"
        return self.LdapEntryNotFoundError(full_message, dn=username)

    def group_error(
        self,
        message: str,
        groupname: str,
        operation: str | None = None,
    ) -> Exception:
        """Create group error."""
        return self.LdapEntryNotFoundError(message, dn=groupname, operation=operation)

    def connection_failed(
        self,
        message: str,
        server_uri: str | None = None,
        ldap_code: int | None = None,
    ) -> Exception:
        """Create connection failed error."""
        return self.LdapConnectionError(
            message, server_uri=server_uri, ldap_code=ldap_code
        )

    class _LdapExceptionKwargs(TypedDict, total=False):
        """Type-safe kwargs for LDAP exceptions."""

        code: str | None
        context: Mapping[str, object] | None
        correlation_id: str | None
        config_file: str | None

    class LdapConnectionError(FlextExceptions._ConnectionError):
        """LDAP connection failure.

        Raised when LDAP server connection fails or is lost.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            server_uri: str | None = None,
            ldap_code: int | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP connection error.

            Args:
                message: Error message
                server_uri: LDAP server URI that failed
                ldap_code: LDAP result code
                **kwargs: Additional context

            """
            super().__init__(
                message,
                service="LDAP",
                endpoint=server_uri,
                **kwargs,
            )
            self.server_uri = server_uri
            self.ldap_code = ldap_code

        @override
        def __str__(self) -> str:
            """Return string representation with server URI and LDAP code."""
            base_str = super().__str__()
            details = []
            if self.server_uri:
                details.append(f"server: {self.server_uri}")
            if self.ldap_code is not None:
                details.append(f"code: {self.ldap_code}")
            if details:
                return f"{base_str} ({', '.join(details)})"
            return base_str

    class LdapAuthenticationError(FlextExceptions._AuthenticationError):
        """LDAP authentication failure.

        Raised when LDAP bind or authentication fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            bind_dn: str | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP authentication error.

            Args:
                message: Error message
                bind_dn: DN used for authentication
                **kwargs: Additional context

            """
            super().__init__(
                message,
                auth_method="LDAP_BIND",
                **kwargs,
            )
            self.bind_dn = bind_dn

        @override
        def __str__(self) -> str:
            """Return string representation with bind DN details."""
            base_str = super().__str__()
            if self.bind_dn:
                return f"{base_str} (bind_dn: {self.bind_dn})"
            return base_str

    class LdapSearchError(FlextExceptions._OperationError):
        """LDAP search operation failure.

        Raised when LDAP search operation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            base_dn: str | None = None,
            filter_str: str | None = None,
            search_context: str | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP search error.

            Args:
                message: Error message
                base_dn: Search base DN
                filter_str: LDAP search filter
                search_context: Additional context information
                **kwargs: Additional context

            """
            super().__init__(
                message,
                operation="LDAP_SEARCH",
                **kwargs,
            )
            self.base_dn = base_dn
            self.filter_str = filter_str
            self.search_context = search_context

        @override
        def __str__(self) -> str:
            """Return string representation with search details."""
            base_str = super().__str__()
            details = []
            if self.filter_str:
                details.append(f"filter: {self.filter_str}")
            if self.base_dn:
                details.append(f"base: {self.base_dn}")
            if self.search_context:
                details.append(f"context: {self.search_context}")
            if details:
                return f"{base_str} ({', '.join(details)})"
            return base_str

    class LdapModifyError(FlextExceptions._OperationError):
        """LDAP modify operation failure.

        Raised when LDAP modify operation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            modifications: list[tuple[str, str, object]] | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP modify error.

            Args:
                message: Error message
                dn: Entry DN being modified
                modifications: List of modifications attempted
                **kwargs: Additional context

            """
            super().__init__(
                message,
                operation="LDAP_MODIFY",
                **kwargs,
            )
            self.dn = dn
            self.modifications = modifications

        @override
        def __str__(self) -> str:
            """Return string representation with DN details."""
            base_str = super().__str__()
            if self.dn:
                return f"{base_str} (dn: {self.dn})"
            return base_str

    class LdapAddError(FlextExceptions._OperationError):
        """LDAP add operation failure.

        Raised when LDAP add operation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            object_classes: list[str] | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP add error.

            Args:
                message: Error message
                dn: Entry DN being added
                object_classes: Object classes for the entry
                **kwargs: Additional context

            """
            super().__init__(
                message,
                operation="LDAP_ADD",
                **kwargs,
            )
            self.dn = dn
            self.object_classes = object_classes

    class LdapDeleteError(FlextExceptions._OperationError):
        """LDAP delete operation failure.

        Raised when LDAP delete operation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP delete error.

            Args:
                message: Error message
                dn: Entry DN being deleted
                **kwargs: Additional context

            """
            super().__init__(
                message,
                operation="LDAP_DELETE",
                **kwargs,
            )
            self.dn = dn

    class LdapValidationError(FlextExceptions._ValidationError):
        """LDAP data validation failure.

        Raised when LDAP data validation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            ldap_field: str | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP validation error.

            Args:
                message: Error message
                ldap_field: LDAP field/attribute that failed validation
                **kwargs: Additional context

            """
            super().__init__(
                message,
                field=ldap_field,
                **kwargs,
            )
            self.ldap_field = ldap_field

        @override
        def __str__(self) -> str:
            """Return string representation with field details."""
            base_str = super().__str__()
            if self.ldap_field:
                return f"{base_str} (field: {self.ldap_field})"
            return base_str

    class LdapConfigurationError(FlextExceptions._ConfigurationError):
        """LDAP configuration error.

        Raised when LDAP configuration is invalid or missing.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            ldap_config_key: str | None = None,
            section: str | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP configuration error.

            Args:
                message: Error message
                ldap_config_key: LDAP configuration key that is invalid
                section: Configuration section name
                **kwargs: Additional context

            """
            super().__init__(
                message,
                config_key=ldap_config_key,
                **kwargs,
            )
            self.ldap_config_key = ldap_config_key
            self.section = section

        @override
        def __str__(self) -> str:
            """Return string representation with config key details."""
            base_str = super().__str__()
            details = []
            if self.ldap_config_key:
                details.append(f"config: {self.ldap_config_key}")
            if self.section:
                details.append(f"section: {self.section}")
            if details:
                return f"{base_str} ({', '.join(details)})"
            return base_str

    class LdapTimeoutError(FlextExceptions._TimeoutError):
        """LDAP operation timeout.

        Raised when LDAP operation exceeds timeout limit.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            operation: str | None = None,
            timeout_seconds: float | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP timeout error.

            Args:
                message: Error message
                operation: LDAP operation that timed out
                timeout_seconds: Timeout duration in seconds
                **kwargs: Additional context

            """
            super().__init__(
                message,
                timeout_seconds=timeout_seconds,
                **kwargs,
            )
            self.operation = operation

    class LdapEntryNotFoundError(FlextExceptions._NotFoundError):
        """LDAP entry not found.

        Raised when requested LDAP entry does not exist.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            operation: str | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP entry not found error.

            Args:
                message: Error message
                dn: DN of the entry that was not found
                operation: Operation that was attempted
                **kwargs: Additional context

            """
            super().__init__(
                message,
                resource_id=dn,
                resource_type="LDAP_ENTRY",
                **kwargs,
            )
            self.dn = dn
            self.operation = operation

        @override
        def __str__(self) -> str:
            """Return string representation with DN and operation details."""
            base_str = super().__str__()
            details = []
            if self.dn:
                details.append(f"dn: {self.dn}")
            if self.operation:
                details.append(f"operation: {self.operation}")
            if details:
                return f"{base_str} ({', '.join(details)})"
            return base_str

    class LdapEntryAlreadyExistsError(FlextExceptions._AlreadyExistsError):
        """LDAP entry already exists.

        Raised when attempting to create an entry that already exists.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            **kwargs: Unpack[FlextLdapExceptions._LdapExceptionKwargs],
        ) -> None:
            """Initialize LDAP entry already exists error.

            Args:
                message: Error message
                dn: DN of the entry that already exists
                **kwargs: Additional context

            """
            super().__init__(
                message,
                resource_id=dn,
                resource_type="LDAP_ENTRY",
                **kwargs,
            )
            self.dn = dn


__all__ = [
    "FlextLdapExceptions",
]
