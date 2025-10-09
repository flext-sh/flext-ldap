"""LDAP-specific exceptions for flext-ldap library.

This module provides LDAP domain-specific exception classes extending
flext-core exception patterns with full correlation ID support and
standardized helper methods for context management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextExceptions, FlextTypes


class FlextLdapExceptions(FlextExceptions):
    """LDAP-specific exceptions extending FlextExceptions from flext-core.

    Provides LDAP domain-specific exception classes for all LDAP operation
    error scenarios while maintaining compatibility with flext-core
    exception hierarchy.

    All LDAP exceptions inherit from FlextExceptions specialized base classes
    and include proper error codes, context, correlation tracking, and
    standardized helper methods for context management.

    Factory methods for direct access - use these methods instead of direct instantiation
    for proper error tracking and correlation ID generation.
    """

    class LdapConnectionError(FlextExceptions.ConnectionError):
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
            **kwargs: object,
        ) -> None:
            """Initialize LDAP connection error.

            Args:
                message: Error message
                server_uri: LDAP server URI that failed
                ldap_code: LDAP result code
                **kwargs: Additional context

            """
            self.server_uri = server_uri
            self.ldap_code = ldap_code

            # Build error message with LDAP context
            enhanced_message = message
            if server_uri:
                enhanced_message = f"{message} (server: {server_uri})"
            if ldap_code is not None:
                enhanced_message = f"{enhanced_message} [LDAP code: {ldap_code}]"

            # Call parent with enhanced message
            super().__init__(enhanced_message)

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

    class LdapAuthenticationError(FlextExceptions.AuthenticationError):
        """LDAP authentication failure.

        Raised when LDAP bind or authentication fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            bind_dn: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDAP authentication error.

            Args:
                message: Error message
                bind_dn: DN used for authentication
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.bind_dn = bind_dn

            # Build error message with LDAP context
            enhanced_message = message
            if bind_dn:
                enhanced_message = f"{message} (bind_dn: {bind_dn})"

            # Call parent with enhanced message
            super().__init__(enhanced_message)

        @override
        def __str__(self) -> str:
            """Return string representation with bind DN details."""
            base_str = super().__str__()
            if self.bind_dn:
                return f"{base_str} (bind_dn: {self.bind_dn})"
            return base_str

    class LdapSearchError(FlextExceptions.OperationError):
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
            **kwargs: object,
        ) -> None:
            """Initialize LDAP search error.

            Args:
                message: Error message
                base_dn: Search base DN
                filter_str: LDAP search filter
                search_context: Additional context information
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.base_dn = base_dn
            self.filter_str = filter_str
            # Use search_context if provided, otherwise check kwargs for context
            self.search_context = search_context or kwargs.get("context")
            # Extract error_code from kwargs
            self.error_code = kwargs.get("error_code")

            # Build error message with LDAP context
            enhanced_message = message
            if base_dn:
                enhanced_message = f"{message} (base_dn: {base_dn})"
            if filter_str:
                enhanced_message = f"{enhanced_message} (filter: {filter_str})"
            if self.search_context:
                enhanced_message = (
                    f"{enhanced_message} (context: {self.search_context})"
                )
            if self.error_code:
                enhanced_message = f"{enhanced_message} (ldap_code: {self.error_code})"

            # Call parent with enhanced message
            super().__init__(enhanced_message)

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
            if self.error_code:
                details.append(f"ldap_code: {self.error_code}")
            if details:
                return f"{base_str} ({', '.join(details)})"
            return base_str

    class LdapModifyError(FlextExceptions.OperationError):
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
            **kwargs: object,
        ) -> None:
            """Initialize LDAP modify error.

            Args:
                message: Error message
                dn: Entry DN being modified
                modifications: List of modifications attempted
                **kwargs: Additional context (context, correlation_id, error_code, target)

            """
            self.dn = dn
            self.modifications = modifications
            self.extra_context = kwargs  # Store extra kwargs for string representation

            # Build error message with LDAP context
            enhanced_message = message
            if dn:
                enhanced_message = f"{message} (dn: {dn})"

            # Call parent with enhanced message
            super().__init__(enhanced_message)

        @override
        def __str__(self) -> str:
            """Return string representation with DN and extra context details."""
            base_str = super().__str__()
            details = []
            if self.dn:
                details.append(f"dn: {self.dn}")
            # Add extra context like target if provided
            for key, value in self.extra_context.items():
                details.append(f"{key}: {value}")

            if details:
                return f"{base_str} ({', '.join(details)})"
            return base_str

    class LdapAddError(FlextExceptions.OperationError):
        """LDAP add operation failure.

        Raised when LDAP add operation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            object_classes: FlextTypes.StringList | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDAP add error.

            Args:
                message: Error message
                dn: Entry DN being added
                object_classes: Object classes for the entry
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.dn = dn
            self.object_classes = object_classes

            # Build error message with LDAP context
            enhanced_message = message
            if dn:
                enhanced_message = f"{message} (dn: {dn})"

            # Call parent with enhanced message
            super().__init__(enhanced_message)

    class LdapDeleteError(FlextExceptions.OperationError):
        """LDAP delete operation failure.

        Raised when LDAP delete operation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDAP delete error.

            Args:
                message: Error message
                dn: Entry DN being deleted
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.dn = dn

            # Build error message with LDAP context
            enhanced_message = message
            if dn:
                enhanced_message = f"{message} (dn: {dn})"

            # Call parent with enhanced message
            super().__init__(enhanced_message)

    class LdapValidationError(FlextExceptions.ValidationError):
        """LDAP data validation failure.

        Raised when LDAP data validation fails.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            ldap_field: str | None = None,
            ldap_value: object | None = None,
            ldap_expected_type: str | None = None,
            ldap_actual_type: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDAP validation error.

            Args:
                message: Error message
                ldap_field: LDAP field/attribute that failed validation
                ldap_value: Value that failed validation
                ldap_expected_type: Expected type for the field
                ldap_actual_type: Actual type received
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.ldap_field = ldap_field
            self.ldap_value = ldap_value
            self.ldap_expected_type = ldap_expected_type
            self.ldap_actual_type = ldap_actual_type

            # Call parent with base message (don't enhance here - let __str__ do it)
            super().__init__(message)

        @override
        def __str__(self) -> str:
            """Return string representation with field, value and type details."""
            base_str = super().__str__()
            details = []
            if self.ldap_value is not None:
                details.append(str(self.ldap_value))
            if self.ldap_field:
                details.append(f"field: {self.ldap_field}")
            if self.ldap_expected_type:
                details.append(f"expected: {self.ldap_expected_type}")
            if self.ldap_actual_type:
                details.append(f"actual: {self.ldap_actual_type}")

            if details:
                return f"{base_str} ({', '.join(details)})"
            return base_str

    class LdapConfigurationError(FlextExceptions.ConfigurationError):
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
            **kwargs: object,
        ) -> None:
            """Initialize LDAP configuration error.

            Args:
                message: Error message
                ldap_config_key: LDAP configuration key that is invalid
                section: Configuration section name
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.ldap_config_key = ldap_config_key
            self.section = section

            # Build error message with LDAP context
            enhanced_message = message
            if ldap_config_key:
                enhanced_message = f"{message} (config_key: {ldap_config_key})"
            if section:
                enhanced_message = f"{enhanced_message} (section: {section})"

            # Call parent with enhanced message
            super().__init__(enhanced_message)

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

    class LdapTimeoutError(FlextExceptions.TimeoutError):
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
            **kwargs: object,
        ) -> None:
            """Initialize LDAP timeout error.

            Args:
                message: Error message
                operation: LDAP operation that timed out
                timeout_seconds: Timeout duration in seconds
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.operation = operation
            self.timeout_seconds = timeout_seconds

            # Build error message with LDAP context
            enhanced_message = message
            if operation:
                enhanced_message = f"{message} (operation: {operation})"
            if timeout_seconds is not None:
                enhanced_message = f"{enhanced_message} (timeout: {timeout_seconds}s)"

            # Call parent with enhanced message
            super().__init__(enhanced_message)

    class LdapEntryNotFoundError(FlextExceptions.NotFoundError):
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
            **kwargs: object,
        ) -> None:
            """Initialize LDAP entry not found error.

            Args:
                message: Error message
                dn: DN of the entry that was not found
                operation: Operation that was attempted
                **kwargs: Additional context (context, correlation_id, error_code, reason)

            """
            self.dn = dn
            self.operation = operation
            self.reason = kwargs.get("reason")  # Extract reason from kwargs

            # Build error message with LDAP context
            enhanced_message = message
            if dn:
                enhanced_message = f"{message} (dn: {dn})"
            if operation:
                enhanced_message = f"{enhanced_message} (operation: {operation})"
            if self.reason:
                enhanced_message = f"{enhanced_message} (reason: {self.reason})"

            # Call parent with enhanced message
            super().__init__(enhanced_message)

        @override
        def __str__(self) -> str:
            """Return string representation with DN, operation and reason details."""
            base_str = super().__str__()
            details = []
            if self.dn:
                details.append(f"dn: {self.dn}")
            if self.operation:
                details.append(f"operation: {self.operation}")
            if self.reason:
                details.append(f"reason: {self.reason}")
            if details:
                return f"{base_str} ({', '.join(details)})"
            return base_str

    class LdapEntryAlreadyExistsError(FlextExceptions.ConflictError):
        """LDAP entry already exists.

        Raised when attempting to create an entry that already exists.
        """

        @override
        def __init__(
            self,
            message: str,
            *,
            dn: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize LDAP entry already exists error.

            Args:
                message: Error message
                dn: DN of the entry that already exists
                **kwargs: Additional context (context, correlation_id, error_code)

            """
            self.dn = dn

            # Build error message with LDAP context
            enhanced_message = message
            if dn:
                enhanced_message = f"{message} (dn: {dn})"

            # Call parent with enhanced message
            super().__init__(enhanced_message)

    # Factory methods for direct access
    @staticmethod
    def connection_error(
        message: str,
        server_uri: str | None = None,
        ldap_code: int | None = None,
    ) -> LdapConnectionError:
        """Create a connection error."""
        return FlextLdapExceptions.LdapConnectionError(
            message,
            server_uri=server_uri,
            ldap_code=ldap_code,
        )

    @staticmethod
    def connection_failed(
        message: str,
        server_uri: str | None = None,
        ldap_code: int | None = None,
    ) -> LdapConnectionError:
        """Create a connection failed error."""
        return FlextLdapExceptions.LdapConnectionError(
            message,
            server_uri=server_uri,
            ldap_code=ldap_code,
        )

    @staticmethod
    def authentication_error(
        message: str,
        bind_dn: str | None = None,
        **kwargs: object,
    ) -> LdapAuthenticationError:
        """Create an authentication error."""
        return FlextLdapExceptions.LdapAuthenticationError(
            message,
            bind_dn=bind_dn,
            **kwargs,
        )

    @staticmethod
    def search_error(
        message: str,
        base_dn: str | None = None,
        filter_str: str | None = None,
        search_context: str | None = None,
        **kwargs: object,
    ) -> LdapSearchError:
        """Create a search error."""
        return FlextLdapExceptions.LdapSearchError(
            message,
            base_dn=base_dn,
            filter_str=filter_str,
            search_context=search_context,
            **kwargs,
        )

    @staticmethod
    def modify_error(
        message: str,
        dn: str | None = None,
        modifications: list[tuple[str, str, object]] | None = None,
        **kwargs: object,
    ) -> LdapModifyError:
        """Create a modify error."""
        return FlextLdapExceptions.LdapModifyError(
            message,
            dn=dn,
            modifications=modifications,
            **kwargs,
        )

    @staticmethod
    def add_error(
        message: str,
        dn: str | None = None,
        object_classes: FlextTypes.StringList | None = None,
        **kwargs: object,
    ) -> LdapAddError:
        """Create an add error."""
        return FlextLdapExceptions.LdapAddError(
            message,
            dn=dn,
            object_classes=object_classes,
            **kwargs,
        )

    @staticmethod
    def delete_error(
        message: str,
        dn: str | None = None,
        **kwargs: object,
    ) -> LdapDeleteError:
        """Create a delete error."""
        return FlextLdapExceptions.LdapDeleteError(message, dn=dn, **kwargs)

    @staticmethod
    def validation_error(
        message: str,
        value: object | None = None,
        field: str | None = None,
    ) -> LdapValidationError:
        """Create a validation error."""
        return FlextLdapExceptions.LdapValidationError(
            message,
            ldap_field=field,
            ldap_value=value,
        )

    @staticmethod
    def configuration_error(
        message: str,
        config_key: str | None = None,
        section: str | None = None,
    ) -> LdapConfigurationError:
        """Create a configuration error."""
        return FlextLdapExceptions.LdapConfigurationError(
            message,
            ldap_config_key=config_key,
            section=section,
        )

    @staticmethod
    def type_error(
        message: str,
        field: str | None = None,
        expected_type: str | None = None,
        actual_type: str | None = None,
    ) -> LdapValidationError:
        """Create a type error."""
        return FlextLdapExceptions.LdapValidationError(
            message,
            ldap_field=field,
            ldap_expected_type=expected_type,
            ldap_actual_type=actual_type,
        )

    @staticmethod
    def user_error(
        message: str,
        username: str | None = None,
        operation: str | None = None,
        reason: str | None = None,
    ) -> LdapEntryNotFoundError:
        """Create a user error."""
        return FlextLdapExceptions.LdapEntryNotFoundError(
            message,
            dn=username,
            operation=operation or "user_lookup",
            reason=reason,
        )

    @staticmethod
    def group_error(
        message: str,
        groupname: str | None = None,
        operation: str | None = None,
        reason: str | None = None,
    ) -> LdapEntryNotFoundError:
        """Create a group error."""
        return FlextLdapExceptions.LdapEntryNotFoundError(
            message,
            dn=groupname,
            operation=operation or "group_lookup",
            reason=reason,
        )

    @staticmethod
    def ldap_error(
        message: str,
        operation: str | None = None,
        ldap_code: int | None = None,
    ) -> LdapSearchError:
        """Create an LDAP error."""
        return FlextLdapExceptions.LdapSearchError(
            message,
            base_dn=None,
            filter_str=None,
            search_context=operation,
            error_code=ldap_code,
        )

    @staticmethod
    def operation_error(
        message: str,
        operation: str | None = None,
        target: str | None = None,
    ) -> LdapModifyError:
        """Create an operation error."""
        return FlextLdapExceptions.LdapModifyError(
            message,
            dn=operation,
            modifications=None,
            target=target,
        )


__all__ = [
    "FlextLdapExceptions",
]
