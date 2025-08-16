"""Compatibility shim: re-export configuration API from models.

Após a consolidação, as classes e helpers de configuração vivem em
`flext_ldap.models`. Este módulo mantém conveniência reexportando-as.
"""

from __future__ import annotations

from .models import (
    FlextLdapAttributes,
    FlextLdapAuthConfig,
    FlextLdapConnectionConfig,
    FlextLdapConstants,
    FlextLdapDefaults,
    FlextLdapLoggingConfig,
    FlextLdapObjectClasses,
    FlextLdapOperationResult,
    FlextLdapProtocolConstants,
    FlextLdapScope,
    FlextLdapSearchConfig,
    FlextLdapSettings,
    create_development_config,
    create_production_config,
    create_test_config,
)

__all__ = [
    "FlextLdapAttributes",
    "FlextLdapAuthConfig",
    "FlextLdapConnectionConfig",
    "FlextLdapConstants",
    "FlextLdapDefaults",
    "FlextLdapLoggingConfig",
    "FlextLdapObjectClasses",
    "FlextLdapOperationResult",
    "FlextLdapProtocolConstants",
    "FlextLdapScope",
    "FlextLdapSearchConfig",
    "FlextLdapSettings",
    "create_development_config",
    "create_production_config",
    "create_test_config",
]

# Compatibility adapter: allow plain string passwords with libraries that
# construct configs from non-SecretStr sources (e.g., external CLIs/tests).
# This preserves strict SecretStr internally while accepting str at init.
try:
    from pydantic import SecretStr

    class FlextLdapConnectionConfigCompat(FlextLdapConnectionConfig):  # type: ignore[misc]
        def __init__(self, *args: object, **kwargs: object) -> None:  # noqa: D401
            password = kwargs.get("bind_password")
            if isinstance(password, str):
                kwargs["bind_password"] = SecretStr(password)
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]

        def __getattribute__(self, name: str) -> object:  # noqa: D401, ANN204
            if name == "bind_password":
                value = super().__getattribute__(name)
                try:
                    # When consumers read .bind_password, expose plain string
                    if isinstance(value, SecretStr):  # type: ignore[arg-type]
                        return value.get_secret_value()
                except Exception:
                    return value
                return value
            return super().__getattribute__(name)

    # Re-export compat alias for consumers that import from config
    FlextLdapConnectionConfig = FlextLdapConnectionConfigCompat  # type: ignore[assignment]
except Exception:
    # If anything goes wrong, keep the original class; tests will reveal issues
    import logging

    logging.getLogger(__name__).debug(
        "Compat layer for FlextLdapConnectionConfig not applied",
    )
