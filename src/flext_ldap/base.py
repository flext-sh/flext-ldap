"""Base service patterns for flext-ldap services.

Defines common patterns for config namespace access:
- FlextLdapServiceBase provides typed config access via self.config
- All services MUST inherit from this base
- All config access MUST use self.config.ldap / self.config.ldif

The config namespace access uses FlextSettings.auto_register pattern:
- FlextLdapSettings is registered via @FlextSettings.auto_register("ldap")
- FlextLdifSettings is registered via @FlextSettings.auto_register("ldif")
- Access via self.config.ldap / self.config.ldif from x.config

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC
from collections.abc import Mapping, Sequence
from types import ModuleType
from typing import TypeVar, override

from pydantic_settings import BaseSettings

from flext_core import FlextService, p, t

from flext_ldap import FlextLdapSettings

TDomainResult = TypeVar("TDomainResult")


class FlextLdapServiceBase(FlextService[TDomainResult], ABC):
    """Base class for all flext-ldap services with typed config access.

    Inherits config property from x which provides:
    - self.config → FlextSettings.get_global_instance()
    - self.config.ldap → FlextLdapSettings (via @FlextSettings.auto_register)
    - self.config.ldif → FlextLdifSettings (via @FlextSettings.auto_register)

    Usage in services:
        class MyService(FlextLdapServiceBase[MyResult]):
            def execute(self) -> FlextResult[MyResult]:
                host = self.config.ldap.host  # Typed access!
                encoding = self.config.ldif.ldif_encoding  # Typed access!
    """

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDAP services.

        Business Rule: This method provides runtime bootstrap configuration for
        all LDAP services, ensuring they use FlextLdapSettings as the configuration
        type. This enables proper DI integration and namespace access.

        Implication: All services extending FlextLdapServiceBase automatically
        use FlextLdapSettings for their runtime configuration, ensuring consistent
        configuration handling across all LDAP services.

        Returns:
            Runtime bootstrap options with config_type set to FlextLdapSettings

        """
        del cls
        options = _RuntimeBootstrapOptions(config_type=FlextLdapSettings)
        return options


# Convenience alias for common usage pattern - exported for domain usage
s = FlextLdapServiceBase

__all__ = ["FlextLdapServiceBase", "s"]


class _RuntimeBootstrapOptions:
    """Concrete runtime bootstrap options compatible with core protocol."""

    def __init__(
        self,
        *,
        config_type: type[BaseSettings] | None = None,
    ) -> None:
        self.config_type: type[BaseSettings] | None = config_type
        self.config_overrides: Mapping[str, t.Scalar] | None = None
        self.context: p.Context | None = None
        self.subproject: str | None = None
        self.services: Mapping[str, t.RegisterableService] | None = None
        self.factories: Mapping[str, t.FactoryCallable] | None = None
        self.resources: Mapping[str, t.ResourceCallable] | None = None
        self.container_overrides: Mapping[str, t.Scalar] | None = None
        self.wire_modules: Sequence[ModuleType] | None = None
        self.wire_packages: Sequence[str] | None = None
        self.wire_classes: Sequence[type] | None = None
