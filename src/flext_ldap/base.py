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
from dataclasses import dataclass
from types import ModuleType
from typing import override

from pydantic_settings import BaseSettings

from flext_core import s
from flext_ldap import FlextLdapSettings, p, t


@dataclass
class _LdapRuntimeBootstrapOptions:
    config_type: type[BaseSettings] | None = FlextLdapSettings
    config_overrides: t.ConfigurationMapping | None = None
    context: p.Context | None = None
    subproject: str | None = None
    services: Mapping[str, t.RegisterableService] | None = None
    factories: Mapping[str, t.FactoryCallable] | None = None
    resources: Mapping[str, t.ResourceCallable] | None = None
    container_overrides: t.ConfigurationMapping | None = None
    wire_modules: Sequence[ModuleType | str] | None = None
    wire_packages: t.StrSequence | None = None
    wire_classes: Sequence[type] | None = None


class FlextLdapServiceBase[
    TResult: t.ValueOrModel | Sequence[t.ValueOrModel] = t.ValueOrModel
    | Sequence[t.ValueOrModel]
](s[TResult], ABC):
    """Base class for all flext-ldap services.

    Subclasses parametrize via s[T] for their specific result type.
    """

    @classmethod
    @override
    def _runtime_bootstrap_options(cls) -> p.RuntimeBootstrapOptions:
        """Return runtime bootstrap options for LDAP services."""
        return _LdapRuntimeBootstrapOptions()


s = FlextLdapServiceBase
__all__ = ["FlextLdapServiceBase", "s"]
