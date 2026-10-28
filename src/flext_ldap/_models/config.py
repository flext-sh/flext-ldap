"""flext-ldap config models — typed business-rule shapes.

Frozen Pydantic shapes for the ``config/ldap.yaml`` business-rule SSOT.
The ``_config.py`` facade validates the model-less YAML slice into these
classes and exposes the ready objects under ``config.Ldap``.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import m


class FlextLdapModelsConfig:
    """Namespace of typed flext-ldap config models (pure Pydantic)."""

    class Identity(m.BaseModel):
        """LDAP identity metadata from ``config/ldap.yaml``."""

        model_config = m.ConfigDict(frozen=True, extra="forbid")

        name: str = m.Field(description="LDAP project name.")
        version: str = m.Field(description="LDAP project version.")

    class Connection(m.BaseModel):
        """LDAP connection defaults and thresholds."""

        model_config = m.ConfigDict(frozen=True, extra="forbid")

        port: int = m.Field(ge=1, le=65535, description="Default LDAP server port.")
        timeout_seconds: int = m.Field(
            ge=1,
            description="Default LDAP operation timeout in seconds.",
        )
        max_retries: int = m.Field(
            ge=0,
            description="Maximum connection retry attempts.",
        )
        retry_delay_seconds: float = m.Field(
            ge=0,
            description="Delay between retry attempts in seconds.",
        )
        auto_bind: bool = m.Field(description="Auto-bind connection after connect.")
        auto_range: bool = m.Field(description="Enable LDAP range retrieval.")
        default_batch_size: int = m.Field(
            ge=1,
            description="Default LDAP search batch size.",
        )

    class Validation(m.BaseModel):
        """LDAP validation and example defaults."""

        model_config = m.ConfigDict(frozen=True, extra="forbid")

        vendor_string_max_tokens: int = m.Field(
            ge=1,
            description="Maximum tokens in a vendor string.",
        )
        dn_truncation_length: int = m.Field(
            ge=1,
            description="Maximum displayed length of a DN.",
        )
        multi_phase_param_count: int = m.Field(
            ge=1,
            description="Parameter count for multi-phase operations.",
        )
        single_phase_param_count: int = m.Field(
            ge=1,
            description="Parameter count for single-phase operations.",
        )
        example_base_dn: str = m.Field(
            description="Example base DN used in fixtures and docs.",
        )

    class Ldap(m.BaseModel):
        """Root LDAP business-rule namespace."""

        model_config = m.ConfigDict(frozen=True, extra="forbid")

        identity: FlextLdapModelsConfig.Identity = m.Field(
            description="LDAP identity metadata.",
        )
        connection: FlextLdapModelsConfig.Connection = m.Field(
            description="LDAP connection defaults and thresholds.",
        )
        validation: FlextLdapModelsConfig.Validation = m.Field(
            description="LDAP validation and example defaults.",
        )

    class Root(m.BaseModel):
        """Root flext-ldap runtime config validated from ``config/*.yaml``."""

        model_config = m.ConfigDict(frozen=True, extra="ignore")

        Ldap: FlextLdapModelsConfig.Ldap = m.Field(
            description="LDAP business-rule config namespace.",
        )


__all__: list[str] = ["FlextLdapModelsConfig"]
