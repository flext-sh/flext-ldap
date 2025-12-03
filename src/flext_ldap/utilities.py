"""FLEXT_LDAP utilities module - Domain-specific utilities.

This module provides LDAP-specific utilities that extend FlextUtilities from flext-core.
Uses advanced builder patterns, mnemonic DSL, and parametrization for clean code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from flext_core import FlextUtilities
from flext_core.runtime import FlextRuntime
from flext_core.typings import FlextTypes as t

# ═══════════════════════════════════════════════════════════════════
# FLEXT_LDAP UTILITIES - Advanced Builder/DSL Patterns
# ═══════════════════════════════════════════════════════════════════
# Extends FlextUtilities with LDAP-specific builders and compositions.
# Uses mnemonic short names for well-parametrized functions.
# Maximizes reuse of base utilities via composition.


class FlextLdapUtilities(FlextUtilities):
    """FlextLdap utilities - extends FlextUtilities with advanced builders.

    ARCHITECTURE:
    ────────────
    - Extends FlextUtilities methods via inheritance
    - Uses builder/DSL patterns for composition
    - Mnemonic short names (to_str_list, norm_join, etc.)
    - Maximizes reuse of base utilities
    - LDAP-specific overrides only where needed

    USAGE:
    ──────
        from flext_ldap.utilities import FlextLdapUtilities as u

        # Builder patterns
        values = u.to_str_list(attr_value)
        normalized = u.norm_join(["A", "B"], case="lower")
        filtered = u.filter_attrs(attrs, only_list_like=True)
    """

    # ═══════════════════════════════════════════════════════════════════
    # CONVERSION BUILDERS - Mnemonic: conv() → to_str(), to_str_list()
    # ═══════════════════════════════════════════════════════════════════
    # Aliases for backward compatibility - delegate to parent conv_str/conv_str_list

    @staticmethod
    def to_str(value: object, *, default: str = "") -> str:
        """Convert to string (builder: conv().str()).

        Uses advanced DSL: conv() builder internally for fluent composition.
        Alias for conv_str() from parent FlextUtilities for backward compatibility.

        Args:
            value: Value to convert
            default: Default if None

        Returns:
            str: Converted string

        """
        return FlextLdapUtilities.ensure_str(cast("t.GeneralValueType", value), default=default)

    @staticmethod
    def to_str_list(value: t.GeneralValueType, *, default: list[str] | None = None) -> list[str]:
        """Convert to str_list (builder: conv().str_list()).

        Uses advanced DSL: conv() builder internally for fluent composition.
        Alias for conv_str_list() from parent FlextUtilities for backward compatibility.

        Args:
            value: Value to convert
            default: Default if None

        Returns:
            list[str]: Converted list

        """
        return FlextLdapUtilities.ensure_str_list(value, default=default or [])

    @staticmethod
    def to_str_list_truthy(value: object, *, default: list[str] | None = None) -> list[str]:
        """Convert to str_list and filter truthy (generalized: chain(ensure_str_list, filter_truthy)).

        Uses advanced DSL: chain() for fluent composition chain.

        Args:
            value: Value to convert
            default: Default if None

        Returns:
            list[str]: Converted and filtered list

        """
        # DSL pattern: chain() for fluent composition chain
        result = FlextLdapUtilities.chain(
            cast("t.GeneralValueType", value),
            lambda v: FlextLdapUtilities.ensure_str_list(cast("t.GeneralValueType", v), default=default or []),
            lambda lst: FlextLdapUtilities.filter_truthy(cast("list[object]", lst)),
        )
        return cast("list[str]", result) if isinstance(result, list) else (default or [])

    @staticmethod
    def to_str_list_safe(value: object | None) -> list[str]:
        """Safe str_list conversion (generalized: when() + ensure_str_list).

        Uses advanced DSL: when() → ensure_str_list() for safe composition.

        Args:
            value: Value to convert (can be None)

        Returns:
            list[str]: Converted list or []

        """
        # DSL pattern: when() for safe None check, then ensure_str_list()
        return cast(
            "list[str]",
            FlextLdapUtilities.when(
                condition=value is not None,
                then_value=FlextLdapUtilities.ensure_str_list(cast("t.GeneralValueType", value), default=[]),
                else_value=[],
            ),
        )

    # ═══════════════════════════════════════════════════════════════════
    # NORMALIZATION BUILDERS - Inherited from parent FlextUtilities
    # ═══════════════════════════════════════════════════════════════════
    # Methods norm_str, norm_list, norm_join, norm_in are inherited from parent
    # No need to override - parent implementations are generic and reusable

    # ═══════════════════════════════════════════════════════════════════
    # FILTER BUILDERS - Inherited from parent FlextUtilities
    # ═══════════════════════════════════════════════════════════════════
    # Methods filter_attrs, filter_not_none, filter_truthy are inherited from parent
    # No need to override - parent implementations are generic and reusable

    # ═══════════════════════════════════════════════════════════════════
    # MAP BUILDERS - Mnemonic: map() → map_str(), attr_to_str_list()
    # ═══════════════════════════════════════════════════════════════════
    # map_str is inherited from parent FlextUtilities
    # attr_to_str_list is LDAP-specific and kept here

    @staticmethod
    def attr_to_str_list(
        attrs: dict[str, object] | dict[str, list[str]],
        *,
        filter_list_like: bool = False,
    ) -> dict[str, list[str]]:
        """Convert attributes to str_list (generalized: map() + ensure_str_list).

        Uses advanced DSL: map() → ensure_str_list() for fluent composition.

        Args:
            attrs: Attributes to convert
            filter_list_like: Only convert list-like values

        Returns:
            dict[str, list[str]]: Converted attributes

        """
        # DSL pattern: map() with when() + ensure_str_list() for fluent composition
        def convert_value(_k: str, v: object) -> list[str]:
            return cast(
                "list[str]",
                FlextLdapUtilities.when(
                    condition=filter_list_like and not FlextRuntime.is_list_like(cast("t.GeneralValueType", v)),
                    then_value=[str(v)],
                    else_value=FlextLdapUtilities.ensure_str_list(cast("t.GeneralValueType", v), default=[]),
                ),
            )

        attrs_dict = cast("dict[str, object]", attrs) if isinstance(attrs, dict) else {}
        if not attrs_dict:
            return {}
        mapped_result = FlextLdapUtilities.map(attrs_dict, mapper=convert_value)
        # map() returns dict[str, R] when input is dict, so type is already correct
        return mapped_result if isinstance(mapped_result, dict) else {}

    # ═══════════════════════════════════════════════════════════════════
    # FIND BUILDERS - Inherited from parent FlextUtilities
    # ═══════════════════════════════════════════════════════════════════
    # Method find_callable is inherited from parent
    # No need to override - parent implementation is generic and reusable

    # ═══════════════════════════════════════════════════════════════════
    # CONDITIONAL BUILDERS - Mnemonic: when() → when_safe(), dn_str()
    # ═══════════════════════════════════════════════════════════════════

    @staticmethod
    def when_safe(
        condition: bool,  # noqa: FBT001
        then_value: object | None,
        *,
        else_value: object | None = None,
        safe_then: bool = False,
    ) -> object | None:
        """Safe conditional (builder: whn().safe().or_().build()).

        Uses advanced DSL: whn() → safe() → or_() for safe composition.

        Args:
            condition: Boolean condition
            then_value: Value if True
            else_value: Value if False
            safe_then: Return else_value if then_value is None

        Returns:
            then_value or else_value

        """
        # DSL pattern: when() → or_() for safe composition with safe_then check
        return FlextLdapUtilities.when(
            condition=condition,
            then_value=FlextLdapUtilities.or_(
                then_value if not safe_then or then_value is not None else None,
                else_value,
                default=else_value,
            ),
            else_value=else_value,
        )

    @staticmethod
    def dn_str(dn: object | None, *, default: str = "unknown") -> str:
        """Extract DN string (builder: whn().safe().conv().str()).

        Uses advanced DSL: whn() → safe() → conv() → str() for fluent composition.

        Args:
            dn: DN object (can be None or have .value)
            default: Default if None

        Returns:
            str: DN string or default

        """
        return FlextLdapUtilities.extract_str_from_obj(dn, attr="value", default=default)


# Convenience alias
u = FlextLdapUtilities
