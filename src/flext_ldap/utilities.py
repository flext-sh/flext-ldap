"""FLEXT_LDAP utilities module - Domain-specific utilities.

This module provides LDAP-specific utilities that extend FlextUtilities from flext-core.
Uses advanced builder patterns, mnemonic DSL, and parametrization for clean code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import cast

from flext_core import FlextRuntime, P
from flext_ldif import FlextLdifUtilities

from flext_ldap import t

# ═══════════════════════════════════════════════════════════════════
# FLEXT_LDAP UTILITIES - Advanced Builder/DSL Patterns
# ═══════════════════════════════════════════════════════════════════
# Extends FlextLdifUtilities (which extends FlextUtilities) with LDAP-specific builders.
# Uses mnemonic short names for well-parametrized functions.
# Maximizes reuse of base utilities via composition.


class FlextLdapUtilities(FlextLdifUtilities):
    """FlextLdap utilities - extends FlextLdifUtilities with advanced builders.

    ARCHITECTURE:
    ────────────
    - Extends FlextUtilities methods via inheritance
    - Uses builder/DSL patterns for composition
    - Mnemonic short names (to_str_list, norm_join, etc.)
    - Maximizes reuse of base utilities
    - LDAP-specific overrides only where needed

    USAGE:
    ──────
        from flext_ldap.utilities import u

        # Builder patterns
        values = u.to_str_list(attr_value)
        normalized = u.norm_join(["A", "B"], case="lower")
        filtered = u.filter_attrs(attrs, only_list_like=True)
    """

    # === LDAP NAMESPACE ===
    # Project-specific namespace for LDAP utilities
    # Access via u.Ldap.* pattern for better organization
    # Also provides access to .Ldif namespace from flext-ldif
    class Ldap:
        """LDAP-specific utility namespace.

        This namespace groups all LDAP-specific utilities for better organization
        and cross-project access. Also provides access to LDIF utilities via .Ldif.

        Example:
            from flext_ldap.utilities import u
            values = u.Ldap.to_str_list(attr_value)
            result = u.Ldap.Ldif.DN.parse("cn=test,dc=example")  # Access LDIF utilities

        """

        # Note: No singleton instance needed - all methods are static

        # ═══════════════════════════════════════════════════════════════════
        # CONVERSION BUILDERS - Mnemonic: conv() → to_str(), to_str_list()
        # ═══════════════════════════════════════════════════════════════════

        @staticmethod
        def to_str(value: object, *, default: str = "") -> str:
            """Convert to string (builder: conv().str()).

            Uses advanced DSL: conv() builder internally for fluent composition.
            Delegates to parent FlextUtilities.conv_str() via inheritance.

            Args:
                value: Value to convert
                default: Default if None

            Returns:
                str: Converted string

            """
            # Convert to string directly
            if value is None:
                return default
            if isinstance(value, str):
                return value
            return str(value) if value else default

        @staticmethod
        def to_str_list(
            value: t.GeneralValueType | None,
            *,
            default: list[str] | None = None,
        ) -> list[str]:
            """Convert to str_list (builder: conv().str_list()).

            Uses advanced DSL: conv() builder internally for fluent composition.
            Delegates to parent FlextUtilities.conv_str_list() via inheritance.

            Args:
                value: Value to convert (can be None)
                default: Default if None

            Returns:
                list[str]: Converted list

            """
            # Convert to list[str] using type narrowing
            if value is None:
                return default or []
            # Check for tuple/set/frozenset first (is_list_like returns False for these)
            if isinstance(value, (list, tuple, set, frozenset)):
                return [str(item) for item in value if item is not None]
            # Use FlextRuntime for type-safe list conversion
            value_typed: t.GeneralValueType = cast("t.GeneralValueType", value)
            if FlextRuntime.is_list_like(value_typed):
                return [str(value)]
            return [str(value)]

        @staticmethod
        def to_str_list_truthy(
            value: object,
            *,
            default: list[str] | None = None,
        ) -> list[str]:
            """Convert to str_list and filter truthy.

            Uses generalized pattern: chain(ensure, filter_truthy).

            Uses advanced DSL: chain() for fluent composition chain.

            Args:
                value: Value to convert
                default: Default if None

            Returns:
                list[str]: Converted and filtered list

            """
            # DSL pattern: chain() for fluent composition chain
            # Use parent class methods directly
            # Convert to list[str] using type narrowing
            if value is None:
                return default or []

            # Check for tuple/set/frozenset first (is_list_like returns False for these)
            if isinstance(value, (list, tuple, set, frozenset)):
                str_list = [str(item) for item in value if item is not None]
            else:
                # Use FlextRuntime for type-safe list conversion
                value_typed: t.GeneralValueType = cast("t.GeneralValueType", value)
                if FlextRuntime.is_list_like(value_typed):
                    # For other list-like types (not handled by isinstance above)
                    str_list = [str(value_typed)]
                else:
                    str_list = (
                        [str(value_typed)] if value is not None else (default or [])
                    )
            # Filter truthy values - implement directly for type safety
            # Type narrowing: str_list is list[str], filter truthy values
            filtered_list: list[str] = [item for item in str_list if item]
            return filtered_list

        @staticmethod
        def to_str_list_safe(value: object | None) -> list[str]:
            """Safe str_list conversion (generalized: when() + ensure).

            Uses advanced DSL: when() → ensure() for safe composition.

            Args:
                value: Value to convert (can be None)

            Returns:
                list[str]: Converted list or []

            """
            # DSL pattern: conditional check for safe None handling, then ensure()
            if value is not None:
                # Convert to list[str] using type narrowing
                # Check for tuple/set/frozenset first (is_list_like returns False for these)
                # then check is_list_like for standard list/Sequence types
                if isinstance(value, (list, tuple, set, frozenset)):
                    return [str(item) for item in value if item is not None]
                # Use FlextRuntime for type-safe list conversion
                value_typed: t.GeneralValueType = cast("t.GeneralValueType", value)
                if FlextRuntime.is_list_like(value_typed):
                    return [str(item) for item in value_typed if item is not None]
                return [str(value_typed)] if value is not None else []
            return []

        # ═══════════════════════════════════════════════════════════════════
        # NORMALIZATION BUILDERS - Expose via static methods
        # ═══════════════════════════════════════════════════════════════════

        @staticmethod
        def norm_str(value: str, *, case: str | None = None) -> str:
            """Normalize string (implements normalization directly).

            Args:
                value: String to normalize
                case: Case normalization ("lower", "upper", None)

            Returns:
                Normalized string

            """
            if not value:
                return ""
            if case == "lower":
                return value.lower()
            if case == "upper":
                return value.upper()
            return value

        @classmethod
        def norm_join(
            cls,
            values: list[str] | tuple[str, ...],
            *,
            case: str | None = None,
        ) -> str:
            """Normalize and join strings (delegates to Parser.norm_join).

            Args:
                values: List or tuple of strings to normalize and join
                case: Case normalization ("lower", "upper", None)

            Returns:
                Joined normalized string

            """
            # Convert tuple to list if needed
            values_list = list(values) if isinstance(values, tuple) else values
            # Normalize each value and join
            normalized = [cls.norm_str(str(v), case=case) for v in values_list if v]
            return " ".join(normalized)

        @classmethod
        def norm_in(
            cls,
            value: str,
            collection: list[str] | tuple[str, ...],
            *,
            case: str | None = None,
        ) -> bool:
            """Check if normalized value is in collection (delegates to Parser.norm_in).

            Args:
                value: String to check
                collection: List or tuple of strings to check against
                case: Case normalization ("lower", "upper", None)

            Returns:
                True if normalized value is in collection

            """
            # Convert tuple to list if needed
            collection_list = (
                list(collection) if isinstance(collection, tuple) else collection
            )
            # Normalize value and check membership
            normalized_value = cls.norm_str(value, case=case or "lower")
            normalized_collection = [
                cls.norm_str(str(item), case=case or "lower")
                for item in collection_list
            ]
            return normalized_value in normalized_collection

        # ═══════════════════════════════════════════════════════════════════
        # FILTER BUILDERS - Expose via static methods
        # ═══════════════════════════════════════════════════════════════════

        @staticmethod
        def filter_truthy(
            value: list[object] | dict[str, object],
        ) -> list[object] | dict[str, object]:
            """Filter truthy values from list or dict.

            Args:
                value: List or dict to filter

            Returns:
                Filtered list or dict with only truthy values

            """
            if isinstance(value, dict):
                return {k: v for k, v in value.items() if v}
            return [item for item in value if item]

        # ═══════════════════════════════════════════════════════════════════
        # MAP BUILDERS - Expose via static methods
        # ═══════════════════════════════════════════════════════════════════

        @staticmethod
        def map_str(
            values: list[str] | tuple[str, ...],
            *,
            case: str | None = None,
            join: str | None = None,
        ) -> str | list[str]:
            """Map strings with normalization and optional join.

            Args:
                values: List of strings to map
                case: Case normalization ("lower", "upper", None)
                join: Join character (if provided, returns str; otherwise list[str])

            Returns:
                Joined string or list of normalized strings

            """
            # Normalize strings
            normalized: list[str] = []
            for val in values:
                normalized_val = val
                if case == "lower":
                    normalized_val = val.lower()
                elif case == "upper":
                    normalized_val = val.upper()
                normalized.append(normalized_val)

            # Join if requested
            if join is not None:
                return join.join(normalized)
            return normalized

        # ═══════════════════════════════════════════════════════════════════
        # FIND BUILDERS - Expose via static methods
        # ═══════════════════════════════════════════════════════════════════

        @staticmethod
        def find_callable(
            callables_dict: Mapping[str, Callable[P, t.FlexibleValue]],
            *args: P.args,
            **kwargs: P.kwargs,
        ) -> str | None:
            """Find first callable that returns truthy value.

            Args:
                callables_dict: Dictionary of callables to test
                *args: Positional arguments to pass to callables
                **kwargs: Keyword arguments to pass to callables

            Returns:
                Key of first matching callable or None

            """
            for key, callable_func in callables_dict.items():
                try:
                    result = callable_func(*args, **kwargs)
                    if result:
                        return key
                except Exception as e:
                    # Log exception for debugging but continue searching
                    # This is expected behavior when testing multiple callables
                    logger = logging.getLogger(__name__)
                    logger.debug(
                        "Callable %s raised exception, continuing",
                        key,
                        exc_info=e,
                    )
                    continue
            return None

        @staticmethod
        def attr_to_str_list(
            attrs: dict[str, object] | dict[str, list[str]],
            *,
            filter_list_like: bool = False,
        ) -> dict[str, list[str]]:
            """Convert attributes to str_list (generalized: map() + ensure).

            Uses advanced DSL: map() → ensure() for fluent composition.

            Args:
                attrs: Attributes to convert
                filter_list_like: Only convert list-like values

            Returns:
                dict[str, list[str]]: Converted attributes

            """

            # DSL pattern: conditional conversion with ensure() for fluent composition
            def convert_value(_k: str, v: object) -> list[str]:
                if v is None:
                    return []
                if filter_list_like:
                    # Cast object to GeneralValueType for is_list_like
                    # FlextRuntime.is_list_like expects GeneralValueType
                    v_typed_check: t.GeneralValueType = cast("t.GeneralValueType", v)
                    if not FlextRuntime.is_list_like(v_typed_check):
                        return [str(v)]
                # Cast object to GeneralValueType for ensure
                v_typed: t.GeneralValueType = cast("t.GeneralValueType", v)
                # Convert to list[str] using type narrowing
                if FlextRuntime.is_list_like(v_typed):
                    if isinstance(v_typed, (list, tuple, set, frozenset)):
                        return [str(item) for item in v_typed if item is not None]
                    return [str(v_typed)]
                return [str(v_typed)] if v_typed is not None else []

            # attrs is dict[str, object] | dict[str, list[str]]
            # Both are compatible with dict[str, object] for processing
            attrs_dict: dict[str, object] = dict(attrs)
            if not attrs_dict:
                return {}
            # Map attributes using dict comprehension (map functionality)
            # mapped_result is always dict[str, list[str]] from comprehension
            return {k: convert_value(k, v) for k, v in attrs_dict.items()}

        # ═══════════════════════════════════════════════════════════════════
        # FIND BUILDERS - Inherited from parent FlextUtilities
        # ═══════════════════════════════════════════════════════════════════
        # Method find_callable is inherited from parent
        # No need to override - parent implementation is generic and reusable

        # ═══════════════════════════════════════════════════════════════════
        # INHERITED METHODS - Available via inheritance from FlextUtilities
        # ═══════════════════════════════════════════════════════════════════
        # These methods are available via inheritance from FlextUtilities:
        # - filter_truthy (via FlextUtilities)
        # - extract_str_from_obj (via FlextUtilities)
        # - normalize (via FlextUtilities) - prefer norm_str() for new code
        # - map_str (via FlextUtilities)
        # - find_callable (via FlextUtilities)
        # - filter_attrs (via FlextUtilities)
        # - all_ and any_ (via FlextUtilities.Validation.ResultHelpers)

        # ═══════════════════════════════════════════════════════════════════
        # CONDITIONAL BUILDERS - Mnemonic: when() → when_safe(), dn_str()
        # ═══════════════════════════════════════════════════════════════════

        @staticmethod
        def when_safe(
            *,
            condition: bool,
            then_value: object | None,
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
            # DSL pattern: conditional check for safe composition
            if condition:
                if safe_then and then_value is None:
                    return else_value
                return then_value if then_value is not None else else_value
            return else_value

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
            # Extract string from object with attribute access
            if dn is None:
                return default
            # Check if object has the specified attribute
            if hasattr(dn, "value"):
                value = getattr(dn, "value", None)
                if isinstance(value, str):
                    return value
                return str(value) if value is not None else default
            # If no attribute, convert directly
            if isinstance(dn, str):
                return dn
            return str(dn) if dn is not None else default

        # ═══════════════════════════════════════════════════════════════════
        # LDIF NAMESPACE ACCESS - Access flext-ldif utilities via .Ldif
        # ═══════════════════════════════════════════════════════════════════
        # Since FlextLdapUtilities extends FlextLdifUtilities, we can access
        # LDIF utilities via the parent class's .Ldif namespace
        # This is a class attribute that references the parent's Ldif namespace
        Ldif: type[FlextLdifUtilities.Ldif] = FlextLdifUtilities.Ldif


# Convenience alias - exported for domain usage
u = FlextLdapUtilities

__all__ = ["FlextLdapUtilities", "u"]
