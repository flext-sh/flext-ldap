"""FLEXT_LDAP utilities module - Domain-specific utilities.

This module provides LDAP-specific utilities that extend FlextUtilities from flext-core.
Uses advanced builder patterns, mnemonic DSL, and parametrization for clean code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from typing import TypeIs

from flext_ldif import FlextLdifUtilities

from flext_ldap.constants import c
from flext_ldap.protocols import p
from flext_ldap.typings import t

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
            """Convert to string using parent convenience shortcut.

            Delegates to FlextLdifUtilities.to_str() for actual conversion.

            Args:
                value: Value to convert
                default: Default if None

            Returns:
                str: Converted string

            """
            return FlextLdifUtilities.to_str(value, default=default)

        @staticmethod
        def to_str_list(
            value: t.GeneralValueType | None,
            *,
            default: list[str] | None = None,
        ) -> list[str]:
            """Convert to str_list using parent convenience shortcut.

            Delegates to FlextLdifUtilities.to_str_list() for actual conversion.

            Args:
                value: Value to convert (can be None)
                default: Default if None

            Returns:
                list[str]: Converted list

            """
            return FlextLdifUtilities.to_str_list(value, default=default)

        @staticmethod
        def to_str_list_truthy(
            value: object,
            *,
            default: list[str] | None = None,
        ) -> list[str]:
            """Convert to str_list and filter truthy values.

            Uses parent Conversion utilities for conversion, then filters truthy values.
            This is LDAP-specific functionality for attribute value processing.

            Args:
                value: Value to convert
                default: Default if None

            Returns:
                list[str]: Converted and filtered list (truthy values only)

            """
            # Use parent convenience shortcut for conversion
            str_list = FlextLdifUtilities.to_str_list(value, default=default)
            # Filter truthy values - LDAP-specific behavior
            return [item for item in str_list if item]

        @staticmethod
        def to_str_list_safe(value: object | None) -> list[str]:
            """Safe str_list conversion using parent Conversion utilities.

            Uses parent Conversion utilities for safe None handling and conversion.
            This is LDAP-specific functionality for safe attribute value processing.

            Args:
                value: Value to convert (can be None)

            Returns:
                list[str]: Converted list or []

            """
            return FlextLdifUtilities.to_str_list(value, default=[])

        # ═══════════════════════════════════════════════════════════════════
        # VALIDATION HELPERS - Moved from constants.py (functions forbidden there)
        # ═══════════════════════════════════════════════════════════════════

        class Validation:
            """LDAP validation utilities namespace.

            This namespace contains validation helper methods. Functions are not allowed
            in constants.py, so validation methods are placed here in utilities.py.
            """

            @staticmethod
            def is_valid_status(
                value: str | c.Ldap.LdapCqrs.Status | c.Ldap.LdapCqrs.StatusLiteral,
            ) -> TypeIs[c.Ldap.LdapCqrs.StatusLiteral]:
                """TypeIs narrowing - works in both if/else branches.

                Since StatusLiteral is a subtype of str, after checking isinstance(
                    value, Status
                ),
                the remaining type is str | StatusLiteral. We can check membership directly
                without another isinstance check.

                Args:
                    value: Status value to validate (str, Status enum, or StatusLiteral)

                Returns:
                    TypeIs guard indicating if value is a valid StatusLiteral

                """
                valid_statuses = {
                    c.Ldap.LdapCqrs.Status.PENDING,
                    c.Ldap.LdapCqrs.Status.RUNNING,
                    c.Ldap.LdapCqrs.Status.COMPLETED,
                    c.Ldap.LdapCqrs.Status.FAILED,
                }
                if isinstance(value, c.Ldap.LdapCqrs.Status):
                    return True
                # Type narrowing: value is str | StatusLiteral after Status check
                # Check membership directly - valid strings are StatusLiteral values
                return value in valid_statuses

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
            callables_dict: Mapping[str, Callable[..., t.FlexibleValue]],
            *args: object,
            **kwargs: object,
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

            # Python 3.13: DSL pattern with isinstance for type narrowing
            def convert_value(_k: str, v: object) -> list[str]:
                if v is None:
                    return []
                # Python 3.13: Use isinstance directly for type narrowing
                if isinstance(v, Sequence):
                    # Type narrowing: isinstance ensures v is Sequence
                    return [str(item) for item in v if item is not None]
                # Not a sequence - return as single string value
                if filter_list_like:
                    return [str(v)]
                # Not a sequence - return as single string value
                return [str(v)] if v is not None else []

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
            # Use Protocol for type-safe access
            if isinstance(dn, p.Ldap.Entry.DistinguishedNameProtocol):
                value = dn.value
                # Protocol guarantees value is str, no need for isinstance check
                return value or default
            # If no attribute, convert directly
            # Type narrowing: after Protocol check, dn is str | object
            if isinstance(dn, str):
                return dn
            # Fallback: convert to string
            return str(dn) if dn is not None else default

        # ═══════════════════════════════════════════════════════════════════
        # LDIF NAMESPACE ACCESS - Explicit re-export for clear access
        # ═══════════════════════════════════════════════════════════════════
        # Explicit re-export of parent's Ldif namespace for namespace inheritance.
        # This allows access to LDIF utilities via u.Ldap.Ldif.* pattern.
        Ldif: type[FlextLdifUtilities.Ldif] = FlextLdifUtilities.Ldif


# Convenience alias - exported for domain usage
u = FlextLdapUtilities

__all__ = ["FlextLdapUtilities", "u"]
