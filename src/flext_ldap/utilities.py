"""FLEXT_LDAP utilities module - Domain-specific utilities.

This module provides LDAP-specific utilities that extend FlextUtilities from flext-core.
Uses advanced builder patterns, mnemonic DSL, and parametrization for clean code.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import TypeIs

from flext_ldif import FlextLdifUtilities

from flext_ldap import c, m


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
        from flext_ldap import u

        # Builder patterns
        values = u.to_str_list(attr_value)
        normalized = u.norm_join(["A", "B"], case="lower")
        filtered = u.filter_attrs(attrs, only_list_like=True)
    """

    class Ldap:
        """LDAP-specific utility namespace.

        This namespace groups all LDAP-specific utilities for better organization
        and cross-project access. Also provides access to LDIF utilities via .Ldif.

        Example:
            from flext_ldap import u
            values = u.Ldap.to_str_list(attr_value)
            result = u.Ldap.DN.parse("cn=test,dc=example")  # Access LDIF utilities

        """

        @staticmethod
        def to_str(value: object | None, *, default: str = "") -> str:
            """Convert a value to string, returning default for None or complex types."""
            if value is None:
                return default
            if isinstance(value, (str, int, float, bool)):
                str_val = str(value)
                return str_val or default
            return default

        @staticmethod
        def to_str_list(
            value: object | None, *, default: list[str] | None = None
        ) -> list[str]:
            """Convert a value to a single-element string list."""
            if value is None:
                return default or []
            if isinstance(value, (str, int, float, bool)):
                return [str(value)]
            return default or []

        @staticmethod
        def to_str_list_safe(value: object | None) -> list[str]:
            """Safe str_list conversion returning [] for None or complex types."""
            if value is None:
                return []
            if isinstance(value, (str, int, float, bool)):
                return [str(value)]
            return []

        @staticmethod
        def to_str_list_truthy(
            value: object | None, *, default: list[str] | None = None
        ) -> list[str]:
            """Convert to str_list and filter truthy values."""
            if value is None:
                return default or []
            if isinstance(value, (str, int, float, bool)):
                str_val = str(value)
                return [str_val] if str_val else (default or [])
            return default or []

        class Validation:
            """LDAP validation utilities namespace.

            This namespace contains validation helper methods. Functions are not allowed
            in constants.py, so validation methods are placed here in utilities.py.
            """

            @staticmethod
            def is_valid_status(value: str | object) -> TypeIs[str]:
                """TypeIs narrowing - works in both if/else branches.

                Since StatusLiteral is a subtype of str, after checking enum type,
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
                return value in valid_statuses

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
            match collection:
                case tuple():
                    collection_list = list(collection)
                case _:
                    collection_list = collection
            normalized_value = cls.norm_str(value, case=case or "lower")
            normalized_collection = [
                cls.norm_str(str(item), case=case or "lower")
                for item in collection_list
            ]
            return normalized_value in normalized_collection

        @classmethod
        def norm_join(
            cls, values: list[str] | tuple[str, ...], *, case: str | None = None
        ) -> str:
            """Normalize and join strings (delegates to Parser.norm_join).

            Args:
                values: List or tuple of strings to normalize and join
                case: Case normalization ("lower", "upper", None)

            Returns:
                Joined normalized string

            """
            match values:
                case tuple():
                    values_list = list(values)
                case _:
                    values_list = values
            normalized = [cls.norm_str(str(v), case=case) for v in values_list if v]
            return " ".join(normalized)

        @staticmethod
        def attr_to_str_list(
            attrs: Mapping[str, object] | Mapping[str, list[str]],
            *,
            filter_list_like: bool = False,
        ) -> Mapping[str, list[str]]:
            """Convert attributes to str_list (generalized: map() + ensure).

            Uses advanced DSL: map() → ensure() for fluent composition.

            Args:
                attrs: Attributes to convert
                filter_list_like: Only convert list-like values

            Returns:
                dict[str, list[str]]: Converted attributes

            """

            def convert_value(_k: str, v: str | list[str] | object) -> list[str]:
                if v is None:
                    return []
                match v:
                    case list() | tuple() | range():
                        return [str(item) for item in v if item is not None]
                    case _:
                        pass
                if filter_list_like:
                    return [str(v)]
                return [str(v)]

            attrs_dict: dict[str, object | list[str]] = dict(attrs)
            if not attrs_dict:
                return {}
            return {k: convert_value(k, v) for k, v in attrs_dict.items()}

        @staticmethod
        def dn_str(
            dn: str | m.Ldif.DN | m.Ldif.Entry | None, *, default: str = "unknown"
        ) -> str:
            """Extract DN string (builder: whn().safe().conv().str()).

            Uses advanced DSL: whn() → safe() → conv() → str() for fluent composition.

            Args:
                dn: DN object (can be None or have .value)
                default: Default if None

            Returns:
                str: DN string or default

            """
            if dn is None:
                return default
            if isinstance(dn, m.Ldif.DN):
                value = dn.value
                return value or default
            if isinstance(dn, str):
                return dn
            return str(dn.dn) if dn.dn else default

        @staticmethod
        def filter_truthy(
            value: list[object] | Mapping[str, object],
        ) -> list[object] | Mapping[str, object]:
            """Filter truthy values from list or dict.

            Args:
                value: List or dict to filter

            Returns:
                Filtered list or dict with only truthy values

            """
            if isinstance(value, Mapping):
                return {k: v for k, v in value.items() if v}
            return [item for item in value if item]

        @staticmethod
        def find_callable(
            callables_dict: Mapping[str, Callable[..., object]],
            *args: str | float | bool | None,
            **kwargs: str | float | bool | None,
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
                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    OSError,
                    RuntimeError,
                    ImportError,
                ) as e:
                    logger = logging.getLogger(__name__)
                    logger.debug(
                        "Callable %s raised exception, continuing", key, exc_info=e
                    )
                    continue
            return None

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
            normalized: list[str] = []
            for val in values:
                normalized_val = val
                if case == "lower":
                    normalized_val = val.lower()
                elif case == "upper":
                    normalized_val = val.upper()
                normalized.append(normalized_val)
            if join is not None:
                return join.join(normalized)
            return normalized

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
            if condition:
                if safe_then and then_value is None:
                    return else_value
                return then_value if then_value is not None else else_value
            return else_value

        Ldif: type[FlextLdifUtilities.Ldif] = FlextLdifUtilities.Ldif


__all__ = ["FlextLdapUtilities", "u"]

u = FlextLdapUtilities
