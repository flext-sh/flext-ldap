from __future__ import annotations

from collections.abc import Mapping, Sequence, Sized
from typing import TypeGuard

from flext_core import r
from flext_tests import FlextTestsUtilities

from flext_ldap import FlextLdapUtilities
from tests import t
from tests._utilities.docker_infra import _DockerInfraUtils
from tests._utilities.fixture_loaders import _FixtureLoaderUtils


class FlextLdapTestUtilities(FlextTestsUtilities, FlextLdapUtilities):
    """Utilities for flext-ldap tests - extends FlextTestsUtilities and FlextLdapUtilities.

    Architecture: Extends both FlextTestsUtilities and FlextLdapUtilities with flext-ldap-specific utility methods.
    All generic utilities from FlextTestsUtilities and production utilities from FlextLdapUtilities are available through inheritance.

    Rules:
    - NEVER redeclare utilities from FlextTestsUtilities or FlextLdapUtilities
    - Only flext-ldap-specific utilities allowed
    - All generic utilities come from FlextTestsUtilities
    - All production utilities come from FlextLdapUtilities
    """

    class Tests(FlextTestsUtilities.Tests):
        """Test utilities with Matchers support."""

        class Matchers:
            """Assertion matchers for test readability."""

            @staticmethod
            def _is_mapping(value: t.NormalizedValue) -> TypeGuard[t.ContainerMapping]:
                """Return whether value supports mapping-style access."""
                return isinstance(value, Mapping)

            @staticmethod
            def _is_numeric(value: t.NormalizedValue) -> TypeGuard[int | float]:
                """Return whether value is a numeric scalar excluding bool."""
                return isinstance(value, int | float) and not isinstance(value, bool)

            @staticmethod
            def _is_sized(value: t.NormalizedValue) -> TypeGuard[Sized]:
                """Return whether value supports len()."""
                return isinstance(value, Sized)

            @staticmethod
            def _is_str_sequence(value: t.NormalizedValue) -> TypeGuard[t.StrSequence]:
                """Return whether value is a non-string sequence of strings."""
                if isinstance(value, str) or not isinstance(value, Sequence):
                    return False
                return all(isinstance(item, str) for item in value)

            @staticmethod
            def that(
                value: t.NormalizedValue,
                *,
                eq: t.NormalizedValue | None = None,
                none: bool | None = None,
                is_: type | None = None,
                contains: t.NormalizedValue | None = None,
                attrs: t.StrSequence | None = None,
                keys: t.StrSequence | None = None,
                lacks_keys: t.StrSequence | None = None,
                kv: t.ContainerMapping | None = None,
                gte: float | None = None,
                lte: float | None = None,
                **kwargs: t.NormalizedValue,
            ) -> None:
                """Assert value matches expected conditions."""
                if eq is not None:
                    assert value == eq, f"Expected {eq!r}, got {value!r}"
                if none is not None:
                    if none is True:
                        assert value is None, f"Expected None, got {value!r}"
                    else:
                        assert value is not None, "Expected non-None value"
                if is_ is not None:
                    assert isinstance(value, is_), (
                        f"Expected instance of {is_!r}, got {type(value)!r}"
                    )
                if contains is not None:
                    if isinstance(value, str):
                        assert isinstance(contains, str), (
                            "String containment expects a string search value"
                        )
                        assert contains in value, (
                            f"Expected {value!r} to contain {contains!r}"
                        )
                    elif FlextLdapTestUtilities.Tests.Matchers._is_mapping(value):
                        assert isinstance(contains, str), (
                            "Mapping containment expects a string key"
                        )
                        assert contains in value, (
                            f"Expected {value!r} to contain key {contains!r}"
                        )
                    elif isinstance(value, Sequence):
                        assert contains in value, (
                            f"Expected {value!r} to contain {contains!r}"
                        )
                    else:
                        raise AssertionError(
                            f"Value {value!r} does not support containment check"
                        )
                if attrs is not None:
                    for attr_name in attrs:
                        assert hasattr(value, attr_name), (
                            f"Missing attribute: {attr_name}"
                        )
                if keys is not None:
                    assert FlextLdapTestUtilities.Tests.Matchers._is_mapping(value), (
                        f"Value {value!r} does not support key lookup"
                    )
                    for key in keys:
                        assert key in value, f"Missing key: {key}"
                if lacks_keys is not None:
                    assert FlextLdapTestUtilities.Tests.Matchers._is_mapping(value), (
                        f"Value {value!r} does not support key lookup"
                    )
                    for key in lacks_keys:
                        assert key not in value, f"Unexpected key: {key}"
                if kv is not None:
                    assert FlextLdapTestUtilities.Tests.Matchers._is_mapping(value), (
                        f"Value {value!r} does not support key lookup"
                    )
                    for key, expected_value in kv.items():
                        actual = value[key]
                        assert actual == expected_value, (
                            f"Key {key!r}: expected {expected_value!r}, got {actual!r}"
                        )
                if gte is not None:
                    assert FlextLdapTestUtilities.Tests.Matchers._is_numeric(value), (
                        f"Expected numeric value for gte comparison, got {value!r}"
                    )
                    assert value >= gte, f"Expected >= {gte!r}, got {value!r}"
                if lte is not None:
                    assert FlextLdapTestUtilities.Tests.Matchers._is_numeric(value), (
                        f"Expected numeric value for lte comparison, got {value!r}"
                    )
                    assert value <= lte, f"Expected <= {lte!r}, got {value!r}"
                if "len" in kwargs:
                    expected_len = kwargs["len"]
                    assert isinstance(expected_len, int) and not isinstance(
                        expected_len,
                        bool,
                    ), "len expectation must be an integer"
                    assert FlextLdapTestUtilities.Tests.Matchers._is_sized(value), (
                        f"Value {value!r} does not support len()"
                    )
                    actual_len = len(value)
                    assert actual_len == expected_len, (
                        f"Expected length {expected_len}, got {actual_len}"
                    )

            @staticmethod
            def ok(
                result: r[t.NormalizedValue],
                *,
                eq: t.NormalizedValue | None = None,
                expected_len: int | None = None,
            ) -> t.NormalizedValue:
                """Assert result is success and return its value."""
                assert hasattr(result, "is_success"), (
                    "Expected a Result t.NormalizedValue"
                )
                assert result.is_success, (
                    f"Expected success, got failure: {getattr(result, 'error', 'unknown')}"
                )
                value = result.value
                if expected_len is not None:
                    FlextLdapTestUtilities.Tests.Matchers.that(value, len=expected_len)
                if eq is not None:
                    FlextLdapTestUtilities.Tests.Matchers.that(value, eq=eq)
                return value

            @staticmethod
            def fail(
                result: r[t.NormalizedValue],
                *,
                has: t.NormalizedValue | None = None,
            ) -> str:
                """Assert result is failure and return error string."""
                assert hasattr(result, "is_failure"), (
                    "Expected a Result t.NormalizedValue"
                )
                assert result.is_failure, "Expected failure, got success"
                error_str = str(result.error) if result.error else ""
                if has is not None:
                    assert str(has).lower() in error_str.lower(), (
                        f"Expected error to contain {has!r}, got {error_str!r}"
                    )
                return error_str

    class Ldap(FlextLdapUtilities.Ldap):
        """LDAP test utilities."""

        class Tests(_DockerInfraUtils, _FixtureLoaderUtils):
            """flext-ldap-specific test utilities namespace.

            Composed via MRO from:
            - _DockerInfraUtils: FileLock, DNSTracker, get_docker_control,
              get_admin_credentials, ensure_basic_ldap_structure
            - _FixtureLoaderUtils: Fixtures (load_json, load_ldif, etc.)

            Access: u.Ldap.Tests.*
            """


u = FlextLdapTestUtilities

__all__ = ["FlextLdapTestUtilities", "u"]
