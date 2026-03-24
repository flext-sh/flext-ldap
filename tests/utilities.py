from __future__ import annotations

from collections.abc import Sequence

from flext_tests import FlextTestsUtilities

from flext_ldap import FlextLdapUtilities
from tests import _DockerInfraUtils, _FixtureLoaderUtils, t

_SENTINEL = t.NormalizedValue()


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
            def that(
                value: t.NormalizedValue,
                *,
                eq: t.NormalizedValue = _SENTINEL,
                none: bool | t.NormalizedValue = _SENTINEL,
                is_: type | t.NormalizedValue = _SENTINEL,
                contains: t.NormalizedValue = _SENTINEL,
                attrs: Sequence[str] | t.NormalizedValue = _SENTINEL,
                keys: Sequence[str] | t.NormalizedValue = _SENTINEL,
                lacks_keys: Sequence[str] | t.NormalizedValue = _SENTINEL,
                kv: t.ContainerMapping | t.NormalizedValue = _SENTINEL,
                gte: float | t.NormalizedValue = _SENTINEL,
                lte: float | t.NormalizedValue = _SENTINEL,
                **kwargs: t.NormalizedValue,
            ) -> None:
                """Assert value matches expected conditions."""
                if eq is not _SENTINEL:
                    assert value == eq, f"Expected {eq!r}, got {value!r}"
                if none is not _SENTINEL:
                    if none is True:
                        assert value is None, f"Expected None, got {value!r}"
                    elif none is False:
                        assert value is not None, "Expected non-None value"
                if is_ is not _SENTINEL:
                    assert isinstance(
                        value,
                        is_,
                    ), f"Expected instance of {is_!r}, got {type(value)!r}"
                if contains is not _SENTINEL:
                    assert contains in value, (
                        f"Expected {value!r} to contain {contains!r}"
                    )
                if attrs is not _SENTINEL:
                    for attr_name in attrs:
                        assert hasattr(value, attr_name), (
                            f"Missing attribute: {attr_name}"
                        )
                if keys is not _SENTINEL:
                    for key in keys:
                        assert key in value, f"Missing key: {key}"
                if lacks_keys is not _SENTINEL:
                    for key in lacks_keys:
                        assert key not in value, f"Unexpected key: {key}"
                if kv is not _SENTINEL:
                    for k, v in kv.items():
                        actual = value[k]
                        assert actual == v, f"Key {k!r}: expected {v!r}, got {actual!r}"
                if gte is not _SENTINEL:
                    assert value >= gte, f"Expected >= {gte!r}, got {value!r}"
                if lte is not _SENTINEL:
                    assert value <= lte, f"Expected <= {lte!r}, got {value!r}"
                if "len" in kwargs:
                    expected_len = kwargs["len"]
                    actual_len = len(value)
                    assert actual_len == expected_len, (
                        f"Expected length {expected_len}, got {actual_len}"
                    )

            @staticmethod
            def ok(
                result: t.NormalizedValue, **kwargs: t.NormalizedValue
            ) -> t.NormalizedValue:
                """Assert result is success and return its value."""
                assert hasattr(result, "is_success"), (
                    "Expected a Result t.NormalizedValue"
                )
                assert result.is_success, (
                    f"Expected success, got failure: {getattr(result, 'error', 'unknown')}"
                )
                value = result.value
                if kwargs:
                    FlextLdapTestUtilities.Tests.Matchers.that(value, **kwargs)
                return value

            @staticmethod
            def fail(result: t.NormalizedValue, **kwargs: t.NormalizedValue) -> str:
                """Assert result is failure and return error string."""
                assert hasattr(result, "is_failure"), (
                    "Expected a Result t.NormalizedValue"
                )
                assert result.is_failure, "Expected failure, got success"
                error_str = str(result.error) if result.error else ""
                has_value = kwargs.get("has")
                if has_value is not None:
                    assert str(has_value).lower() in error_str.lower(), (
                        f"Expected error to contain {has_value!r}, got {error_str!r}"
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
