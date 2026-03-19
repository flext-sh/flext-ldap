from __future__ import annotations

from typing import override

import pytest
from flext_core import FlextService, FlextSettings, r

from flext_ldap import FlextLdapServiceBase, base, s
from tests import p

pytestmark = pytest.mark.unit


class _SuccessService(FlextLdapServiceBase[str]):
    @override
    def execute(self) -> r[str]:
        return r[str].ok("ok")


class _FailService(FlextLdapServiceBase[str]):
    @override
    def execute(self) -> r[str]:
        return r[str].fail("nope")


class _BoolService(FlextLdapServiceBase[bool]):
    @override
    def execute(self) -> r[bool]:
        return r[bool].ok(True)


class _IntService(FlextLdapServiceBase[int]):
    @override
    def execute(self) -> r[int]:
        return r[int].ok(42)


class TestsFlextLdapBase:
    # ── Structure & exports ────────────────────────────────────────────

    def test_class_inherits_flext_service(self) -> None:
        assert issubclass(FlextLdapServiceBase[str], FlextService)
        assert hasattr(FlextLdapServiceBase, "__class_getitem__")

    def test_exports(self) -> None:
        assert s is FlextLdapServiceBase
        assert "FlextLdapServiceBase" in base.__all__
        assert "s" in base.__all__

    def test_has_docstring(self) -> None:
        assert FlextLdapServiceBase.__doc__ is not None
        assert "config" in FlextLdapServiceBase.__doc__.lower()

    # ── Execute: success + failure ─────────────────────────────────────

    def test_execute_success(self) -> None:
        result = _SuccessService().execute()
        assert result.is_success
        assert result.value == "ok"

    def test_execute_failure(self) -> None:
        result = _FailService().execute()
        assert result.is_failure
        assert result.error == "nope"

    # ── Type parameters ────────────────────────────────────────────────

    _TYPE_SERVICES = [
        ("str", _SuccessService, "ok"),
        ("bool", _BoolService, True),
        ("int", _IntService, 42),
    ]

    @pytest.mark.parametrize(
        ("label", "cls", "expected"), _TYPE_SERVICES, ids=[x[0] for x in _TYPE_SERVICES]
    )
    def test_type_parameter(
        self, label: str, cls: type, expected: str | bool | int
    ) -> None:
        result = cls().execute()
        assert result.is_success
        assert result.value == expected

    # ── Config + Logger ────────────────────────────────────────────────

    def test_config_property(self) -> None:
        svc = _SuccessService()
        assert hasattr(svc, "config")
        assert isinstance(svc.config, p.Settings)

    def test_config_matches_global(self) -> None:
        cfg = _SuccessService().config
        glob = FlextSettings.get_global()
        assert cfg.app_name == glob.app_name
        assert cfg.version == glob.version

    def test_logger_property(self) -> None:
        assert _SuccessService().logger is not None

    # ── Model config inheritance ───────────────────────────────────────

    _MODEL_CONFIG = [
        ("arbitrary_types_allowed", True),
        ("extra", "forbid"),
        ("use_enum_values", True),
        ("validate_assignment", True),
    ]

    @pytest.mark.parametrize(
        ("attr", "expected"), _MODEL_CONFIG, ids=[x[0] for x in _MODEL_CONFIG]
    )
    def test_model_config(self, attr: str, expected: str | bool) -> None:
        assert _SuccessService.model_config.get(attr) == expected

    # ── Independence ───────────────────────────────────────────────────

    def test_multiple_services_independent(self) -> None:
        a, b = _SuccessService(), _FailService()
        assert a.execute().is_success
        assert b.execute().is_failure
        assert a.execute().value == "ok"
        assert b.execute().error == "nope"
