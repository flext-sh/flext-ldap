# from flext-ldap_docs/guides/using-flext-tests.md:145
from flext_core import FlextSettings


def test_settings_override() -> None:
    FlextSettings.reset_for_testing()
    try:
        settings = FlextSettings.fetch_global()
        settings.debug = True
        assert settings.debug
    finally:
        FlextSettings.reset_for_testing()
