# from flext-ldap_docs/guides/using-flext-core.md:83
from flext_core import FlextSettings, m


class GreetingSettings(FlextSettings):
    model_config = m.SettingsConfigDict(env_prefix="GREETING_", extra="forbid")
