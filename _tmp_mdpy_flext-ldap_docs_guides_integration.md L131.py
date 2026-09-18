# from flext-ldap/docs/guides/integration.md:131
from __future__ import annotations

# Environment-based configuration following FLEXT patterns
from Flext_ldap import FlextLdapSettings
from pydantic import BaseSettings


class AppSettings(BaseSettings):
    """Application settings with LDAP configuration."""

    # LDAP connection settings
    ldap_host: str = "ldap.example.com"
    ldap_port: int = 636
    ldap_use_ssl: bool = True
    ldap_bind_dn: str = "cn=service,dc=example,dc=com"
    ldap_bind_password: str = ""
    ldap_base_dn: str = "dc=example,dc=com"

    # Application settings
    app_name: str = "flext-app"
    debug: bool = False

    def get_ldap_config(self) -> FlextLdapSettings:
        """Create LDAP configuration from app settings."""
        return FlextLdapSettings(
            host=self.ldap_host,
            port=self.ldap_port,
            use_ssl=self.ldap_use_ssl,
            bind_dn=self.ldap_bind_dn,
            bind_password=self.ldap_bind_password,
            base_dn=self.ldap_base_dn,
        )


# Usage in FLEXT applications
settings = AppSettings()
ldap_config = settings.get_ldap_config()```
______________________________________________________________________

## FastAPI Integration

### API Endpoints with LDAP Authentication

