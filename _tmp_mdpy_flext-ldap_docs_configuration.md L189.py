# from flext-ldap/docs/configuration.md:189
from __future__ import annotations

import os
from Flext_ldap import FlextLdapSettings


def get_config() -> FlextLdapSettings:
    """Get configuration based on environment."""
    env = os.getenv("FLEXT_ENV", "development")

    if env == "production":
        return PRODUCTION_CONFIG
    if env == "staging":
        return STAGING_CONFIG
    return DEVELOPMENT_CONFIG


# Usage
settings = get_config()```
______________________________________________________________________

## Docker Configuration

### Environment File

Create `.env` file:

