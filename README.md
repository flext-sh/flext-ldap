# FLEXT LDAP

Enterprise LDAP Operations Library built on FLEXT Core.

## Features

- 🚀 High-performance async operations
- 🔐 Enterprise security with TLS/SASL
- 📊 Built on FLEXT Core infrastructure
- 🎯 Type-safe with Python 3.13
- ⚡ Zero code duplication

## Installation

```bash
pip install flext-ldap
```

## Quick Start

```python
from flext_ldap import LDAPClient
from flext_core import Config

async with LDAPClient(Config.from_env()) as client:
    users = await client.search("(objectClass=person)")
    for user in users:
        print(user.dn, user.attributes)
```

## Documentation

See [docs.flext.sh/ldap](https://docs.flext.sh/ldap) for full documentation.

## License

MIT License - see LICENSE file for details.
