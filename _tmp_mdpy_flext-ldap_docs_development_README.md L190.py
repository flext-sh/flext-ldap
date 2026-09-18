# from flext-ldap/docs/development/README.md:190
from __future__ import annotations
from flext_core import s


class MyService(s[None]):
    """Inherit from s to get mixins."""

    def operation(self):
        # ✅ Use inherited properties
        self.logger.info("message")  # From x
        timeout = self.settings.timeout  # From x
        service = self.container.resolve("service")  # From x```
### Pydantic v2 Models

