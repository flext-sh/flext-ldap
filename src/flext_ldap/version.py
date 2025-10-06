"""Version and package metadata for flext-ldap using centralized constants."""

from __future__ import annotations

from importlib.metadata import metadata

from flext_ldap.constants import FlextLdapConstants

_metadata = metadata("flext-ldap")

# Use centralized constants - no module-level constants
__version__ = FlextLdapConstants.Version.get_version()
__version_info__ = FlextLdapConstants.Version.get_version_info()


class FlextLdapVersion:
    """Simple version class for flext-ldap with metadata access."""

    def __init__(self, version: str, version_info: tuple[int | str, ...]) -> None:
        self.version = version
        self.version_info = version_info
        # Extract metadata attributes
        self.project = _metadata.get("Name", "flext-ldap")
        self.author = _metadata.get("Author", "")
        self.maintainer = _metadata.get("Maintainer", "")
        self.urls = dict(_metadata.items()) if hasattr(_metadata, "items") else {}
        self.requires_python = _metadata.get("Requires-Python", "")

    @classmethod
    def current(cls) -> FlextLdapVersion:
        """Return current version."""
        return cls(__version__, __version_info__)


VERSION = FlextLdapVersion.current()

__all__ = ["VERSION", "FlextLdapVersion", "__version__", "__version_info__"]
