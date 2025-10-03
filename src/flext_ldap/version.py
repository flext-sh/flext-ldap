"""Version and package metadata for flext-ldap using importlib.metadata."""

from __future__ import annotations

from importlib.metadata import metadata

_metadata = metadata("flext-ldap")

__version__ = _metadata["Version"]
__version_info__ = tuple(
    int(part) if part.isdigit() else part for part in __version__.split(".")
)


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
    def current(cls) -> "FlextLdapVersion":
        """Return current version."""
        return cls(__version__, __version_info__)


VERSION = FlextLdapVersion.current()

__all__ = ["VERSION", "FlextLdapVersion", "__version__", "__version_info__"]
