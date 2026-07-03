# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports
from flext_ldap.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)
from flext_ldap._exports import (
    FLEXT_LDAP_LAZY_IMPORTS,
    FLEXT_LDAP_PUBLIC_EXPORTS,
)

_LAZY_IMPORTS = {
    name: target
    for name, target in FLEXT_LDAP_LAZY_IMPORTS.items()
    if name in FLEXT_LDAP_PUBLIC_EXPORTS
}


_EAGER_EXPORTS = (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)


_PUBLIC_EXPORTS: tuple[str, ...] = FLEXT_LDAP_PUBLIC_EXPORTS


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    public_exports=_PUBLIC_EXPORTS,
)
