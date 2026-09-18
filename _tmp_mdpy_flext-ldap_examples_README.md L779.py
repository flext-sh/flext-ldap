# from flext-ldap/examples/README.md:779
from __future__ import annotations

from contextlib import contextmanager
from flext_ldap import ldap


@contextmanager
def ldap_connection():
    api = ldap(settings=...)
    connect_result = api.connect()
    if connect_result.is_failure:
        raise ConnectionError(connect_result.error)
    try:
        yield api
    finally:
        api.unbind()


# Usage
with ldap_connection() as api:
    result = api.search(...)
