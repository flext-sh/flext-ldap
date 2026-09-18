# from flext-ldap_docs/guides/using-flext-core.md:93
from flext_core import FlextContainer, p

container = FlextContainer()
container.bind("service", "ready")
resolved: p.Result[str] = container.resolve("service", type_cls=str)

assert resolved.success
assert resolved.value == "ready"
