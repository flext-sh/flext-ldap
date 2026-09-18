# from flext-ldap_docs/development.md:364
from __future__ import annotations


@dataclass(frozen=True)
class DN:
    """RFC 4514 compliant Distinguished Name."""

    value: str

    def __post_init__(self) -> None:
        if not self._is_valid_dn():
            raise ValueError(f"Invalid DN: {self.value}")

    def _is_valid_dn(self) -> bool:
        # DN validation logic
        return bool(self.value and "=" in self.value and "," in self.value)```
______________________________________________________________________

## Code Quality Standards

### Type Safety Requirements

