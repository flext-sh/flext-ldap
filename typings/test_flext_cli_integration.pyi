from typing import Any

from _typeshed import Incomplete
from flext_cli import FlextResult, OutputFormat, cli_enhanced, cli_validate_inputs

class FlextLdapCLI:
    config: Incomplete
    ldap_api: Incomplete
    context: Incomplete
    def __init__(self) -> None: ...
    @cli_enhanced
    @cli_validate_inputs
    async def list_users(
        self, base_dn: str = "ou=users,dc=example,dc=com"
    ) -> FlextResult[dict[str, Any]]: ...
    @cli_enhanced
    @cli_validate_inputs
    async def create_user(
        self, username: str, full_name: str, email: str
    ) -> FlextResult[dict[str, Any]]: ...
    def format_and_display(
        self,
        data: dict[str, object] | list[object] | object,
        format_type: OutputFormat = ...,
    ) -> None: ...

async def main() -> None: ...
