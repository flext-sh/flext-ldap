"""Exemplo de uso da biblioteca flext-cli integrada com flext-ldap.

Este script demonstra como usar a biblioteca flext-cli real para criar
comandos CLI no contexto do flext-ldap.
"""

import asyncio
import json

from flext_cli import (
    FlextCliConfig,
    FlextCliContext,
    FlextCliExecutionContext,
    FlextCliOutputFormat,
)
from flext_core import FlextResult, FlextTypes

from flext_ldap import FlextLDAPApi, FlextLDAPEntities


class FlextLDAPCLI:
    """CLI integrada para operações LDAP usando flext-cli."""

    def __init__(self) -> None:
        """Initialize the LDAP CLI with configuration and API."""
        self.config = FlextCliConfig()
        self.ldap_api = FlextLDAPApi()
        # Create CLI context with available parameters
        self.context: FlextCliContext = FlextCliContext()

    async def list_users(
        self,
        base_dn: str = "ou=users,dc=example,dc=com",
    ) -> FlextResult[FlextTypes.Core.Dict]:
        """Listar usuários LDAP usando flext-cli."""
        try:
            # Simulação de conexão LDAP (sem servidor real)
            execution_context = FlextCliExecutionContext(
                command_name="list_users",
                command_args={"base_dn": base_dn},
            )

            # Dados simulados de usuários
            users_data = [
                {
                    "dn": "cn=john,ou=users,dc=example,dc=com",
                    "cn": "John Doe",
                    "uid": "john",
                },
                {
                    "dn": "cn=jane,ou=users,dc=example,dc=com",
                    "cn": "Jane Smith",
                    "uid": "jane",
                },
                {
                    "dn": "cn=bob,ou=users,dc=example,dc=com",
                    "cn": "Bob Wilson",
                    "uid": "bob",
                },
            ]

            result: FlextTypes.Core.Dict = {
                "command": "list_users",
                "base_dn": base_dn,
                "users": users_data,
                "count": len(users_data),
                "execution_context": execution_context.get_execution_info(),
            }

            return FlextResult[FlextTypes.Core.Dict].ok(result)

        except Exception as e:
            return FlextResult[FlextTypes.Core.Dict].fail(
                f"Erro ao listar usuários: {e}"
            )

    async def create_user(
        self,
        username: str,
        full_name: str,
        email: str,
    ) -> FlextResult[FlextTypes.Core.Dict]:
        """Criar usuário LDAP usando flext-cli."""
        try:
            execution_context = FlextCliExecutionContext(
                command_name="create_user",
                command_args={
                    "username": username,
                    "full_name": full_name,
                    "email": email,
                },
            )

            # Simulação de criação de usuário
            user_dn = f"cn={username},ou=users,dc=example,dc=com"

            # Usar FlextLDAPCreateUserRequest para validação
            user_request = FlextLDAPEntities.CreateUserRequest(
                dn=user_dn,
                uid=username,
                cn=full_name,
                sn=full_name.rsplit(maxsplit=1)[-1] if " " in full_name else full_name,
                given_name=full_name.split(maxsplit=1)[0]
                if " " in full_name
                else full_name,
                mail=email,
                # Note: phone field removed - not available in CreateUserRequest
            )

            result: FlextTypes.Core.Dict = {
                "command": "create_user",
                "user_dn": user_dn,
                "username": username,
                "full_name": full_name,
                "email": email,
                "user_request": {
                    "dn": user_request.dn,
                    "uid": user_request.uid,
                    "cn": user_request.cn,
                    "sn": user_request.sn,
                    "mail": user_request.mail,
                },
                "execution_context": execution_context.get_execution_info(),
            }

            return FlextResult[FlextTypes.Core.Dict].ok(result)

        except Exception as e:
            return FlextResult[FlextTypes.Core.Dict].fail(f"Erro ao criar usuário: {e}")


class FlextLDAPApiExample:
    """Exemplo básico de integração com flext-cli."""

    def format_and_display(
        self,
        data: FlextTypes.Core.Dict | FlextTypes.Core.List | object,
        format_type: str = "json",
    ) -> None:
        """Formatar e exibir dados usando flext-cli."""
        # Use basic JSON formatting since flext_cli_format is not available
        if format_type == "json":
            try:
                print(json.dumps(data, indent=2, ensure_ascii=False))
            except (TypeError, ValueError):
                print(str(data))
        else:
            print(str(data))


async def main() -> None:
    """Função principal demonstrando uso da flext-cli."""
    # Inicializar CLI
    cli = FlextLDAPCLI()

    # Teste 1: Listar usuários

    result = await cli.list_users(base_dn="ou=users,dc=example,dc=com")
    # Use explicit success check with proper typing
    if result.is_success:
        empty_data: FlextTypes.Core.Dict = {}
        data = result.unwrap_or(empty_data)
        if data:
            cli.format_and_display(data, "json")

    # Teste 2: Criar usuário

    result = await cli.create_user(
        username="testuser", full_name="Test User", email="test@example.com"
    )
    # Use explicit success check with proper typing
    if result.is_success:
        empty_create_data: FlextTypes.Core.Dict = {}
        data = result.unwrap_or(empty_create_data)
        if data:
            cli.format_and_display(data, "json")

    # Teste 3: Demonstrar configuração

    config_data: FlextTypes.Core.Dict = {
        "cli_config": {
            "debug": getattr(cli.context, "is_debug", False),
            "verbose": getattr(cli.context, "is_verbose", False),
            "ldap_config": cli.context.config,
        },
        "flext_cli_features": [
            "FlextResult pattern para error handling",
            "Decoradores para validação e melhorias",
            "Formatação automática de output",
            "Contexto de execução para tracking",
            "Integração com flext-core patterns",
        ],
    }

    cli.format_and_display(config_data, FlextCliOutputFormat.JSON)

    # Teste 4: Demonstrar diferentes formatos de output

    sample_data: FlextTypes.Core.Dict = {
        "biblioteca": "flext-cli",
        "versao": "1.0.0",
        "status": "funcionando",
        "recursos": ["CLI patterns", "Error handling", "Output formatting"],
    }

    cli.format_and_display(sample_data, FlextCliOutputFormat.JSON)

    # Table format not available, using JSON
    cli.format_and_display(sample_data, "json")


if __name__ == "__main__":
    asyncio.run(main())
