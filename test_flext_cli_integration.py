"""Exemplo de uso da biblioteca flext-cli integrada com flext-ldap.

Este script demonstra como usar a biblioteca flext-cli real para criar
comandos CLI no contexto do flext-ldap.
"""

import asyncio
import contextlib
from typing import Any

from flext_cli import (
    CLIContext,
    CLIExecutionContext,
    FlextResult,
    OutputFormat,
    cli_enhanced,
    cli_format_output,
    cli_validate_inputs,
    get_config,
)

# Importar do flext-ldap
from flext_ldap import FlextLdapCreateUserRequest, get_ldap_api


class FlextLdapCLI:
    """CLI integrada para operações LDAP usando flext-cli."""

    def __init__(self) -> None:
        self.config = get_config()
        self.ldap_api = get_ldap_api()
        self.context = CLIContext(
            config={"ldap_server": "localhost", "ldap_port": 389},
            debug=True,
            verbose=True,
        )

    @cli_enhanced
    @cli_validate_inputs
    async def list_users(
        self, base_dn: str = "ou=users,dc=example,dc=com",
    ) -> FlextResult[dict[str, Any]]:
        """Listar usuários LDAP usando flext-cli."""
        try:
            # Simulação de conexão LDAP (sem servidor real)
            execution_context = CLIExecutionContext(
                command_name="list_users",
                command_args={"base_dn": base_dn},
                config=self.context.config,
                debug=True,
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

            result = {
                "command": "list_users",
                "base_dn": base_dn,
                "users": users_data,
                "count": len(users_data),
                "execution_context": execution_context.get_execution_info(),
            }

            return FlextResult.ok(result)

        except Exception as e:
            return FlextResult.fail(f"Erro ao listar usuários: {e}")

    @cli_enhanced
    @cli_validate_inputs
    async def create_user(
        self, username: str, full_name: str, email: str,
    ) -> FlextResult[dict[str, Any]]:
        """Criar usuário LDAP usando flext-cli."""
        try:
            execution_context = CLIExecutionContext(
                command_name="create_user",
                command_args={
                    "username": username,
                    "full_name": full_name,
                    "email": email,
                },
                config=self.context.config,
                debug=True,
            )

            # Simulação de criação de usuário
            user_dn = f"cn={username},ou=users,dc=example,dc=com"

            # Usar FlextLdapCreateUserRequest para validação
            user_request = FlextLdapCreateUserRequest(
                dn=user_dn,
                uid=username,
                cn=full_name,
                sn=full_name.rsplit(maxsplit=1)[-1] if " " in full_name else full_name,
                mail=email,
            )

            result = {
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

            return FlextResult.ok(result)

        except Exception as e:
            return FlextResult.fail(f"Erro ao criar usuário: {e}")

    def format_and_display(
        self, data: Any, format_type: OutputFormat = OutputFormat.JSON,
    ) -> None:
        """Formatar e exibir dados usando flext-cli."""
        cli_format_output(data, format_type, indent=2)


async def main() -> None:
    """Função principal demonstrando uso da flext-cli."""
    # Inicializar CLI
    cli = FlextLdapCLI()

    # Teste 1: Listar usuários

    result = await cli.list_users("ou=users,dc=example,dc=com")
    if result.is_success:
        cli.format_and_display(result.data, OutputFormat.JSON)

    # Teste 2: Criar usuário

    result = await cli.create_user("testuser", "Test User", "test@example.com")
    if result.is_success:
        cli.format_and_display(result.data, OutputFormat.JSON)

    # Teste 3: Demonstrar configuração

    config_data = {
        "cli_config": {
            "debug": cli.context.debug,
            "verbose": cli.context.verbose,
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

    cli.format_and_display(config_data, OutputFormat.JSON)

    # Teste 4: Demonstrar diferentes formatos de output

    sample_data = {
        "biblioteca": "flext-cli",
        "versao": "1.0.0",
        "status": "funcionando",
        "recursos": ["CLI patterns", "Error handling", "Output formatting"],
    }

    cli.format_and_display(sample_data, OutputFormat.JSON)

    with contextlib.suppress(Exception):
        cli.format_and_display(sample_data, OutputFormat.TABLE)


if __name__ == "__main__":
    asyncio.run(main())
