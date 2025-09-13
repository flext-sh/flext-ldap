# flext-ldap

**Tipo**: Biblioteca de Infraestrutura | **Status**: Em desenvolvimento ativo | **Dependências**: flext-core, ldap3, pydantic, click, rich, structlog

Biblioteca de operações LDAP com Clean Architecture e DDD, oferecendo serviços de diretório com tratamento de erros tipo-safe via FlextResult.

---

## 🚀 Instalação

Pré-requisitos:

- Python 3.13+
- Poetry
- Acesso a um servidor LDAP (ou Docker para desenvolvimento)

Configuração:

```bash
git clone <repository-url>
cd flext-ldap
poetry install
make setup
```

## 🔧 Uso básico (assíncrono)

```python
import asyncio
from flext_ldap.services import FlextLDAPService
from flext_ldap.models import FlextLDAPCreateUserRequest

async def main() -> None:
    service = FlextLDAPService()
    ok = await service.connect(
        server_url="ldap://localhost:3389",
        bind_dn="cn=admin,dc=example,dc=com",
        bind_password="admin",
    )
    if ok.is_failure:
        raise SystemExit(f"Falha na conexão: {ok.error}")

    req = FlextLDAPCreateUserRequest(
        dn="cn=jane.doe,ou=users,dc=example,dc=com",
        uid="jane.doe",
        cn="Jane",
        sn="Doe",
        mail="jane.doe@example.com",
    )
    created = await service.create_user(req)
    print(created)

asyncio.run(main())
```

Observação: a API de serviços é assíncrona (conforme `src/flext_ldap/services.py`).

## 🏛️ Estrutura real do projeto

```
src/flext_ldap/
├── api.py                  # API de alto nível
├── services.py             # Serviços de aplicação (assíncronos)
├── adapters.py             # Adapters/ports para operações de diretório
├── operations.py           # Operações LDAP de baixo nível
├── models.py               # Entidades/Value Objects (pydantic)
├── config.py               # Configuração e validação
├── constants.py | types.py | utils.py | exceptions.py
└── cli.py                  # CLI (entrypoint: flext-ldap)
```

Padrões-chave: FlextResult, FlextDomainService, Clean Architecture, DDD.

## ⚙️ Configuração por ambiente

```bash
# Configuração básica LDAP
FLEXT_LDAP_HOST=localhost
FLEXT_LDAP_PORT=389
FLEXT_LDAP_USE_SSL=false
FLEXT_LDAP_BASE_DN=dc=example,dc=com
FLEXT_LDAP_BIND_DN=cn=admin,dc=example,dc=com
FLEXT_LDAP_BIND_PASSWORD=admin

# Opções
FLEXT_LDAP_TIMEOUT=30
FLEXT_LOG_LEVEL=INFO
```

## 📦 Dependências principais

- `ldap3` (operações LDAP reais)
- `pydantic` e `pydantic-settings`
- `click` e `rich` (CLI/UX)
- `structlog` (observabilidade)
- Integrações locais opcionais: `flext-core`, `flext-ldif`

## 🧪 Desenvolvimento

```bash
make lint         # Lint
make type-check
make test         # Testes
make validate     # Pipeline completo
```

## 📄 Licença

MIT License — veja `LICENSE`.

## 🔗 Projetos relacionados

- `../flext-core`
- `../flext-ldif`
