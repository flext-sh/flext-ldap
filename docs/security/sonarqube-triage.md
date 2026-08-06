# Triagem SonarCloud — flext-sh/flext-ldap

Gerado do dump da plataforma SonarCloud (2026-08-06).

Bead de rastreio: `mro-2wjm.9`

## Resumo

**11 issues** — BLOCKER 0, CRITICAL 3, MAJOR 6, MINOR 2
Tipos: VULNERABILITY 4, BUG 0, CODE_SMELL 7

| regra | issues |
|---|---|
| `python:S3776` | 2 |
| `githubactions:S8233` | 2 |
| `python:S5778` | 2 |
| `python:S1192` | 1 |
| `githubactions:S8264` | 1 |
| `text:S8565` | 1 |
| `python:S7504` | 1 |
| `python:S116` | 1 |

## Issues

Coluna **Decisão**: `corrigir` / `falso-positivo` / `risco-aceito`.

| # | sev | tipo | regra | componente | linha | Decisão |
|---|---|---|---|---|---|---|
| 1 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldap/services/operations.py` | 151 | |
| 2 | CRITICAL | CODE_SMELL | `python:S3776` | `src/flext_ldap/services/operations.py` | 265 | |
| 3 | CRITICAL | CODE_SMELL | `python:S1192` | `src/flext_ldap/services/operations.py` | 579 | |
| 4 | MAJOR | VULNERABILITY | `githubactions:S8264` | `.github/workflows/docs.yml` | 18 | |
| 5 | MAJOR | VULNERABILITY | `githubactions:S8233` | `.github/workflows/docs.yml` | 19 | |
| 6 | MAJOR | VULNERABILITY | `githubactions:S8233` | `.github/workflows/docs.yml` | 20 | |
| 7 | MAJOR | VULNERABILITY | `text:S8565` | `pyproject.toml` | - | |
| 8 | MAJOR | CODE_SMELL | `python:S5778` | `tests/unit/test_config.py` | 77 | |
| 9 | MAJOR | CODE_SMELL | `python:S5778` | `tests/unit/test_sync.py` | 147 | |
| 10 | MINOR | CODE_SMELL | `python:S7504` | `conftest.py` | 20 | |
| 11 | MINOR | CODE_SMELL | `python:S116` | `src/flext_ldap/typings.py` | 18 | |

## Como triar

1. **BLOCKER e CRITICAL primeiro**, e todo VULNERABILITY independente de severidade.
2. Classificar: **corrigir**, **falso-positivo** (marcar na plataforma SonarCloud com justificativa), **risco-aceito** (com prazo).
3. CODE_SMELL em volume alto sugere padrão — corrigir a causa raiz, não issue a issue.

Dados brutos: `~/sonarqube-violations/by-repo/flext-sh__flext-ldap.json`

