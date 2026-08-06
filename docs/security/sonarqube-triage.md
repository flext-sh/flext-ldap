# Triagem SonarCloud — flext-sh/flext-ldap

Gerado do dump da plataforma SonarCloud (2026-08-06).

Bead: `mro-2wjm.9`

## Resumo

**11 issues** — BLOCKER 0, CRITICAL 3, MAJOR 6, MINOR 2
Tipos: VULNERABILITY 4, BUG 0, CODE_SMELL 7 · **Debt total: 65min**

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

## Como usar

Cada issue traz a **mensagem do SonarQube** (descreve o problema e o impacto), o **código real** (linha `>>>`), o tipo e o effort estimado.
**Decisão**: `corrigir` / `falso-positivo` (marcar na plataforma com justificativa) / `risco-aceito`. Ordem: BLOCKER → CRITICAL → VULNERABILITY → MAJOR. CODE_SMELL em volume pede correção de padrão.

## Issues

### 1 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldap/services/operations.py:151` · **Effort**: 13min

> Refactor this function to reduce its Cognitive Complexity from 23 to the 15 allowed.

```python
      147              if changetype == c.Ldif.LdifChangeType.MODIFY:
      148                  return self.handle_schema_modify(entry)
      149              return self.handle_regular_add(entry)
      150  
>>>   151          def handle_existing_entry(
      152              self, entry: p.Ldif.Entry
      153          ) -> p.Result[m.Ldap.LdapOperationResult]:
      154              """Handle an upsert when the entry already exists in LDAP.
      155  
```

**Decisão**: 

### 2 · 🟠 CRITICAL · CODE_SMELL · `python:S3776`
**Local**: `src/flext_ldap/services/operations.py:265` · **Effort**: 9min

> Refactor this function to reduce its Cognitive Complexity from 19 to the 15 allowed.

```python
      261                      )
      262                  )
      263              )
      264  
>>>   265          def handle_schema_modify(
      266              self, entry: p.Ldif.Entry
      267          ) -> p.Result[m.Ldap.LdapOperationResult]:
      268              """Apply a schema modification entry (supports multiple add operations).
      269  
```

**Decisão**: 

### 3 · 🟠 CRITICAL · CODE_SMELL · `python:S1192`
**Local**: `src/flext_ldap/services/operations.py:579` · **Effort**: 6min

> Define a constant instead of duplicating this literal "Unknown error" 3 times.

```python
      575          dn_model: m.Ldif.DN = dn_build.unwrap()
      576          result = self._ensure_adapter().delete(dn_model)
      577          folded: p.Result[m.Ldap.OperationResult] = result.fold(
      578              on_failure=lambda e: r[m.Ldap.OperationResult].fail(
>>>   579                  u.to_str(e, default="Unknown error")
      580              ),
      581              on_success=r[m.Ldap.OperationResult].ok,
      582          )
      583          return folded
```

**Decisão**: 

### 4 · 🟡 MAJOR · VULNERABILITY · `githubactions:S8264`
**Local**: `.github/workflows/docs.yml:18` · **Effort**: 5min

> Move this read permission from workflow level to job level.

```yaml
       14        - ".github/workflows/docs.yml"
       15    workflow_dispatch:
       16  
       17  permissions:
>>>    18    contents: read
       19    pages: write
       20    id-token: write
       21  
       22  concurrency:
```

**Decisão**: 

### 5 · 🟡 MAJOR · VULNERABILITY · `githubactions:S8233`
**Local**: `.github/workflows/docs.yml:19` · **Effort**: 5min

> Move this write permission from workflow level to job level.

```yaml
       15    workflow_dispatch:
       16  
       17  permissions:
       18    contents: read
>>>    19    pages: write
       20    id-token: write
       21  
       22  concurrency:
       23    group: pages
```

**Decisão**: 

### 6 · 🟡 MAJOR · VULNERABILITY · `githubactions:S8233`
**Local**: `.github/workflows/docs.yml:20` · **Effort**: 5min

> Move this write permission from workflow level to job level.

```yaml
       16  
       17  permissions:
       18    contents: read
       19    pages: write
>>>    20    id-token: write
       21  
       22  concurrency:
       23    group: pages
       24    cancel-in-progress: false
```

**Decisão**: 

### 7 · 🟡 MAJOR · VULNERABILITY · `text:S8565`
**Local**: `pyproject.toml:-` · **Effort**: 5min

> Dependency versions are not predictable if the lock file (uv.lock, poetry.lock, pdm.lock or pylock.toml) is missing.


**Decisão**: 

### 8 · 🟡 MAJOR · CODE_SMELL · `python:S5778`
**Local**: `tests/unit/test_config.py:77` · **Effort**: 5min

> Refactor this exception test to have only one invocation possibly throwing an exception.

```python
       73  
       74      @pytest.mark.parametrize("port", [0, -1, 65536, 70000, 999999])
       75      def test_out_of_range_port_is_rejected(self, port: int) -> None:
       76          """Verify out of range port is rejected."""
>>>    77          with pytest.raises(c.ValidationError):
       78              LdapTestSettings(Ldap=_LdapSettings(port=port))
       79  
       80      # ── Host values ────────────────────────────────────────────────────
       81  
```

**Decisão**: 

### 9 · 🟡 MAJOR · CODE_SMELL · `python:S5778`
**Local**: `tests/unit/test_sync.py:147` · **Effort**: 5min

> Refactor this exception test to have only one invocation possibly throwing an exception.

```python
      143          ldif_file.write_text(
      144              c.Ldap.Tests.SYNC_FACADE_SINGLE_ENTRY_LDIF, encoding="utf-8"
      145          )
      146          # Act / Assert: an unsupported arity is a contract violation, not a failure result
>>>   147          with pytest.raises(TypeError, match="single-phase"):
      148              ldap.sync_phase_entries(
      149                  ldif_file,
      150                  c.Ldap.Tests.SYNC_FACADE_PHASE_NAME_USERS,
      151                  settings=m.Ldap.SyncPhaseConfig(
```

**Decisão**: 

### 10 · ⚪ MINOR · CODE_SMELL · `python:S7504`
**Local**: `conftest.py:20` · **Effort**: 5min

> Remove this unnecessary `list()` call on an already iterable object.

```python
       16      if (
       17          existing_package is None
       18          or Path(getattr(existing_package, "__file__", "")).resolve() != init_file
       19      ):
>>>    20          for module_name in list(sys.modules):
       21              if module_name == package_name or module_name.startswith(
       22                  f"{package_name}."
       23              ):
       24                  sys.modules.pop(module_name, None)
```

**Decisão**: 

### 11 · ⚪ MINOR · CODE_SMELL · `python:S116`
**Local**: `src/flext_ldap/typings.py:18` · **Effort**: 2min

> Rename this field "LDAPException" to match the regular expression ^[_a-z][_a-z0-9]*$.

```python
       14  
       15      class Ldap:
       16          """LDAP type aliases."""
       17  
>>>    18          LDAPException: type[Exception] = _Ldap3LDAPException
       19  
       20          type Ldap3AttributeScalar = str | bytes
       21          type Ldap3AttributeValues = t.SequenceOf[Ldap3AttributeScalar]
       22          type Ldap3AttributeDict = t.MappingKV[str, Ldap3AttributeValues]
```

**Decisão**: 

