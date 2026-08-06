# AGENTS.md — flext-ldap

> **Parent workspace law** lives in [`../AGENTS.md`](../AGENTS.md) — read it first.
> Universal engineering core: `~/.agents/UNIVERSAL_CORE.md`. Composition: global skills + parent/root `AGENTS.md` + this scope delta. Do not re-embed universal law.
>
> **Standalone / independent mode:** when `../AGENTS.md` does not resolve, pin the parent raw `AGENTS.md` URL to the same branch/release as this package (never `main`).

<!-- AIHUB-AGENTS-SCOPE-LOCAL-BEGIN -->
**Package:** `flext_ldap` · deps: `flext-cli`, `flext-core`, `flext-ldif`

## Overview

Enterprise LDAP operations library. Base for the LDAP Singer connectors (`flext-tap-ldap`, `flext-target-ldap`, `flext-dbt-ldap`).

## Structure

```text
src/flext_ldap/
├── api.py            # FlextLdap facade, composed from FlextLdapConnection + FlextLdapSync + FlextLdapApiRuntime
├── base.py
├── adapters/         # LDAP adapter implementations
├── services/         # connection / runtime / synchronization services
├── constants.py typings.py protocols.py models.py utilities.py   # AUTO-GENERATED facets
└── _constants? _models/ _utilities/                              # private impl
```

## Code Map

| Symbol | Kind | Location | Role |
|--------|------|----------|------|
| `FlextLdap` | class | `api.py` | facade (connection + sync + runtime) |
| `FlextLdapConnection` | class | adapters/services | connection lifecycle |
| `FlextLdapSync` | class | services | directory synchronization |

## Anti-Patterns / Gotchas

- **Use the `FlextLdap` facade** — do not reach into `adapters/` or `services/` internals directly.
- LDIF parsing/serialization is delegated to `flext-ldif` (registry-selected dialects), not reimplemented here.

## Conventions (specific to this package)

- Config/settings canonical pattern: ADR-012.
- Codemod governance (ast-grep + make mod): ADR-014.

## Commands

```bash
make check PROJECT=flext-ldap
make test  PROJECT=flext-ldap       # tests/{unit,integration,fixtures}
```
<!-- AIHUB-AGENTS-SCOPE-LOCAL-END -->
