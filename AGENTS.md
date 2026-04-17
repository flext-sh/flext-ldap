# CLAUDE

Project-level pointer file.

**See [../AGENTS.md](../AGENTS.md) for full workspace standards.**

## Zero Tolerance Rules (Completely Prohibited)

1. **Hacks**: ❌ PROHIBITED - `model_rebuild()`, `eval()`, `exec()`, and architectural `getattr()`.
1. **Inline/Lazy Imports**: ❌ PROHIBITED - No imports inside functions or `try/except ImportError:`.
1. **# type: ignore**: ❌ PROHIBITED COMPLETELY - Zero tolerance, no exceptions
1. **Root Aliases**: ❌ PROHIBITED COMPLETELY - Always use complete namespace.
1. **cast()**: ❌ PROHIBITED - Replace with Models/Protocols/TypeGuards
1. **Any**: ❌ PROHIBITED - Replace with specific types.
