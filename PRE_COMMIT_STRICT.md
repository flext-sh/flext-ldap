# 🔒 ULTRA-STRICT PRE-COMMIT CONFIGURATION

## Overview

This project uses an **ULTRA-STRICT** pre-commit configuration with **ZERO TOLERANCE** for code quality issues.

## 🛡️ Enforced Standards

### Python Code Quality Tools

1. **Black** - Code formatting (fail on any deviation)
2. **isort** - Import sorting (fail on any disorder)
3. **Ruff** - ALL rules enabled with preview features
4. **MyPy** - Maximum strictness type checking
5. **Pylint** - Perfect 10.0/10 score required
6. **Bandit** - Security scanning (LOW severity threshold)
7. **Flake8** - PEP8 compliance with all plugins
8. **Pycodestyle** - Additional PEP8 validation
9. **Pydocstyle** - Google docstring convention
10. **Vulture** - Dead code detection (70% confidence)
11. **McCabe** - Complexity checking (max 10)

### Additional Checks

- **Trailing whitespace** removal
- **End of file** fixing
- **YAML/JSON/TOML** validation
- **Large file** prevention (100KB max)
- **Case conflicts** detection
- **Merge conflicts** detection
- **Debug statements** detection
- **Private keys** detection
- **Mixed line endings** fixing
- **Test naming** conventions
- **License headers** enforcement
- **Markdown linting**
- **Python syntax upgrade** to 3.13+

## 🚨 Configuration Features

### Fail Fast Mode

All hooks are configured with `fail_fast: true` - the first failure stops all checks.

### No Auto-Fix

Most tools are configured with `--no-fix` or `--check` flags - you must fix issues manually.

### Maximum Severity

- Ruff: `--select=ALL` (every single rule)
- MyPy: `--strict` with additional restrictions
- Pylint: `--enable=all` with 10.0/10 required
- Bandit: `--severity-level=low` (catches everything)

## 💯 Usage

### Install Pre-commit Hooks

```bash
poetry run pre-commit install
```

### Run All Checks

```bash
poetry run pre-commit run --all-files
```

### Run Specific Check

```bash
poetry run pre-commit run <hook-id> --all-files
```

## 🎯 Expected Results

With this configuration, your code must be:

- **100% type safe**
- **100% PEP8 compliant**
- **100% secure** (no security warnings)
- **100% formatted** correctly
- **100% documented** (all public APIs)
- **0% dead code**
- **Low complexity** (McCabe ≤ 10)
- **Perfect lint score** (Pylint 10.0/10)

## ⚠️ Important Notes

1. **CI Integration**: Pre-commit CI will NOT auto-fix - manual fixes required
2. **No Compromises**: There are minimal ignore rules (only for tool conflicts)
3. **Performance**: Initial runs may be slow due to comprehensive checking
4. **Dependencies**: All quality tools must be installed via Poetry

## 🔧 Troubleshooting

If a hook fails:

1. Read the error message carefully
2. Fix the issue manually (no auto-fix)
3. Re-run the specific hook to verify
4. Commit only when ALL hooks pass

## 📋 Hook IDs Reference

- `black` - Code formatting
- `isort` - Import sorting
- `ruff` - Linting with ALL rules
- `ruff-format` - Ruff formatting check
- `mypy` - Type checking
- `pylint` - Code quality score
- `bandit` - Security scanning
- `flake8` - PEP8 compliance
- `pycodestyle` - Style guide checking
- `pydocstyle` - Docstring checking
- `vulture` - Dead code detection
- `mccabe` - Complexity checking
- `type-coverage` - Type annotation coverage

---

**Remember**: This configuration enforces the highest possible code quality standards. There are no shortcuts or compromises.