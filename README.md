# LDAP Core Shared

Shared core components for LDAP operations within the PYAUTO ecosystem.

## Overview

This package provides common LDAP functionality and utilities that are shared across multiple LDAP-related projects in the PYAUTO workspace, including tap-ldap, target-ldap, and flx-ldap.

## Features

- Common LDAP connection management
- Shared data models and schemas
- Utility functions for LDAP operations
- Configuration management
- Error handling and logging

## Installation

```bash
pip install -e .
```

## Usage

This is a shared library package and is typically used as a dependency by other LDAP projects in the PYAUTO ecosystem.

## Development

### Setup

```bash
poetry install
```

### Testing

```bash
poetry run pytest
```

### Code Quality

```bash
poetry run ruff check
poetry run mypy .
```

## License

Apache License 2.0

## Contributing

This package is part of the PYAUTO ecosystem. Please refer to the main PYAUTO documentation for contribution guidelines.
