# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Enterprise-grade project reorganization following PEP standards
- Comprehensive .gitignore file
- MIT LICENSE file
- This CHANGELOG

### Changed

- Reorganized project structure for better maintainability
- Moved development documentation to docs/development/
- Cleaned up root directory from unnecessary files

### Fixed

- Import errors in configuration modules
- Module organization following enterprise standards

## [0.6.0] - 2025-01-07

### Added

- Initial release of FLEXT LDAP library
- Comprehensive LDAP operations support
- High-performance LDIF processing (12K+ entries/sec)
- Enterprise migration tools (Oracle OID to OUD)
- Full async support with connection pooling
- SASL authentication mechanisms
- Schema discovery and management
- Transaction support for atomic operations
- Vectorized bulk operations
- CLI tools for administration

### Security

- TLS/SSL encryption support
- Comprehensive authentication mechanisms
- Secure credential management

[Unreleased]: https://github.com/flext-sh/flext-ldap/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/flext-sh/flext-ldap/releases/tag/v0.6.0
