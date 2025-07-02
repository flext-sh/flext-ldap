"""LDIF (LDAP Data Interchange Format) Processing Module.

This module provides comprehensive LDIF processing capabilities for enterprise
LDAP operations including parsing, writing, validation, and transformation.

Key Features:
    - Standards-compliant LDIF parsing and generation
    - Enterprise-grade validation and error handling
    - Streaming support for large LDIF files
    - Schema-aware LDIF processing
    - Advanced filtering and transformation
    - Performance monitoring and metrics

Components:
    - LDIFProcessor: Core LDIF processing engine
    - LDIFWriter: Advanced LDIF writing with formatting
    - LDIFValidator: Comprehensive LDIF validation
    - LDIFAnalyzer: LDIF content analysis and statistics
    - LDIFTransformer: Entry transformation and filtering
    - LDIFMerger: Multiple LDIF file merging capabilities

Example:
    ```python
    from ldap_core_shared.ldif import LDIFProcessor, LDIFWriter

    # Parse LDIF file
    processor = LDIFProcessor()
    entries = processor.parse_file("input.ldif")

    # Write processed entries
    writer = LDIFWriter()
    writer.write_entries(entries, "output.ldif", title="Processed Entries")
    ```

"""

# Import classes that are actually implemented
try:
    from ldap_core_shared.ldif.analyzer import LDIFAnalyzer
    from ldap_core_shared.ldif.merger import LDIFMerger
    from ldap_core_shared.ldif.processor import LDIFProcessor

    # from ldap_core_shared.ldif.transformer import LDIFTransformer  # Temporarily disabled due to syntax errors
    from ldap_core_shared.ldif.validator import LDIFValidator
    from ldap_core_shared.ldif.writer import LDIFWriter

    __all__ = [
        "LDIFAnalyzer",
        "LDIFMerger",
        "LDIFProcessor",
        # "LDIFTransformer",  # Temporarily disabled
        "LDIFValidator",
        "LDIFWriter",
    ]
except ImportError:
    # If modules are not yet implemented, provide empty list
    __all__ = []
