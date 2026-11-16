# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import defer_lazy_bases, install_lazy_exports

if TYPE_CHECKING:
    from flext_ldap._utilities.base import FlextLdapUtilitiesBase
    from flext_ldap._utilities.comparison import FlextLdapUtilitiesComparison
    from flext_ldap._utilities.conversion import FlextLdapUtilitiesConversion
    from flext_ldap._utilities.detection import FlextLdapUtilitiesDetection
    from flext_ldap._utilities.normalization import FlextLdapUtilitiesNormalization
    from flext_ldap._utilities.root_dse import FlextLdapUtilitiesRootDse
    from flext_ldap._utilities.server import FlextLdapUtilitiesServer
    from flext_ldap._utilities.validation import FlextLdapUtilitiesValidation


__all__: tuple[str, ...] = (
    "FlextLdapUtilitiesBase",
    "FlextLdapUtilitiesComparison",
    "FlextLdapUtilitiesConversion",
    "FlextLdapUtilitiesDetection",
    "FlextLdapUtilitiesNormalization",
    "FlextLdapUtilitiesRootDse",
    "FlextLdapUtilitiesServer",
    "FlextLdapUtilitiesValidation",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdapUtilitiesBase": ".base",
        "FlextLdapUtilitiesComparison": ".comparison",
        "FlextLdapUtilitiesConversion": ".conversion",
        "FlextLdapUtilitiesDetection": ".detection",
        "FlextLdapUtilitiesNormalization": ".normalization",
        "FlextLdapUtilitiesRootDse": ".root_dse",
        "FlextLdapUtilitiesServer": ".server",
        "FlextLdapUtilitiesValidation": ".validation",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdapUtilitiesComparison": (
            "extract_entry_attributes",
            "find_existing_values",
            "normalize_value_set",
            "process_new_attributes",
            "process_deleted_attributes",
            "rdn_attribute_names",
            "compare_entries",
        ),
        "FlextLdapUtilitiesConversion": (
            "build_conversion_metadata",
            "search_entry_to_ldif_entry",
            "track_conversion_differences",
            "extract_attrs_dict_from_entry",
            "extract_objectclass_category",
            "resolve_entry_category",
            "group_entries_by_objectclass",
        ),
        "FlextLdapUtilitiesDetection": (
            "detect_from_extensions",
            "_contains_marker",
            "_matches_vendor_rule",
            "detect_from_vendor",
            "detect_server_type",
        ),
        "FlextLdapUtilitiesNormalization": (
            "norm_in",
            "norm_join",
            "_convert_attr_value",
            "attr_to_str_list",
            "ldap3_value_to_strings",
            "base64_encoded",
            "normalize_original_attr_value",
            "dn_str",
            "filter_truthy",
            "map_str",
            "norm_str",
            "when_safe",
        ),
        "FlextLdapUtilitiesRootDse": (
            "resolve_first_attribute_value",
            "detect_from_root_dse",
        ),
        "FlextLdapUtilitiesServer": (
            "resolve_get_info",
            "create_server",
            "create_connection_server",
            "create_server_from_url",
            "create_connection",
            "create_bare_server",
        ),
        "FlextLdapUtilitiesValidation": ("valid_status",),
    },
)

defer_lazy_bases(
    __name__,
    {
        "FlextLdapUtilitiesComparison": ((".", "FlextLdapUtilitiesNormalization"),),
        "FlextLdapUtilitiesConversion": ((".", "FlextLdapUtilitiesNormalization"),),
        "FlextLdapUtilitiesDetection": ((".", "FlextLdapUtilitiesNormalization"),),
        "FlextLdapUtilitiesRootDse": ((".", "FlextLdapUtilitiesDetection"),),
    },
)
