"""LDAP rootDSE classification utility methods.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap._utilities import FlextLdapUtilitiesDetection
from flext_ldap.constants import c
from flext_ldap.typings import t


class FlextLdapUtilitiesRootDse(FlextLdapUtilitiesDetection):
    """Server-type classification of rootDSE attributes read by the adapter."""

    @staticmethod
    def resolve_first_attribute_value(
        attrs: t.Ldap.OperationAttributes,
        key: str,
    ) -> str | None:
        """Return the first normalized value for a rootDSE attribute.

        Args:
            attrs: rootDSE attributes mapped to their value sequences.
            key: Attribute name to look up.

        Returns:
            The first non-empty value, or ``None`` when absent or empty.

        """
        values = attrs.get(key)
        if values is None:
            return None
        return next((value for value in values if value), None)

    @classmethod
    def detect_from_root_dse(cls, root_dse_attrs: t.Ldap.OperationAttributes) -> str:
        """Classify the LDAP server type from rootDSE attributes the adapter read.

        Returns:
            The detected server type.

        """
        return cls.detect_server_type(
            vendor_name=cls.resolve_first_attribute_value(
                root_dse_attrs,
                c.Ldap.RootDseAttribute.VENDOR_NAME,
            ),
            vendor_version=cls.resolve_first_attribute_value(
                root_dse_attrs,
                c.Ldap.RootDseAttribute.VENDOR_VERSION,
            ),
            naming_contexts=root_dse_attrs.get(
                c.Ldap.RootDseAttribute.NAMING_CONTEXTS,
                [],
            ),
            supported_extensions=root_dse_attrs.get(
                c.Ldap.RootDseAttribute.SUPPORTED_EXTENSIONS,
                [],
            ),
        )


__all__: list[str] = ["FlextLdapUtilitiesRootDse"]
