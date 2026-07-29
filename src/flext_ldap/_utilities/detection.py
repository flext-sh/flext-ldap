"""LDAP server type detection utility methods."""

from __future__ import annotations

from flext_ldap import c, t
from flext_ldap._utilities.normalization import FlextLdapUtilitiesNormalization
from flext_ldif import u


class FlextLdapUtilitiesDetection(FlextLdapUtilitiesNormalization):
    """LDAP rootDSE and vendor detection helpers."""

    @classmethod
    def detect_from_extensions(
        cls, supported_extensions: t.StrSequence, naming_contexts: t.StrSequence
    ) -> str:
        """Infer server type from rootDSE extensions and naming contexts."""
        ext_str = str(cls.map_str(supported_extensions, case="lower", join=" "))
        context_str = cls.norm_join(naming_contexts, case="lower")
        for server_name in c.Ldap.ROOT_DSE_DETECTION_ORDER:
            extension_markers = c.Ldap.ROOT_DSE_EXTENSION_MARKERS.get(
                server_name, frozenset()
            )
            context_markers = c.Ldap.ROOT_DSE_CONTEXT_MARKERS.get(
                server_name, frozenset()
            )
            if cls._contains_marker(ext_str, extension_markers) or cls._contains_marker(
                context_str, context_markers
            ):
                detected: str = server_name
                return detected
        default: str = c.Ldap.DEFAULT_TYPE.value
        return default

    @staticmethod
    def _contains_marker(
        haystack: str, markers: t.StrSequence | frozenset[str]
    ) -> bool:
        """Return True when any configured marker is present in the input text."""
        return any(marker in haystack for marker in markers)

    @classmethod
    def _matches_vendor_rule(cls, vendor_info: str, server_name: str) -> bool:
        """Evaluate declarative vendor-detection markers for one server type."""
        required_markers = c.Ldap.ROOT_DSE_VENDOR_REQUIRED_MARKERS.get(
            server_name, frozenset()
        )
        if any(marker not in vendor_info for marker in required_markers):
            return False
        excluded_markers = c.Ldap.ROOT_DSE_VENDOR_EXCLUDED_MARKERS.get(
            server_name, frozenset()
        )
        if cls._contains_marker(vendor_info, excluded_markers):
            return False
        any_markers = c.Ldap.ROOT_DSE_VENDOR_ANY_MARKERS.get(server_name, frozenset())
        if any_markers and cls._contains_marker(vendor_info, any_markers):
            return True
        max_tokens = c.Ldap.ROOT_DSE_VENDOR_MAX_TOKENS.get(server_name)
        if max_tokens is not None and len(vendor_info.split()) <= max_tokens:
            return True
        return not any_markers and max_tokens is None

    @classmethod
    def detect_from_vendor(
        cls, vendor_name: str | None, vendor_version: str | None
    ) -> str | None:
        """Infer server type from vendor metadata when available."""
        vendor_parts = [
            u.to_str(value)
            for value in (vendor_name, vendor_version)
            if value is not None
        ]
        vendor_info = " ".join(
            str(value) for value in cls.filter_truthy(vendor_parts)
        ).lower()
        if not vendor_info:
            return None
        for detected_type in c.Ldap.ROOT_DSE_DETECTION_ORDER:
            if cls._matches_vendor_rule(vendor_info, detected_type):
                matched: str = detected_type
                return matched
        return None

    @classmethod
    def detect_server_type(
        cls,
        *,
        vendor_name: str | None,
        vendor_version: str | None,
        naming_contexts: t.StrSequence,
        supported_extensions: t.StrSequence,
    ) -> str:
        """Resolve the effective server type from rootDSE metadata."""
        return cls.detect_from_vendor(
            vendor_name, vendor_version
        ) or cls.detect_from_extensions(supported_extensions, naming_contexts)


__all__: list[str] = ["FlextLdapUtilitiesDetection"]
