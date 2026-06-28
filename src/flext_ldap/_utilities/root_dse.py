"""LDAP rootDSE query utility methods."""

from __future__ import annotations

from flext_ldap import c, p, t
from flext_ldap._utilities.detection import FlextLdapUtilitiesDetection
from flext_ldif import r


class FlextLdapUtilitiesRootDse(FlextLdapUtilitiesDetection):
    """LDAP rootDSE query and connection detection helpers."""

    @staticmethod
    def get_first_attribute_value(
        attrs: t.Ldap.OperationAttributes,
        key: str,
    ) -> str | None:
        """Return the first normalized value for a rootDSE attribute."""
        values = attrs.get(key)
        if values is None:
            return None
        return next((value for value in values if value), None)

    @classmethod
    def query_root_dse(
        cls,
        connection: p.Ldap.RootDseConnection,
    ) -> p.Result[t.Ldap.OperationAttributes]:
        """Read rootDSE data from a bound ldap3-compatible connection."""
        result: p.Result[t.Ldap.OperationAttributes]
        search_method = getattr(connection, "search", None)
        if not callable(search_method):
            result = r[t.Ldap.OperationAttributes].fail(
                "rootDSE query failed: search unavailable",
            )
        else:
            try:
                search_ok = search_method(
                    search_base="",
                    search_filter=str(c.Ldap.ALL_ENTRIES_FILTER),
                    search_scope=c.Ldap.SearchScopeValue.BASE,
                    attributes=str(c.Ldap.AttributeName.ALL_ATTRIBUTES),
                )
            except (
                ValueError,
                TypeError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
                KeyError,
                t.Ldap.LDAPException,
            ) as exc:
                result = r[t.Ldap.OperationAttributes].fail_op("rootDSE query", exc)
            else:
                if not search_ok:
                    result = r[t.Ldap.OperationAttributes].fail_op(
                        "rootDSE query",
                        str(connection.result),
                    )
                elif not getattr(connection, "entries", []):
                    result = r[t.Ldap.OperationAttributes].fail(
                        "rootDSE query returned no entries",
                    )
                elif not isinstance(connection.entries[0], p.Ldap.RootDseEntry):
                    result = r[t.Ldap.OperationAttributes].fail(
                        "rootDSE query returned invalid entry payload",
                    )
                else:
                    result = r[t.Ldap.OperationAttributes].ok(
                        cls.attr_to_str_list(
                            connection.entries[0].entry_attributes_as_dict,
                        ),
                    )
        return result

    @classmethod
    def detect_from_connection(
        cls,
        connection: p.Ldap.RootDseConnection,
    ) -> p.Result[str]:
        """Detect LDAP server type from rootDSE on an active connection."""
        root_dse_result = cls.query_root_dse(connection)
        if root_dse_result.failure:
            return r[str].fail(f"Failed to query rootDSE: {root_dse_result.error}")
        root_dse_attrs = root_dse_result.value
        return r[str].ok(
            cls.detect_server_type(
                vendor_name=cls.get_first_attribute_value(
                    root_dse_attrs,
                    c.Ldap.RootDseAttribute.VENDOR_NAME,
                ),
                vendor_version=cls.get_first_attribute_value(
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
            ),
        )


__all__: list[str] = ["FlextLdapUtilitiesRootDse"]
