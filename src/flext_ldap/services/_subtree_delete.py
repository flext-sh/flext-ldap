"""Deepest-first subtree deletion for LDAP.

Split from ``FlextLdapOperations`` following the ``_upsert_handler`` pattern;
the handler delegates every LDAP call back to the operations service instance
it is constructed with.

Business Rules:
    - The base entry must exist (typed failure when absent)
    - The subtree is collected with a DN-only subtree search (attributes 1.1)
    - Entries are deleted deepest-first (children always before parents)
    - The base entry itself is deleted last
    - The first failed deletion stops the run and reports progress

Audit Implications:
    - ``deleted_count`` reports how many entries were removed before a stop
    - ``failed_dn`` and ``cause`` identify the first failed deletion
    - Every outcome flows through ``r`` (no exceptions escape)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_ldif import r

from flext_ldap import c, m, p, t, u

if TYPE_CHECKING:
    from flext_ldap.services.operations import FlextLdapOperations


class FlextLdapSubtreeDeleteHandler:
    """Handle deepest-first subtree deletion."""

    def __init__(self, operations: FlextLdapOperations) -> None:
        """Initialize subtree-delete handler with the owning operations service.

        Args:
            operations: FlextLdapOperations instance used for every LDAP call.
                Must have an active connection for execute() to succeed.

        """
        super().__init__()
        self._ops = operations

    def run(self, dn: str) -> p.Result[m.Ldap.SubtreeDeleteResult]:
        """Delete the subtree rooted at ``dn``, children before parents.

        Business Rules:
            - A DN-only subtree search (``1.1``) enumerates the subtree
            - Deletion order is deepest-first so no parent is removed while a
              child still exists (avoids LDAP error 66 notAllowedOnNonLeaf)
            - The base entry is depth 0 and is therefore deleted last
            - Depth is the RDN count (DN commas); escaped commas inside an RDN
              can only inflate a child's count, never below its parent's, so
              ordering stays parent-safe

        Returns:
            r with SubtreeDeleteResult (deleted_count on success) or a typed
            failure describing the base DN, progress, failed DN, and cause.

        """
        if not dn or not dn.strip():
            return r[m.Ldap.SubtreeDeleteResult].fail(
                "Subtree delete requires a non-empty base DN",
            )
        base_dn = dn.strip()
        existence_result = self._ops.find_entry(base_dn)
        if existence_result.failure:
            return r[m.Ldap.SubtreeDeleteResult].fail_op(
                "Subtree delete existence check",
                existence_result.error,
            )
        if not existence_result.value.entries:
            return r[m.Ldap.SubtreeDeleteResult].fail(
                f"Subtree delete base does not exist: {base_dn}",
            )
        collect_result = self._collect_subtree_dns(base_dn)
        if collect_result.failure:
            return r[m.Ldap.SubtreeDeleteResult].fail_op(
                "Subtree delete enumeration",
                collect_result.error,
            )
        subtree_dns = collect_result.unwrap()
        ordered_dns = sorted(subtree_dns, key=self._dn_depth, reverse=True)
        deleted_count = 0
        for entry_dn in ordered_dns:
            delete_result = self._ops.delete(entry_dn)
            if delete_result.failure:
                cause = u.to_str(delete_result.error, default="Unknown error")
                return r[m.Ldap.SubtreeDeleteResult].fail(
                    f"Subtree delete stopped at dn={entry_dn} "
                    f"(deleted_count={deleted_count}, base_dn={base_dn}): {cause}",
                )
            deleted_count += 1
        self._ops.logger.info(
            "Subtree deleted",
            operation=c.Ldap.OperationName.SUBTREE_DELETE,
            base_dn=base_dn,
            deleted_count=deleted_count,
        )
        return r[m.Ldap.SubtreeDeleteResult].ok(
            m.Ldap.SubtreeDeleteResult(base_dn=base_dn, deleted_count=deleted_count),
        )

    def _collect_subtree_dns(self, base_dn: str) -> p.Result[t.SequenceOf[str]]:
        """Enumerate every DN under (and including) the base, attributes omitted.

        Returns:
            The resulting ``p.Result[t.SequenceOf[str]]``.
        """
        search_options = m.Ldap.SearchOptions(
            base_dn=base_dn,
            scope=c.Ldap.SearchScope.SUBTREE,
            filter_str=c.Ldap.ALL_ENTRIES_FILTER,
            attributes=[c.Ldap.AttributeName.NO_ATTRIBUTES],
        )
        search_result = self._ops.search(search_options)
        if search_result.failure:
            return r[t.SequenceOf[str]].fail_op(
                "Subtree enumeration search",
                search_result.error,
            )
        search_data = search_result.map_or(None)
        entries: t.SequenceOf[m.Ldif.Entry] = (
            list(search_data.entries) if search_data is not None else []
        )
        subtree_dns: list[str] = [
            entry.dn.value
            for entry in entries
            if entry.dn is not None and entry.dn.value
        ]
        if base_dn not in subtree_dns:
            subtree_dns.append(base_dn)
        return r[t.SequenceOf[str]].ok(subtree_dns)

    @staticmethod
    def _dn_depth(dn: str) -> int:
        """Depth of a DN as its RDN separator count (parent-safe ordering).

        Returns:
            The resulting ``int``.
        """
        return dn.count(",")
