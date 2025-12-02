"""Synchronize LDIF content into LDAP through the operations service."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from flext_core import FlextResult, FlextUtilities
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.utilities import FlextLdifUtilities
from pydantic import ConfigDict, PrivateAttr

from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.operations import FlextLdapOperations


class FlextLdapSyncService(FlextLdapServiceBase[FlextLdapModels.SyncStats]):
    """Stream LDIF entries into LDAP while tracking progress and totals.

    All LDAP mutations are delegated to :class:`FlextLdapOperations`, keeping
    this service focused on batching, optional base-DN translation, and runtime
    statistics. Syncs rely on ``add`` operations with idempotent handling for
    existing entries, mirroring the current runtime behaviour in code.
    """

    model_config = ConfigDict(
        frozen=False,  # Service needs mutable state for operations and ldif references
        extra="allow",
        arbitrary_types_allowed=True,
    )

    _operations: FlextLdapOperations = PrivateAttr()
    _ldif: FlextLdif = PrivateAttr()
    _generate_datetime_utc: Callable[[], datetime] = PrivateAttr()

    class BatchSync:
        """Batch synchronization helper."""

        def __init__(self, operations: FlextLdapOperations) -> None:
            """Store the operations service reference."""
            self._ops = operations

        def sync(
            self,
            entries: list[FlextLdifModels.Entry],
            options: FlextLdapModels.SyncOptions,
        ) -> FlextResult[FlextLdapModels.SyncStats]:
            """Sync entries in batch mode."""
            added = skipped = failed = 0
            for idx, entry in enumerate(entries, 1):
                entry_dn = FlextLdifUtilities.DN.get_dn_value(entry.dn)
                add_result = self._ops.add(entry)
                if add_result.is_success:
                    added += 1
                    entry_stats = FlextLdapModels.LdapBatchStats(
                        synced=1,
                        skipped=0,
                        failed=0,
                    )
                else:
                    error_str = str(add_result.error) if add_result.error else ""
                    if FlextLdapOperations.is_already_exists_error(error_str):
                        skipped += 1
                        entry_stats = FlextLdapModels.LdapBatchStats(
                            synced=0,
                            skipped=1,
                            failed=0,
                        )
                    else:
                        failed += 1
                        entry_stats = FlextLdapModels.LdapBatchStats(
                            synced=0,
                            skipped=0,
                            failed=1,
                        )

                if options.progress_callback:
                    options.progress_callback(idx, len(entries), entry_dn, entry_stats)

            return FlextResult[FlextLdapModels.SyncStats].ok(
                FlextLdapModels.SyncStats.from_counters(
                    added=added,
                    skipped=skipped,
                    failed=failed,
                    duration_seconds=0.0,
                ),
            )

    class BaseDNTransformer:
        """Transform entry base DNs when source and target differ."""

        @staticmethod
        def transform(
            entries: list[FlextLdifModels.Entry],
            source_basedn: str,
            target_basedn: str,
        ) -> list[FlextLdifModels.Entry]:
            """Rewrite entry DNs from ``source_basedn`` to ``target_basedn``."""
            if source_basedn == target_basedn:
                return entries

            transformed = []
            for entry in entries:
                dn_str = FlextLdifUtilities.DN.get_dn_value(entry.dn)
                if source_basedn.lower() in dn_str.lower():
                    transformed.append(
                        entry.model_copy(
                            update={
                                "dn": FlextLdifModels.DistinguishedName(
                                    value=dn_str.replace(source_basedn, target_basedn),
                                ),
                            },
                        ),
                    )
                else:
                    transformed.append(entry)
            return transformed

    def __init__(
        self,
        operations: FlextLdapOperations | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize the sync service with the provided operations instance."""
        super().__init__(**kwargs)
        if operations is None:
            operations_kwarg = kwargs.pop("operations", None)
            if operations_kwarg is not None:
                if not isinstance(operations_kwarg, FlextLdapOperations):
                    error_msg = f"operations must be FlextLdapOperations, got {type(operations_kwarg).__name__}"
                    raise TypeError(error_msg)
                operations = operations_kwarg
        if operations is None:
            error_msg = "operations parameter is required"
            raise TypeError(error_msg)
        self._operations = operations
        # FlextLdif accepts config via kwargs, not as direct parameter
        self._ldif = FlextLdif.get_instance()
        self._generate_datetime_utc = FlextUtilities.Generators.generate_datetime_utc

    def sync_ldif_file(
        self,
        ldif_file: Path,
        options: FlextLdapModels.SyncOptions,
    ) -> FlextResult[FlextLdapModels.SyncStats]:
        """Parse and sync an LDIF file into the directory."""
        if not ldif_file.exists():
            return FlextResult[FlextLdapModels.SyncStats].fail(
                f"LDIF file not found: {ldif_file}",
            )

        start_time = self._generate_datetime_utc()
        # Use FlextLdif API parse method (avoids broken parse_source)
        # Use ServerTypes Literal type directly (FlextLdif.parse accepts Literal)
        # Use the literal value from the enum
        server_type_literal: FlextLdifConstants.LiteralTypes.ServerTypeLiteral = (
            "rfc"  # Literal matching FlextLdifConstants.ServerTypes.RFC.value
        )
        parse_result = self._ldif.parse(
            source=ldif_file,
            server_type=server_type_literal,
        )

        if parse_result.is_failure:
            return FlextResult[FlextLdapModels.SyncStats].fail(
                f"Failed to parse LDIF file: {parse_result.error}",
            )

        # API parse returns list[Entry] directly
        entries = parse_result.unwrap()
        return self._process_entries(entries, options, start_time)

    def _process_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        options: FlextLdapModels.SyncOptions,
        start_time: datetime,
    ) -> FlextResult[FlextLdapModels.SyncStats]:
        """Process parsed entries through the sync pipeline."""
        if not entries:
            return FlextResult[FlextLdapModels.SyncStats].ok(
                FlextLdapModels.SyncStats.from_counters(),
            )

        if options.source_basedn and options.target_basedn:
            entries = self.BaseDNTransformer.transform(
                entries,
                options.source_basedn,
                options.target_basedn,
            )

        batch_result = self.BatchSync(self._operations).sync(entries, options)
        if batch_result.is_failure:
            return batch_result

        stats = batch_result.unwrap()
        duration = (self._generate_datetime_utc() - start_time).total_seconds()
        return FlextResult[FlextLdapModels.SyncStats].ok(
            stats.model_copy(update={"duration_seconds": duration}),
        )

    def execute(  # noqa: PLR6301
        self,
        **_kwargs: str | float | bool | None,
    ) -> FlextResult[FlextLdapModels.SyncStats]:
        """Return an empty stats payload to indicate service readiness."""
        return FlextResult[FlextLdapModels.SyncStats].ok(
            FlextLdapModels.SyncStats.from_counters(),
        )
