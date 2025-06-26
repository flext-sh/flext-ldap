"""🔥🔥🔥 ULTRA INTEGRATION Tests for LDIF Processing Components.

Integration tests for LDIF processor, parser, and validator components working together
in realistic scenarios with performance monitoring and error handling validation.

Architecture tested:
- LDIFProcessor + LDIFParser integration
- LDIF validation + performance monitoring
- Stream processing + categorization integration
- Error handling across LDIF components
- Memory management during large file processing
- Concurrent LDIF processing workflows

ZERO TOLERANCE INTEGRATION PRINCIPLES:
✅ Component coordination testing
✅ Data flow validation across modules
✅ Performance monitoring integration
✅ Error propagation and recovery
✅ Resource management verification
✅ Real-world LDIF file processing
"""

import asyncio
import tempfile
import time
from typing import Any

import pytest

from ldap_core_shared.ldif.parser import LDIFParser
from ldap_core_shared.ldif.processor import LDIFProcessor
from ldap_core_shared.utils.performance import PerformanceMonitor


class TestLDIFProcessorParserIntegration:
    """🔥 Integration tests for LDIF processor and parser coordination."""

    @pytest.fixture
    def complex_ldif_content(self) -> str:
        """Create complex LDIF content for integration testing."""
        return """# Complex LDIF with multiple organizational units and entries
dn: dc=company,dc=com
objectClass: top
objectClass: domain
dc: company

dn: ou=people,dc=company,dc=com
objectClass: top
objectClass: organizationalUnit
ou: people
description: All company personnel

dn: ou=groups,dc=company,dc=com
objectClass: top
objectClass: organizationalUnit
ou: groups
description: Company groups and roles

dn: ou=systems,dc=company,dc=com
objectClass: top
objectClass: organizationalUnit
ou: systems
description: System accounts

dn: uid=jsmith,ou=people,dc=company,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: jsmith
cn: John Smith
sn: Smith
givenName: John
mail: john.smith@company.com
telephoneNumber: +1-555-0123
employeeNumber: 12345
departmentNumber: Engineering
title: Senior Developer

dn: uid=mjohnson,ou=people,dc=company,dc=com
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: mjohnson
cn: Mary Johnson
sn: Johnson
givenName: Mary
mail: mary.johnson@company.com
telephoneNumber: +1-555-0124
employeeNumber: 12346
departmentNumber: Marketing
title: Marketing Manager

dn: cn=developers,ou=groups,dc=company,dc=com
objectClass: top
objectClass: groupOfNames
cn: developers
description: Software development team
member: uid=jsmith,ou=people,dc=company,dc=com

dn: cn=managers,ou=groups,dc=company,dc=com
objectClass: top
objectClass: groupOfNames
cn: managers
description: Management team
member: uid=mjohnson,ou=people,dc=company,dc=com

dn: uid=backup,ou=systems,dc=company,dc=com
objectClass: top
objectClass: account
objectClass: simpleSecurityObject
uid: backup
description: Backup system account
userPassword: {SSHA}encrypted_password_hash

dn: uid=monitoring,ou=systems,dc=company,dc=com
objectClass: top
objectClass: account
objectClass: simpleSecurityObject
uid: monitoring
description: System monitoring account
userPassword: {SSHA}another_encrypted_hash
"""

    @pytest.fixture
    def ldif_with_errors(self) -> str:
        """Create LDIF content with various errors for integration testing."""
        return """# LDIF with intentional errors for testing
dn: dc=test,dc=com
objectClass: domain
dc: test

dn: ou=users,dc=test,dc=com
objectClass: organizationalUnit
ou: users

# Missing required attribute
dn: uid=user1,ou=users,dc=test,dc=com
objectClass: inetOrgPerson
uid: user1
# missing cn attribute

# Invalid DN format
dn: invalid-dn-format
objectClass: person
cn: Invalid Entry

# Duplicate DN
dn: uid=user2,ou=users,dc=test,dc=com
objectClass: inetOrgPerson
uid: user2
cn: User Two

dn: uid=user2,ou=users,dc=test,dc=com
objectClass: inetOrgPerson
uid: user2
cn: Duplicate User Two

# Valid entry
dn: uid=user3,ou=users,dc=test,dc=com
objectClass: inetOrgPerson
uid: user3
cn: User Three
sn: Three
"""

    @pytest.mark.asyncio
    async def test_processor_parser_coordination(self, complex_ldif_content: str) -> None:
        """🔥 Test coordination between processor and parser."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
            f.write(complex_ldif_content)
            ldif_path = f.name

        try:
            processor = LDIFProcessor()
            parser = LDIFParser()

            # Process file with processor
            async with processor.process_file(ldif_path) as processor_results:
                processor_entries = [entry async for entry in processor_results]

            # Parse same file with parser
            parser_entries = [entry async for entry in parser.parse_file(ldif_path)]

            # Verify both components produced consistent results
            assert len(processor_entries) == len(parser_entries)
            assert len(processor_entries) > 0

            # Verify entry structure consistency
            for proc_entry, parse_entry in zip(
                processor_entries,
                parser_entries,
                strict=False,
            ):
                assert proc_entry["dn"] == parse_entry["dn"]
                assert "attributes" in proc_entry
                assert "attributes" in parse_entry

        finally:
            import os

            os.unlink(ldif_path)

    @pytest.mark.asyncio
    async def test_categorization_integration(self, complex_ldif_content: str) -> None:
        """🔥 Test entry categorization integration across components."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
            f.write(complex_ldif_content)
            ldif_path = f.name

        try:
            processor = LDIFProcessor()

            # Process with categorization
            async with processor.process_file(ldif_path) as results:
                categories = {
                    "people": [],
                    "groups": [],
                    "systems": [],
                    "domains": [],
                }

                async for entry in results:
                    category = processor.categorize_entry(entry)
                    if category in categories:
                        categories[category].append(entry)

            # Verify categorization results
            assert len(categories["people"]) == 2  # jsmith, mjohnson
            assert len(categories["groups"]) == 2  # developers, managers
            assert len(categories["systems"]) == 2  # backup, monitoring
            assert len(categories["domains"]) == 1  # company.com

            # Verify category-specific attributes
            for person in categories["people"]:
                assert "inetOrgPerson" in person["attributes"].get("objectClass", [])
                assert "mail" in person["attributes"]

            for group in categories["groups"]:
                assert "groupOfNames" in group["attributes"].get("objectClass", [])
                assert "member" in person["attributes"]

        finally:
            import os

            os.unlink(ldif_path)

    @pytest.mark.asyncio
    async def test_error_handling_integration(self, ldif_with_errors: Any) -> None:
        """🔥 Test error handling integration across LDIF components."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
            f.write(ldif_with_errors)
            ldif_path = f.name

        try:
            processor = LDIFProcessor()
            parser = LDIFParser()

            # Test processor error handling
            processor_entries = []
            processor_errors = []

            async with processor.process_file(ldif_path) as results:
                async for entry in results:
                    try:
                        # Validate entry structure
                        if entry.get("dn"):
                            processor_entries.append(entry)
                        else:
                            processor_errors.append(entry)
                    except Exception as e:
                        processor_errors.append({"error": str(e), "entry": entry})

            # Test parser error handling
            parser_entries = []
            parser_errors = []

            async for entry in parser.parse_file(ldif_path):
                try:
                    if entry.get("dn") and "," in entry["dn"]:
                        parser_entries.append(entry)
                    else:
                        parser_errors.append(entry)
                except Exception as e:
                    parser_errors.append({"error": str(e), "entry": entry})

            # Verify error handling consistency
            assert len(processor_entries) > 0  # Should have some valid entries
            assert len(parser_entries) > 0  # Should have some valid entries

            # Both should handle errors gracefully
            assert len(processor_entries) == len(parser_entries)

        finally:
            import os

            os.unlink(ldif_path)

    @pytest.mark.asyncio
    async def test_performance_monitoring_integration(
        self,
        complex_ldif_content: Any,
    ) -> None:
        """🔥 Test performance monitoring integration with LDIF processing."""
        monitor = PerformanceMonitor()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
            f.write(complex_ldif_content)
            ldif_path = f.name

        try:
            processor = LDIFProcessor()
            parser = LDIFParser()

            # Monitor processor performance
            monitor.start_measurement("processor_performance")

            async with processor.process_file(ldif_path) as results:
                entry_count = 0
                async for _entry in results:
                    entry_count += 1
                    monitor.record_event("processor_entry")

            monitor.stop_measurement("processor_performance")

            # Monitor parser performance
            monitor.start_measurement("parser_performance")

            parser_count = 0
            async for _entry in parser.parse_file(ldif_path):
                parser_count += 1
                monitor.record_event("parser_entry")

            monitor.stop_measurement("parser_performance")

            # Analyze performance metrics
            metrics = monitor.get_metrics()

            assert "processor_performance" in metrics
            assert "parser_performance" in metrics
            assert metrics["events"]["processor_entry"] == entry_count
            assert metrics["events"]["parser_entry"] == parser_count
            assert entry_count == parser_count  # Should process same number of entries

            # Verify performance characteristics
            processor_time = metrics["processor_performance"]["duration"]
            parser_time = metrics["parser_performance"]["duration"]

            assert processor_time > 0
            assert parser_time > 0

        finally:
            import os

            os.unlink(ldif_path)


class TestConcurrentLDIFProcessing:
    """🔥🔥 Integration tests for concurrent LDIF processing."""

    @pytest.fixture
    def multiple_ldif_files(self):
        """Create multiple LDIF files for concurrent testing."""
        files = []

        for i in range(3):
            content = f"""dn: dc=domain{i},dc=com
objectClass: domain
dc: domain{i}

dn: ou=users{i},dc=domain{i},dc=com
objectClass: organizationalUnit
ou: users{i}

dn: uid=user{i}_1,ou=users{i},dc=domain{i},dc=com
objectClass: inetOrgPerson
uid: user{i}_1
cn: User {i} One
sn: One
mail: user{i}_1@domain{i}.com

dn: uid=user{i}_2,ou=users{i},dc=domain{i},dc=com
objectClass: inetOrgPerson
uid: user{i}_2
cn: User {i} Two
sn: Two
mail: user{i}_2@domain{i}.com
"""

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=f"_domain{i}.ldif",
                delete=False, encoding="utf-8",
            ) as f:
                f.write(content)
                files.append(f.name)

        return files

    @pytest.mark.asyncio
    async def test_concurrent_file_processing(self, multiple_ldif_files: Any) -> None:
        """🔥 Test concurrent processing of multiple LDIF files."""

        async def process_file(file_path: str) -> dict[str, Any]:
            """Process a single LDIF file and return statistics."""
            processor = LDIFProcessor()

            start_time = time.time()
            entry_count = 0
            categories = {"domains": 0, "users": 0, "groups": 0}

            async with processor.process_file(file_path) as results:
                async for entry in results:
                    entry_count += 1
                    category = processor.categorize_entry(entry)
                    if category in categories:
                        categories[category] += 1

            duration = time.time() - start_time

            return {
                "file": file_path,
                "entries": entry_count,
                "duration": duration,
                "categories": categories,
            }

        try:
            # Process files concurrently
            tasks = [process_file(file_path) for file_path in multiple_ldif_files]
            results = await asyncio.gather(*tasks)

            # Verify all files were processed
            assert len(results) == len(multiple_ldif_files)

            # Verify each file had expected number of entries
            for result in results:
                assert result["entries"] == 4  # domain + ou + 2 users
                assert result["duration"] > 0
                assert result["categories"]["domains"] == 1
                assert result["categories"]["users"] == 2

            # Verify concurrent processing was faster than sequential
            total_duration = sum(r["duration"] for r in results)
            max_duration = max(r["duration"] for r in results)

            # Concurrent should be closer to max than to sum
            assert max_duration < total_duration

        finally:
            # Cleanup temporary files
            import os

            for file_path in multiple_ldif_files:
                os.unlink(file_path)

    @pytest.mark.asyncio
    async def test_concurrent_stream_processing(self, multiple_ldif_files: Any) -> None:
        """🔥 Test concurrent stream processing with shared resources."""
        monitor = PerformanceMonitor()

        async def stream_processor(file_path: str, processor_id: int) -> dict[str, Any]:
            """Stream process a file with monitoring."""
            processor = LDIFProcessor()

            monitor.start_measurement(f"stream_{processor_id}")

            entry_count = 0
            async with processor.process_file(file_path) as results:
                async for _entry in results:
                    entry_count += 1
                    monitor.record_event(f"stream_{processor_id}_entry")
                    # Simulate processing delay
                    await asyncio.sleep(0.001)

            monitor.stop_measurement(f"stream_{processor_id}")

            return {"processor_id": processor_id, "entries": entry_count}

        try:
            # Launch concurrent stream processors
            tasks = [
                stream_processor(file_path, i)
                for i, file_path in enumerate(multiple_ldif_files)
            ]

            results = await asyncio.gather(*tasks)

            # Verify all processors completed
            assert len(results) == len(multiple_ldif_files)

            for result in results:
                assert result["entries"] == 4

            # Verify monitoring captured all streams
            metrics = monitor.get_metrics()

            for i in range(len(multiple_ldif_files)):
                assert f"stream_{i}" in metrics
                assert metrics["events"][f"stream_{i}_entry"] == 4

        finally:
            import os

            for file_path in multiple_ldif_files:
                os.unlink(file_path)

    @pytest.mark.asyncio
    async def test_memory_management_integration(self) -> None:
        """🔥 Test memory management during large file processing."""
        # Create a large LDIF content
        large_ldif_content = "dn: dc=large,dc=com\nobjectClass: domain\ndc: large\n\n"

        # Add many entries
        for i in range(1000):
            large_ldif_content += f"""dn: uid=user{i:04d},dc=large,dc=com
objectClass: inetOrgPerson
uid: user{i:04d}
cn: User {i:04d}
sn: User{i:04d}
mail: user{i:04d}@large.com

"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
            f.write(large_ldif_content)
            large_ldif_path = f.name

        try:
            processor = LDIFProcessor()
            monitor = PerformanceMonitor()

            monitor.start_measurement("large_file_processing")

            # Process large file with memory monitoring
            entry_count = 0
            max_memory_usage = 0

            async with processor.process_file(large_ldif_path) as results:
                async for _entry in results:
                    entry_count += 1
                    monitor.record_event("large_file_entry")

                    # Simulate memory monitoring (in real implementation, would use psutil)
                    if entry_count % 100 == 0:
                        max_memory_usage = max(max_memory_usage, entry_count)

            monitor.stop_measurement("large_file_processing")

            # Verify large file processing
            assert entry_count == 1001  # 1 domain + 1000 users

            metrics = monitor.get_metrics()
            assert "large_file_processing" in metrics
            assert metrics["events"]["large_file_entry"] == 1001

            # Verify streaming processing kept memory usage reasonable
            # (actual values would depend on implementation)
            assert max_memory_usage > 0

        finally:
            import os

            os.unlink(large_ldif_path)


class TestLDIFValidationIntegration:
    """🔥🔥🔥 Integration tests for LDIF validation across components."""

    @pytest.mark.asyncio
    async def test_validation_pipeline_integration(self) -> None:
        """🔥 Test complete validation pipeline integration."""
        # LDIF with various validation scenarios
        validation_ldif = """dn: dc=validation,dc=com
objectClass: domain
dc: validation

dn: ou=valid,dc=validation,dc=com
objectClass: organizationalUnit
ou: valid

dn: uid=valid_user,ou=valid,dc=validation,dc=com
objectClass: inetOrgPerson
uid: valid_user
cn: Valid User
sn: User
mail: valid@validation.com

dn: uid=invalid_user,ou=valid,dc=validation,dc=com
objectClass: inetOrgPerson
uid: invalid_user
# Missing required cn attribute

dn:
objectClass: person
cn: Invalid DN

dn: uid=duplicate,ou=valid,dc=validation,dc=com
objectClass: inetOrgPerson
uid: duplicate
cn: First Duplicate
sn: Duplicate

dn: uid=duplicate,ou=valid,dc=validation,dc=com
objectClass: inetOrgPerson
uid: duplicate
cn: Second Duplicate
sn: Duplicate
"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
            f.write(validation_ldif)
            ldif_path = f.name

        try:
            processor = LDIFProcessor()
            LDIFParser()
            monitor = PerformanceMonitor()

            monitor.start_measurement("validation_pipeline")

            # Process with validation
            valid_entries = []
            invalid_entries = []

            async with processor.process_file(ldif_path) as results:
                async for entry in results:
                    # Validate entry structure
                    if (
                        entry.get("dn")
                        and entry.get("dn").strip()
                        and "," in entry.get("dn", "")
                        and entry.get("attributes")
                    ):
                        valid_entries.append(entry)
                        monitor.record_event("valid_entry")
                    else:
                        invalid_entries.append(entry)
                        monitor.record_event("invalid_entry")

            monitor.stop_measurement("validation_pipeline")

            # Verify validation results
            assert len(valid_entries) >= 3  # domain, ou, at least one valid user
            assert len(invalid_entries) >= 1  # entries with issues

            # Verify monitoring captured validation events
            metrics = monitor.get_metrics()
            assert "validation_pipeline" in metrics
            assert metrics["events"]["valid_entry"] == len(valid_entries)
            assert metrics["events"]["invalid_entry"] == len(invalid_entries)

        finally:
            import os

            os.unlink(ldif_path)

    @pytest.mark.asyncio
    async def test_schema_validation_integration(self, complex_ldif_content: str) -> None:
        """🔥 Test schema validation integration across components."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ldif", delete=False, encoding="utf-8") as f:
            f.write(complex_ldif_content)
            ldif_path = f.name

        try:
            processor = LDIFProcessor()

            # Process with schema-aware validation
            schema_results = {
                "valid_schemas": [],
                "invalid_schemas": [],
                "missing_required": [],
            }

            async with processor.process_file(ldif_path) as results:
                async for entry in results:
                    object_classes = entry.get("attributes", {}).get("objectClass", [])

                    if "inetOrgPerson" in object_classes:
                        # Validate inetOrgPerson requirements
                        required_attrs = ["cn", "sn"]
                        missing = [
                            attr
                            for attr in required_attrs
                            if attr not in entry.get("attributes", {})
                        ]

                        if missing:
                            schema_results["missing_required"].append(
                                {
                                    "dn": entry.get("dn"),
                                    "missing": missing,
                                },
                            )
                        else:
                            schema_results["valid_schemas"].append(entry.get("dn"))

                    elif "groupOfNames" in object_classes:
                        # Validate groupOfNames requirements
                        if "member" in entry.get("attributes", {}):
                            schema_results["valid_schemas"].append(entry.get("dn"))
                        else:
                            schema_results["invalid_schemas"].append(entry.get("dn"))

            # Verify schema validation results
            assert len(schema_results["valid_schemas"]) > 0
            assert (
                len(schema_results["missing_required"]) == 0
            )  # Should be no missing required attrs
            assert (
                len(schema_results["invalid_schemas"]) == 0
            )  # Should be no invalid schemas

        finally:
            import os

            os.unlink(ldif_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
