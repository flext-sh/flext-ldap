#!/usr/bin/env python3
"""Test Coverage Analysis Script for ldap-core-shared.

This script analyzes the current test coverage and identifies critical modules
that need comprehensive testing.
"""

import ast
import sys
from pathlib import Path
from typing import NamedTuple


class ModuleInfo(NamedTuple):
    path: str
    functions: int
    classes: int
    lines: int
    has_notimplemented: bool
    complexity_score: int


class TestInfo(NamedTuple):
    path: str
    test_functions: int
    test_classes: int
    coverage_targets: set[str]


class CoverageGap(NamedTuple):
    module_path: str
    criticality: str  # HIGH/MEDIUM/LOW
    test_types_needed: list[str]  # unit/integration/performance
    implementation_complexity: str  # HIGH/MEDIUM/LOW
    functions_count: int
    has_incomplete_impl: bool
    reason: str


def analyze_python_file(file_path: Path) -> ModuleInfo:
    """Analyze a Python file for complexity metrics."""
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        # Parse AST
        tree = ast.parse(content)

        # Count functions and classes
        functions = sum(
            1 for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        )
        classes = sum(1 for node in ast.walk(tree) if isinstance(node, ast.ClassDef))
        lines = len(content.splitlines())

        # Check for NotImplementedError
        has_notimplemented = (
            "NotImplementedError" in content or "TODO" in content or "FIXME" in content
        )

        # Calculate complexity score (rough heuristic)
        complexity_score = functions + (classes * 3) + (lines // 10)
        if has_notimplemented:
            complexity_score += 20  # Penalty for incomplete implementation

        return ModuleInfo(
            path=str(file_path),
            functions=functions,
            classes=classes,
            lines=lines,
            has_notimplemented=has_notimplemented,
            complexity_score=complexity_score,
        )
    except Exception:
        return ModuleInfo(str(file_path), 0, 0, 0, False, 0)


def analyze_test_file(file_path: Path) -> TestInfo:
    """Analyze a test file to see what it covers."""
    try:
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        # Parse AST
        tree = ast.parse(content)

        # Count test functions and classes
        test_functions = sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
        )
        test_classes = sum(
            1
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and "Test" in node.name
        )

        # Extract import targets to see what's being tested
        coverage_targets = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if "ldap_core_shared" in node.module:
                    coverage_targets.add(node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if "ldap_core_shared" in alias.name:
                        coverage_targets.add(alias.name)

        return TestInfo(
            path=str(file_path),
            test_functions=test_functions,
            test_classes=test_classes,
            coverage_targets=coverage_targets,
        )
    except Exception:
        return TestInfo(str(file_path), 0, 0, set())


def is_critical_module(module_path: str) -> tuple[bool, str, list[str]]:
    """Determine if a module is critical and what types of tests it needs."""
    critical_patterns = {
        "protocols/asn1/": (
            "HIGH",
            ["unit", "integration", "security"],
            "ASN.1 encoding/decoding critical for LDAP protocol",
        ),
        "protocols/sasl/": (
            "HIGH",
            ["unit", "integration", "security"],
            "SASL authentication critical for security",
        ),
        "core/security.py": (
            "HIGH",
            ["unit", "integration", "security"],
            "Core security operations",
        ),
        "connections/security.py": (
            "HIGH",
            ["unit", "integration", "security"],
            "Connection security and SSL/TLS",
        ),
        "vectorized/": (
            "MEDIUM",
            ["unit", "performance"],
            "Performance-critical vectorized operations",
        ),
        "cli/": (
            "MEDIUM",
            ["unit", "integration"],
            "Command-line interfaces for users",
        ),
        "core/": (
            "HIGH",
            ["unit", "integration"],
            "Core LDAP operations",
        ),
        "controls/": (
            "MEDIUM",
            ["unit", "integration"],
            "LDAP controls and extensions",
        ),
        "schema/": (
            "MEDIUM",
            ["unit", "integration"],
            "Schema validation and processing",
        ),
        "ldif/": (
            "MEDIUM",
            ["unit", "integration"],
            "LDIF processing and validation",
        ),
        "operations/": (
            "HIGH",
            ["unit", "integration"],
            "LDAP operations",
        ),
        "extensions/": (
            "MEDIUM",
            ["unit", "integration"],
            "LDAP extensions",
        ),
        "transactions/": (
            "HIGH",
            ["unit", "integration"],
            "Transaction management",
        ),
        "exceptions/": (
            "MEDIUM",
            ["unit"],
            "Error handling and exceptions",
        ),
    }

    for pattern, (criticality, test_types, reason) in critical_patterns.items():
        if pattern in module_path:
            return True, criticality, test_types, reason

    return False, "LOW", ["unit"], "Standard module"


def main() -> int:
    """Main analysis function."""
    project_root = Path("/home/marlonsc/pyauto/ldap-core-shared")
    src_dir = project_root / "src" / "ldap_core_shared"
    tests_dir = project_root / "tests"

    if not src_dir.exists():
        return 1

    if not tests_dir.exists():
        return 1

    # Analyze all source modules
    modules_info: dict[str, ModuleInfo] = {}
    for py_file in src_dir.rglob("*.py"):
        if py_file.name != "__init__.py":
            rel_path = str(py_file.relative_to(src_dir))
            modules_info[rel_path] = analyze_python_file(py_file)

    # Analyze all test files
    tests_info: dict[str, TestInfo] = {}
    for py_file in tests_dir.rglob("*.py"):
        if py_file.name.startswith("test_") and py_file.name != "__init__.py":
            rel_path = str(py_file.relative_to(tests_dir))
            tests_info[rel_path] = analyze_test_file(py_file)

    # Create coverage mapping
    tested_modules = set()
    for test_info in tests_info.values():
        for target in test_info.coverage_targets:
            # Extract module path from import
            if "ldap_core_shared." in target:
                module_path = (
                    target.replace("ldap_core_shared.", "").replace(".", "/") + ".py"
                )
                tested_modules.add(module_path)

    # Identify coverage gaps
    coverage_gaps: list[CoverageGap] = []

    for module_path, module_info in modules_info.items():
        is_critical, criticality, test_types, reason = is_critical_module(module_path)

        # Complexity threshold constants
        HIGH_COMPLEXITY_THRESHOLD = 100
        MEDIUM_COMPLEXITY_THRESHOLD = 50

        # Determine implementation complexity
        if module_info.complexity_score > HIGH_COMPLEXITY_THRESHOLD:
            impl_complexity = "HIGH"
        elif module_info.complexity_score > MEDIUM_COMPLEXITY_THRESHOLD:
            impl_complexity = "MEDIUM"
        else:
            impl_complexity = "LOW"

        # Check if module has adequate test coverage
        has_adequate_tests = False
        for test_info in tests_info.values():
            for target in test_info.coverage_targets:
                if module_path.replace(".py", "").replace("/", ".") in target:
                    if test_info.test_functions >= max(1, module_info.functions // 3):
                        has_adequate_tests = True
                        break

        # Only include gaps for critical modules or modules with insufficient tests
        if (is_critical and not has_adequate_tests) or module_info.has_notimplemented:
            coverage_gaps.append(
                CoverageGap(
                    module_path=module_path,
                    criticality=criticality if is_critical else "LOW",
                    test_types_needed=test_types if is_critical else ["unit"],
                    implementation_complexity=impl_complexity,
                    functions_count=module_info.functions,
                    has_incomplete_impl=module_info.has_notimplemented,
                    reason=reason if is_critical else "Incomplete implementation",
                )
            )

    # Sort gaps by criticality and complexity
    coverage_gaps.sort(
        key=lambda x: (
            {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[x.criticality],
            {"HIGH": 0, "MEDIUM": 1, "LOW": 2}[x.implementation_complexity],
            -x.functions_count,
        )
    )

    # Generate report

    high_priority = [gap for gap in coverage_gaps if gap.criticality == "HIGH"]
    medium_priority = [gap for gap in coverage_gaps if gap.criticality == "MEDIUM"]
    low_priority = [gap for gap in coverage_gaps if gap.criticality == "LOW"]

    def print_gaps(gaps: list[CoverageGap], priority: str) -> None:
        if not gaps:
            return

        for gap in gaps:
            if gap.has_incomplete_impl:
                pass

    print_gaps(high_priority, "HIGH")
    print_gaps(medium_priority, "MEDIUM")
    print_gaps(low_priority, "LOW")

    # Summary statistics

    # Calculate total test functions
    total_test_functions = sum(test.test_functions for test in tests_info.values())
    total_source_functions = sum(module.functions for module in modules_info.values())

    (
        total_test_functions / total_source_functions * 100
    ) if total_source_functions > 0 else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
