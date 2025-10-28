#!/usr/bin/env python3
"""Scan for SOLID principle violations in flext-ldap."""

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Violation:
    """Represents a SOLID violation."""

    file: str
    line: int
    severity: str  # critical, high, medium, low
    principle: str  # S, O, L, I, D
    issue: str
    suggestion: str


class SOLIDAnalyzer(ast.NodeVisitor):
    """Analyze Python files for SOLID violations."""

    def __init__(self, filepath: str) -> None:
        """Initialize SOLIDAnalyzer with filepath."""
        self.filepath = filepath
        self.violations: list[Violation] = []
        self.current_class = None
        self.imported_modules: set[str] = set()
        self.defined_functions: set[str] = set()
        self.defined_classes: set[str] = set()
        self.method_responsibilities: dict[str, int] = defaultdict(int)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track imports for dependency analysis."""
        if node.module:
            self.imported_modules.add(node.module)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Analyze class definitions for SRP violations."""
        old_class = self.current_class
        self.current_class = node.name
        self.defined_classes.add(node.name)

        # Check for too many methods (SRP)
        methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
        if len(methods) > 15:
            self.violations.append(
                Violation(
                    file=self.filepath,
                    line=node.lineno,
                    severity="high",
                    principle="S",
                    issue=f"Class '{node.name}' has {len(methods)} methods (too many responsibilities)",
                    suggestion="Split into focused classes with single responsibilities",
                )
            )

        # Check for methods with too many statements (SRP)
        for method in methods:
            stmt_count = len(method.body)
            if stmt_count > 50:
                self.violations.append(
                    Violation(
                        file=self.filepath,
                        line=method.lineno,
                        severity="high",
                        principle="S",
                        issue=f"Method '{method.name}' has {stmt_count} statements (too large)",
                        suggestion="Break into smaller, focused methods",
                    )
                )

        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze function definitions."""
        if self.current_class is None:
            self.defined_functions.add(node.name)
        self.generic_visit(node)


def scan_layer_1_foundation() -> list[Violation]:
    """Scan Foundation Layer (typings.py, constants.py)."""
    print("\n" + "=" * 80)
    print("LAYER 1: FOUNDATION LAYER")
    print("=" * 80)
    print("Files: typings.py, constants.py")
    print("Responsibility: Type definitions and constants ONLY")
    print()

    violations = []

    # Check typings.py
    print("Scanning typings.py...")
    typings_file = Path("src/flext_ldap/typings.py")
    if typings_file.exists():
        with Path(typings_file).open(encoding="utf-8") as f:
            content = f.read()

        # Check for logic beyond type definitions
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Classes shouldn't be in typings (only Protocol)
                if not any(
                    isinstance(base, ast.Name) and base.id == "Protocol"
                    for base in node.bases
                ):
                    violations.append(
                        Violation(
                            file="src/flext_ldap/typings.py",
                            line=node.lineno,
                            severity="high",
                            principle="S",
                            issue=f"Non-Protocol class '{node.name}' in typings.py",
                            suggestion="Move to appropriate module (models.py, domain.py)",
                        )
                    )
            elif isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
                violations.append(
                    Violation(
                        file="src/flext_ldap/typings.py",
                        line=node.lineno,
                        severity="medium",
                        principle="S",
                        issue=f"Function '{node.name}' in typings.py (should only have types)",
                        suggestion="Move to utils.py or appropriate module",
                    )
                )

    # Check constants.py
    print("Scanning constants.py...")
    const_file = Path("src/flext_ldap/constants.py")
    if const_file.exists():
        with Path(const_file).open(encoding="utf-8") as f:
            content = f.read()

        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                violations.append(
                    Violation(
                        file="src/flext_ldap/constants.py",
                        line=node.lineno,
                        severity="high",
                        principle="S",
                        issue=f"Class '{node.name}' in constants.py",
                        suggestion="Move to appropriate module (should only have constants)",
                    )
                )
            elif isinstance(node, ast.FunctionDef):
                violations.append(
                    Violation(
                        file="src/flext_ldap/constants.py",
                        line=node.lineno,
                        severity="high",
                        principle="S",
                        issue=f"Function '{node.name}' in constants.py",
                        suggestion="Move to appropriate module",
                    )
                )

    return violations


def scan_layer_2_domain() -> list[Violation]:
    """Scan Domain Layer (models.py, domain.py, search.py, protocols.py)."""
    print("\n" + "=" * 80)
    print("LAYER 2: DOMAIN LAYER")
    print("=" * 80)
    print("Files: models.py, domain.py, search.py, protocols.py")
    print("Responsibility: Domain logic and models ONLY")
    print()

    violations = []

    # Analyze models.py
    print("Scanning models.py...")
    models_file = Path("src/flext_ldap/models.py")
    if models_file.exists():
        with Path(models_file).open(encoding="utf-8") as f:
            content = f.read()
            lines = content.split("\n")

        # Check file size (SRP indicator)
        if len(lines) > 2000:
            violations.append(
                Violation(
                    file="src/flext_ldap/models.py",
                    line=1,
                    severity="critical",
                    principle="S",
                    issue=f"models.py is {len(lines)} lines (TOO LARGE - likely multiple responsibilities)",
                    suggestion="Split into multiple focused modules or remove duplicate models",
                )
            )

        tree = ast.parse(content)

        # Check for duplicate models from flext-ldif
        duplicate_models = [
            "DistinguishedName",
            "SchemaAttribute",
            "SchemaObjectClass",
            "SchemaDiscoveryResult",
            "Acl",
            "AclTarget",
            "AclSubject",
            "AclPermissions",
        ]

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in duplicate_models:
                violations.append(
                    Violation(
                        file="src/flext_ldap/models.py",
                        line=node.lineno,
                        severity="critical",
                        principle="D",
                        issue=f"Duplicate model '{node.name}' (exists in FlextLdif)",
                        suggestion="Remove and import from FlextLdifModels instead",
                    )
                )

            # Check for conversion methods (should be in adapters)
            if isinstance(node, ast.FunctionDef) and node.name in {"to_ldap3", "from_ldap3", "to_dict", "from_dict"}:
                violations.append(
                    Violation(
                        file="src/flext_ldap/models.py",
                        line=node.lineno,
                        severity="high",
                        principle="S",
                        issue=f"Conversion method '{node.name}' in model (violates SRP)",
                        suggestion="Move to entry_adapter.py",
                    )
                )

    print("Scanning domain.py...")
    domain_file = Path("src/flext_ldap/domain.py")
    if domain_file.exists():
        with Path(domain_file).open(encoding="utf-8") as f:
            content = f.read()
            lines = content.split("\n")

        # Check imports from infrastructure
        tree = ast.parse(content)
        violations.extend(Violation(
                        file="src/flext_ldap/domain.py",
                        line=node.lineno,
                        severity="critical",
                        principle="D",
                        issue=f"Domain layer imports infrastructure: {node.module}",
                        suggestion="Depend on abstractions, not infrastructure",
                    ) for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and (
                (node.module and "clients" in node.module)
                or "ldap3" in node.module
                or "servers" in node.module
            ))

    print("Scanning protocols.py...")
    protocols_file = Path("src/flext_ldap/protocols.py")
    if protocols_file.exists():
        with Path(protocols_file).open(encoding="utf-8") as f:
            content = f.read()

        tree = ast.parse(content)
        violations.extend(Violation(
                        file="src/flext_ldap/protocols.py",
                        line=node.lineno,
                        severity="medium",
                        principle="S",
                        issue=f"Function '{node.name}' in protocols.py (should only have Protocol definitions)",
                        suggestion="Move to appropriate module",
                    ) for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"))

    return violations


def scan_layer_3_infrastructure() -> list[Violation]:
    """Scan Infrastructure Layer (clients.py, servers/, entry_adapter.py)."""
    print("\n" + "=" * 80)
    print("LAYER 3: INFRASTRUCTURE LAYER")
    print("=" * 80)
    print("Files: clients.py, servers/*, entry_adapter.py")
    print("Responsibility: Protocol adaptation and external service wrapping ONLY")
    print()

    violations = []

    # Analyze clients.py
    print("Scanning clients.py...")
    clients_file = Path("src/flext_ldap/clients.py")
    if clients_file.exists():
        with Path(clients_file).open(encoding="utf-8") as f:
            content = f.read()
            content.split("\n")

        tree = ast.parse(content)

        # Check for wrapper methods (pure delegation)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and len(node.body) == 1:
                # Check if method just returns a call (wrapper pattern)
                stmt = node.body[0]
                if isinstance(stmt, ast.Return) and isinstance(
                    stmt.value, ast.Call
                ):
                    # This is likely a pure wrapper
                    violations.append(
                        Violation(
                            file="src/flext_ldap/clients.py",
                            line=node.lineno,
                            severity="medium",
                            principle="S",
                            issue=f"Wrapper method '{node.name}' (pure delegation - violates SRP)",
                            suggestion="Remove wrapper, call underlying method directly",
                        )
                    )

    # Analyze entry_adapter.py
    print("Scanning entry_adapter.py...")
    adapter_file = Path("src/flext_ldap/entry_adapter.py")
    if adapter_file.exists():
        with Path(adapter_file).open(encoding="utf-8") as f:
            content = f.read()

        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "FlextLdapModels" in str(node.names):
                violations.append(
                    Violation(
                        file="src/flext_ldap/entry_adapter.py",
                        line=node.lineno,
                        severity="high",
                        principle="D",
                        issue="Adapter imports FlextLdapModels (should only use FlextLdifModels)",
                        suggestion="Update to use FlextLdifModels directly",
                    )
                )

    # Analyze server operations
    print("Scanning servers/...")
    servers_dir = Path("src/flext_ldap/servers")
    if servers_dir.exists():
        server_files = list(servers_dir.glob("*.py"))

        # Check for duplicate methods across server implementations
        methods_by_name = defaultdict(list)

        for server_file in server_files:
            if server_file.name in {"__init__.py", "factory.py"}:
                continue

            with Path(server_file).open(encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    for method in node.body:
                        if isinstance(method, ast.FunctionDef):
                            methods_by_name[method.name].append((
                                server_file.name,
                                method.lineno,
                            ))

        # Report duplicate methods
        for method_name, locations in methods_by_name.items():
            if len(locations) > 1 and not method_name.startswith("_"):
                files_with_method = [f"{f}:{line_no}" for f, line_no in locations]
                violations.append(
                    Violation(
                        file="src/flext_ldap/servers/",
                        line=0,
                        severity="high",
                        principle="D",
                        issue=f"Method '{method_name}' duplicated in: {', '.join(files_with_method)}",
                        suggestion="Move to BaseServerOperations or consolidate",
                    )
                )

    return violations


def scan_layer_4_application() -> list[Violation]:
    """Scan Application Layer (api.py, services.py, handlers.py)."""
    print("\n" + "=" * 80)
    print("LAYER 4: APPLICATION LAYER")
    print("=" * 80)
    print("Files: api.py, services/*, handlers.py")
    print("Responsibility: Use case orchestration and business logic ONLY")
    print()

    violations = []

    # Analyze api.py
    print("Scanning api.py...")
    api_file = Path("src/flext_ldap/api.py")
    if api_file.exists():
        with Path(api_file).open(encoding="utf-8") as f:
            content = f.read()

        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "FlextLdap":
                # Count methods
                methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
                if len(methods) > 20:
                    violations.append(
                        Violation(
                            file="src/flext_ldap/api.py",
                            line=node.lineno,
                            severity="high",
                            principle="S",
                            issue=f"FlextLdap class has {len(methods)} methods (too many responsibilities)",
                            suggestion="Split into focused API classes or delegate to services",
                        )
                    )

                # Check for wrapper methods
                for method in methods:
                    if len(method.body) == 1:
                        stmt = method.body[0]
                        if isinstance(stmt, ast.Return) and isinstance(
                            stmt.value, ast.Call
                        ):
                            violations.append(
                                Violation(
                                    file="src/flext_ldap/api.py",
                                    line=method.lineno,
                                    severity="medium",
                                    principle="S",
                                    issue=f"Wrapper method '{method.name}' in API",
                                    suggestion="Remove wrapper, call service directly",
                                )
                            )

    # Analyze services
    print("Scanning services/...")
    services_dir = Path("src/flext_ldap/services")
    if services_dir.exists():
        for svc_file in services_dir.glob("*.py"):
            if svc_file.name == "__init__.py":
                continue

            with Path(svc_file).open(encoding="utf-8") as f:
                content = f.read()

            # Check for infrastructure imports (DI violation)
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module and (
                    "ldap3" in node.module or "clients" in node.module
                ):
                    violations.append(
                        Violation(
                            file=f"src/flext_ldap/services/{svc_file.name}",
                            line=node.lineno,
                            severity="high",
                            principle="D",
                            issue=f"Service imports concrete infrastructure: {node.module}",
                            suggestion="Depend on abstractions/protocols instead",
                        )
                    )

    return violations


def main() -> None:
    """Run complete SOLID analysis on all layers."""
    print("\n" + "=" * 80)
    print("FLEXT-LDAP SOLID VIOLATIONS ANALYSIS")
    print("=" * 80)

    all_violations = []

    # Scan each layer
    all_violations.extend(scan_layer_1_foundation())
    all_violations.extend(scan_layer_2_domain())
    all_violations.extend(scan_layer_3_infrastructure())
    all_violations.extend(scan_layer_4_application())

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_violations.sort(
        key=lambda v: (severity_order.get(v.severity, 4), v.file, v.line)
    )

    # Report
    print("\n" + "=" * 80)
    print("VIOLATIONS SUMMARY")
    print("=" * 80)

    by_principle = defaultdict(list)
    by_severity = defaultdict(list)

    for v in all_violations:
        by_principle[v.principle].append(v)
        by_severity[v.severity].append(v)

    print(f"\nTotal Violations: {len(all_violations)}")
    print(f"Critical: {len(by_severity['critical'])}")
    print(f"High: {len(by_severity['high'])}")
    print(f"Medium: {len(by_severity['medium'])}")
    print(f"Low: {len(by_severity['low'])}")

    print("\nBy Principle:")
    for principle in ["S", "O", "L", "I", "D"]:
        print(f"  {principle}: {len(by_principle[principle])} violations")

    # Detailed report
    print("\n" + "=" * 80)
    print("DETAILED VIOLATIONS")
    print("=" * 80)

    for violation in all_violations:
        print(
            f"\n[{violation.severity.upper()}] {violation.principle} - {violation.file}:{violation.line}"
        )
        print(f"  Issue:      {violation.issue}")
        print(f"  Suggestion: {violation.suggestion}")

    # Priority list
    print("\n" + "=" * 80)
    print("PRIORITY FIX ORDER")
    print("=" * 80)

    critical = [v for v in all_violations if v.severity == "critical"]
    if critical:
        print(f"\n🔴 CRITICAL ({len(critical)} must fix first):")
        for v in critical[:10]:  # Show first 10
            print(f"  - {v.principle}: {v.file}:{v.line} - {v.issue}")

    high = [v for v in all_violations if v.severity == "high"]
    if high:
        print(f"\n🟠 HIGH ({len(high)} should fix):")
        for v in high[:10]:  # Show first 10
            print(f"  - {v.principle}: {v.file}:{v.line} - {v.issue}")

    print("\n" + "=" * 80)
    print("NEXT: Fix violations layer by layer, starting with Foundation Layer")
    print("=" * 80)


if __name__ == "__main__":
    main()
