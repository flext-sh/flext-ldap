#!/usr/bin/env python3
"""AST-based code analysis for finding unused/duplicate code in flext-ldap."""

import ast
import sys
from pathlib import Path


class CodeAnalyzer(ast.NodeVisitor):
    """Analyze Python modules for unused code."""

    def __init__(self, filename: str = "") -> None:
        """Initialize CodeAnalyzer with optional filename."""
        self.filename = filename
        self.defined_classes: set[str] = set()
        self.defined_functions: set[str] = set()
        self.defined_methods: dict[str, list[str]] = {}  # class_name -> [method_names]
        self.imported_names: set[str] = set()
        self.used_names: set[str] = set()
        self.class_definitions: dict[str, ast.ClassDef] = {}
        self.function_definitions: dict[str, ast.FunctionDef] = {}

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definition."""
        self.defined_classes.add(node.name)
        self.class_definitions[node.name] = node

        methods = []
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                methods.append(item.name)
                self.defined_methods.setdefault(node.name, []).append(item.name)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        self.defined_functions.add(node.name)
        self.function_definitions[node.name] = node
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definition."""
        self.defined_functions.add(node.name)
        self.function_definitions[node.name] = node
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        """Visit import statement."""
        for alias in node.names:
            name = alias.asname or alias.name
            self.imported_names.add(name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Visit from...import statement."""
        for alias in node.names:
            if alias.name != "*":
                name = alias.asname or alias.name
                self.imported_names.add(name)

    def visit_Name(self, node: ast.Name) -> None:
        """Visit name usage."""
        self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Visit attribute access."""
        self.used_names.add(node.attr)
        self.generic_visit(node)

    def find_unused(self) -> dict[str, set[str]]:
        """Find unused classes and functions."""
        return {
            "unused_classes": self.defined_classes - self.used_names,
            "unused_functions": self.defined_functions - self.used_names,
            "imported_but_unused": self.imported_names - self.used_names,
        }


def analyze_module(file_path: Path) -> dict:
    """Analyze a single Python module."""
    try:
        with Path(file_path).open("r", encoding="utf-8") as f:
            source = f.read()

        tree = ast.parse(source, filename=str(file_path))
        analyzer = CodeAnalyzer(str(file_path))
        analyzer.visit(tree)

        return {
            "file": str(file_path.relative_to(Path.cwd())),
            "status": "OK",
            "unused": analyzer.find_unused(),
            "classes": sorted(analyzer.defined_classes),
            "functions": sorted(analyzer.defined_functions),
            "methods": {k: sorted(v) for k, v in analyzer.defined_methods.items()},
            "imports": sorted(analyzer.imported_names),
        }
    except SyntaxError as e:
        return {
            "file": str(file_path.relative_to(Path.cwd())),
            "status": "SYNTAX_ERROR",
            "error": str(e),
        }
    except Exception as e:
        return {
            "file": str(file_path.relative_to(Path.cwd())),
            "status": "ERROR",
            "error": str(e),
        }


def analyze_project(src_dir: Path) -> dict:
    """Analyze entire project."""
    results = {}

    print(f"Analyzing {src_dir}...")

    for py_file in sorted(src_dir.rglob("*.py")):
        if "__pycache__" not in str(py_file):
            result = analyze_module(py_file)
            results[str(py_file.relative_to(Path.cwd()))] = result

            # Print progress
            if result["status"] == "OK":
                unused = result["unused"]
                if any(unused.values()):
                    print(f"  ⚠️  {result['file']}")

    return results


def print_report(results: dict) -> None:
    """Print analysis report."""
    print("\n" + "=" * 100)
    print("AST-BASED CODE ANALYSIS REPORT - FLEXT-LDAP")
    print("=" * 100)

    unused_classes_total = 0
    unused_functions_total = 0
    unused_imports_total = 0

    # Group by issue type
    files_with_unused_classes = {}
    files_with_unused_functions = {}
    files_with_unused_imports = {}

    for file, data in results.items():
        if data["status"] != "OK":
            continue

        unused = data["unused"]

        if unused["unused_classes"]:
            files_with_unused_classes[file] = unused["unused_classes"]
            unused_classes_total += len(unused["unused_classes"])

        if unused["unused_functions"]:
            files_with_unused_functions[file] = unused["unused_functions"]
            unused_functions_total += len(unused["unused_functions"])

        if unused["imported_but_unused"]:
            files_with_unused_imports[file] = unused["imported_but_unused"]
            unused_imports_total += len(unused["imported_but_unused"])

    # Print unused classes
    if files_with_unused_classes:
        print(f"\n## UNUSED CLASSES ({unused_classes_total} total)\n")
        for file, classes in sorted(files_with_unused_classes.items()):
            print(f"📄 {file}:")
            for cls in sorted(classes):
                print(f"   ❌ class {cls}")

    # Print unused functions
    if files_with_unused_functions:
        print(f"\n## UNUSED FUNCTIONS ({unused_functions_total} total)\n")
        for file, functions in sorted(files_with_unused_functions.items()):
            print(f"📄 {file}:")
            for func in sorted(functions):
                print(f"   ❌ def {func}()")

    # Print unused imports
    if files_with_unused_imports:
        print(f"\n## UNUSED IMPORTS ({unused_imports_total} total)\n")
        for file, imports in sorted(files_with_unused_imports.items()):
            print(f"📄 {file}:")
            for imp in sorted(imports):
                print(f"   ❌ {imp}")

    # Summary
    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    print(f"Total Unused Classes: {unused_classes_total}")
    print(f"Total Unused Functions: {unused_functions_total}")
    print(f"Total Unused Imports: {unused_imports_total}")
    print(f"Total Files Analyzed: {len(results)}")
    print(
        f"Files with Issues: {len(files_with_unused_classes) + len(files_with_unused_functions) + len(files_with_unused_imports)}"
    )
    print("=" * 100 + "\n")


if __name__ == "__main__":
    src = Path("src/flext_ldap")

    if not src.exists():
        print(f"ERROR: {src} not found")
        sys.exit(1)

    results = analyze_project(src)
    print_report(results)
