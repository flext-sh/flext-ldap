#!/usr/bin/env python3
"""Fix all indentation issues in services.py."""

import re

# Read the file
with open("src/flext_ldap/application/services.py", encoding="utf-8") as f:
    content = f.read()

# Fix all exception returns
content = re.sub(
    r"(\s+except Exception as e:)\n\s+return", r"\1\n            return", content,
)

# Fix all if statements inside for loops
content = re.sub(r"(\s+for [^:]+:)\n(\s+)if ", r"\1\n\2    if ", content)

# Fix all returns inside if statements
content = re.sub(r"(\s+if [^:]+:)\n(\s+)return", r"\1\n\2    return", content)

# Fix all del statements
content = re.sub(r"(\s+if [^:]+:)\n(\s+)del ", r"\1\n\2    del ", content)

# Fix all setattr statements
content = re.sub(r"(\s+if [^:]+:)\n(\s+)setattr", r"\1\n\2    setattr", content)

# Fix list comprehensions
content = re.sub(r"(\s+if [^:]+:)\n(\s+)[a-z_]+ = \[", r"\1\n\2    \g<2>= [", content)

# Fix operations method calls
content = re.sub(
    r"(\s+if [^:]+:)\n(\s+)[a-z_]+\.[a-z_]+\(", r"\1\n\2    \g<2>.[a-z_]+(", content,
)

# Fix class indentation
content = re.sub(r'(class [^:]+:)\n\s+"""([^"]+)"""', r'\1\n    """\2"""', content)

# Fix __init__ indentation
content = re.sub(r"(\s+def __init__[^:]+:)\n\s+self\._", r"\1\n        self._", content)

# Write the fixed content
with open("src/flext_ldap/application/services.py", "w", encoding="utf-8") as f:
    f.write(content)
