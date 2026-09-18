# from flext-ldap_docs/maintenance/troubleshooting.md:656
# Debug file operations
import os
import pathlib

print(f"Current directory: {os.getcwd()}")
print(f"Docs directory exists: {pathlib.Path('docs').exists()}")
print(f"Docs directory contents: {os.listdir('docs')}")```
## Advanced Troubleshooting

### Custom Diagnostic Scripts

Create diagnostic scripts for complex issues:

