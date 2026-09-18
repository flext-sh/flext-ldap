# from flext-ldap/docs/maintenance/troubleshooting.md:636
# Monitor memory usage
import psutil
import os

process = psutil.Process(os.getpid())
print(f"Memory usage: {process.memory_info().rss / 1024 / 1024:.1f} MB")```
### Network Debugging

