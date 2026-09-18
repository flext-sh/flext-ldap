# from flext-ldap_docs/troubleshooting.md:677
from flext_cli import u

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# FLEXT logger with debug level
logger = u.fetch_logger(__name__)
logger.setLevel(logging.DEBUG)```
### Network Debugging

