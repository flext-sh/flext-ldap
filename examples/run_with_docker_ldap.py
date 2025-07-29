#!/usr/bin/env python3
"""Example of running FLEXT-LDAP examples with Docker OpenLDAP container.

This script automatically starts an OpenLDAP container and runs examples against it.
Perfect for testing and demonstration without needing a manual LDAP setup.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

# Add src to path for local testing
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


def start_openldap_container() -> bool:
    """Start OpenLDAP container for testing."""
    try:
        # Stop any existing container
        subprocess.run(
            ["docker", "stop", "flext-ldap-example", "2>/dev/null"],
            check=False,
            shell=True,
        )
        subprocess.run(
            ["docker", "rm", "flext-ldap-example", "2>/dev/null"],
            check=False,
            shell=True,
        )

        print("🐳 Starting OpenLDAP container...")

        # Start new container
        subprocess.run([
            "docker", "run", "-d",
            "--name", "flext-ldap-example",
            "-p", "3389:389",
            "-e", "LDAP_ORGANISATION=FLEXT Example Org",
            "-e", "LDAP_DOMAIN=flext.local",
            "-e", "LDAP_ADMIN_PASSWORD=admin123",
            "-e", "LDAP_CONFIG_PASSWORD=config123",
            "-e", "LDAP_READONLY_USER=false",
            "-e", "LDAP_RFC2307BIS_SCHEMA=true",
            "-e", "LDAP_BACKEND=mdb",
            "-e", "LDAP_TLS=false",
            "-e", "LDAP_REMOVE_CONFIG_AFTER_SETUP=true",
            "osixia/openldap:1.5.0",
        ], check=True)

        # Wait for container to be ready
        print("⏳ Waiting for OpenLDAP to be ready...")
        for attempt in range(30):
            try:
                result = subprocess.run([
                    "docker", "exec", "flext-ldap-example",
                    "ldapsearch", "-x",
                    "-H", "ldap://localhost:389",
                    "-D", "cn=admin,dc=flext,dc=local",
                    "-w", "admin123",
                    "-b", "dc=flext,dc=local",
                    "-s", "base",
                    "(objectClass=*)",
                ], capture_output=True, check=True)

                if result.returncode == 0:
                    print("✅ OpenLDAP container is ready!")
                    return True

            except subprocess.CalledProcessError:
                time.sleep(1)

        print("❌ OpenLDAP container failed to start properly")
        return False

    except Exception as e:
        print(f"❌ Failed to start OpenLDAP container: {e}")
        return False


def stop_openldap_container() -> None:
    """Stop and remove OpenLDAP container."""
    try:
        print("🛑 Stopping OpenLDAP container...")
        subprocess.run(["docker", "stop", "flext-ldap-example"], check=False)
        subprocess.run(["docker", "rm", "flext-ldap-example"], check=False)
        print("✅ Container stopped and removed")
    except Exception as e:
        print(f"⚠️  Error stopping container: {e}")


async def run_examples_with_docker() -> None:
    """Run FLEXT-LDAP examples against Docker OpenLDAP."""
    # Set environment variables for container
    os.environ.update({
        "LDAP_TEST_SERVER": "ldap://localhost:3389",
        "LDAP_TEST_BIND_DN": "cn=admin,dc=flext,dc=local",
        "LDAP_TEST_PASSWORD": "admin123",
        "LDAP_TEST_BASE_DN": "dc=flext,dc=local",
    })

    print("🚀 Running integrated LDAP service example...")

    # Run the integrated example
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from integrated_ldap_service import main as integrated_main
        await integrated_main()
        print("✅ Integrated example completed successfully!")

    except Exception as e:
        print(f"❌ Integrated example failed: {e}")

    print("\n🚀 Running simple client example...")

    # Run the simple client example
    try:
        from ldap_simple_client_example import main as simple_main
        await simple_main()
        print("✅ Simple client example completed successfully!")

    except Exception as e:
        print(f"❌ Simple client example failed: {e}")


async def main() -> None:
    """Main execution function."""
    print("🌟 FLEXT-LDAP Docker Example Runner")
    print("=" * 50)

    # Start container
    if not start_openldap_container():
        print("💥 Failed to start OpenLDAP container. Exiting.")
        return

    try:
        # Run examples
        await run_examples_with_docker()

    finally:
        # Always cleanup
        stop_openldap_container()

    print("\n🎉 Example run completed!")


if __name__ == "__main__":
    # Check if Docker is available
    try:
        subprocess.run(["docker", "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Docker is not available. Please install Docker to run this example.")
        sys.exit(1)

    asyncio.run(main())
