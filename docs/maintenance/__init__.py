"""Project-local wrapper package for shared FLEXT LDAP documentation maintenance."""

from __future__ import annotations

import os
from pathlib import Path

from flext_quality.docs_maintenance.profiles.advanced import *  # noqa: F403

_PROJECT_ROOT = str(Path(__file__).resolve().parents[2])
os.environ.setdefault("FLEXT_DOC_PROJECT_ROOT", _PROJECT_ROOT)
os.environ.setdefault("FLEXT_DOC_PROFILE", "advanced")
