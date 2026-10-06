#!/usr/bin/env python3
"""AI Hub hook projection: cursor-precompact.py.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import json
import sys

payload = json.load(sys.stdin)
if not isinstance(payload, dict):
    msg = "hook input must be a JSON object"
    raise TypeError(msg)
response = json.loads("{}")
json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
