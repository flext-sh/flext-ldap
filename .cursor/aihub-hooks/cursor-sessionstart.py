#!/usr/bin/env python3
"""AI Hub hook projection: cursor-sessionstart.py.

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
response = json.loads(
    '{"additional_context":"<!-- AIHUB-GOVERNANCE-CAPSULE v1 sha256:5888ee9f8'
    "147f63364a4f7cd6906e9d837f58cb8a8546844760c526ecb1a303b -->\\n# Generate"
    "d session governance capsule\\n\\nThis projection is derived by `agentsc"
    "tl sync`; edit canonical `AGENTS.md`, `rules/`, `skills/`, or `commands/"
    "`, never this output. The operator's newest request has precedence. Pro"
    "vider hooks are delivery mechanisms, not policy owners.\\n\\n## Rule `ar"
    "chitecture/engineering-core`\\n\\n# Engineering core\\n\\nFor every impl"
    "ementation:\\n\\n1. Research repository owners, dependencies, and canoni"
    "cal documentation.\\n2. Remove scope without a current requirement or co"
    "nsumer (YAGNI).\\n3. Elect one writable authority; every other copy is a"
    " generated projection\\n   (SSOT).\\n4. Apply SOLID only to a responsibi"
    "lity or dependency boundary under change.\\n5. Implement through the own"
    "er and simplify without weakening behavior.\\n6. Remove duplication and "
    "god components; recheck YAGNI, SSOT, SOLID.\\n7. Exercise runtime behavi"
    "or, run every applicable native gate, and complete\\n   the approved lan"
    "ding cycle before changing phase.\\n\\nAt a cross-boundary failure, prov"
    "e the producer contract and output. Fix its\\nowner when invalid or the "
    "receiver when it conforms. Never alter a correct\\nadjacent owner for an"
    " invalid consumer; symptom workarounds are defects.\\n\\nHardcodes, norm"
    "alized failure, failover, retry, fallback, compatibility,\\npartial exec"
    "ution, keyring, and unevidenced success are defects. Typed owners\\nkeep"
    " defaults. The first exception escapes its CLI with traceback and cause."
    "\\n\\nGit, runtime, build, and tests are baseline. Auxiliary tracking is"
    " a capability.\\nAuxiliary capabilities apply only when authorized and s"
    "elected; installation\\nnever selects. Do not load, probe, or gate dorma"
    "nt capabilities. Invalid\\nselected authorization, configuration, readin"
    "ess, or result fails without\\nfallback. Require only non-derivable valu"
    "es.\\n\\nAn external token validation without its token is not executed "
    "and is recorded\\nas `NOT EXECUTED`, never green; it does not block offl"
    "ine gates, landing, or\\npost-merge proof. Direct invocation selects it:"
    " the token becomes required and\\nany failure escapes without skip, catc"
    "h, fallback, or normalization.\\n\\nCompose with `generalized ownership`"
    " (rule file),\\n`strict execution` (rule file),\\n`runtime evidence` (ru"
    "le file),\\n`storage isolation` (rule file),\\n`security closure` (rule "
    "file).\\n\\n## Rule `coordination/operator-precedence`\\n\\n# Newest ope"
    "rator instruction wins; adjust artifacts to it\\n\\nAuthority order: ope"
    "rator request > declared orchestration contract > canonical\\ntracker > "
    "ADRs > skills > docs, and newest supersedes oldest. On conflict,\\nadjus"
    "t the lower or older artifact to match; never override the operator to"
    "\\nsatisfy stale guidance.\\n\\nWhile orchestration and tracker runtimes"
    " are suspended, do not invoke them.\\nCreate no substitute tracker or le"
    "dger, preserve implementation evidence only\\nin separately authorized G"
    "it/PR/CI, and leave phase closure open.\\n\\nExact operator authorizatio"
    "n naming targets, disposition, recovery, and\\nvalidation survives inter"
    "ruption, divergence, and red gates; re-preflight and\\ncontinue. Ask onl"
    "y when the effect expands beyond it or two evidenced current\\nintention"
    "s conflict. State alone proves no intention, actor, or process.\\n\\n## "
    "Rule `ethics/professional-integrity`\\n\\n# Professional integrity is ab"
    "solute\\n\\nNever lie, fabricate evidence, hide a blocker, bypass a gate"
    ", or patch a symptom\\nonly to make a check pass. Fix the generalized ro"
    "ot cause with full context and\\nreport exact command, working directory"
    ", exit code and decisive output.\\n\\n## Rule `runtime/strict-execution`"
    "\\n\\n# Strict execution is universal and non-optional\\n\\nEvery projec"
    "t and projected agent applies all of these policies together:\\n\\n- `fa"
    "il loud` (rule file);\\n- `no fallback` (rule file);\\n- `preflight befo"
    "re effects` (rule file);\\n- `required environment` (rule file);\\n- `at"
    "omic effects` (rule file);\\n- `causal subprocess propagation` (rule fil"
    "e);\\n- `no keyring` (rule file);\\n- `zero residue` (rule file).\\n\\nT"
    "he policies are cumulative. A project rule may make them narrower or rej"
    "ect\\nmore inputs; it cannot relax, catch, normalize, skip, defer, or ro"
    "ute around any\\nof them. Existing opposing behavior is a blocking viola"
    "tion to exterminate at\\nits owner, never grandfathered compatibility."
    "\\n\\nResolve gate applicability before invocation. A dormant external-t"
    "oken gate is\\nnot executed; selecting or invoking it applies every poli"
    "cy above.\\n\\n## Capability indexes\\n\\nSkills: caveman, context-canar"
    "y, fix-forward-collaboration, governance-audit, operator-correction-lear"
    "ning, plan-focus-recovery, sprint-closure, strategic-compact, verificati"
    "on-loop\\nCommands: add-language-rules, database-migration, feature-deve"
    "lopment, ghi-list, pr-list, ralph-loop, security-triage, synthesize-gove"
    'rnance\\n"}',
)
json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
