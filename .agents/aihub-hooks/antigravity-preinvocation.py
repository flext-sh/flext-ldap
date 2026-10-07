#!/usr/bin/env python3
"""AI Hub hook projection: antigravity-preinvocation.py.

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
    '{"injectSteps":[{"ephemeralMessage":"<!-- AIHUB-GOVERNANCE-CAPSULE v1 sh'
    'a256:5888ee9f8147f63364a4f7cd6906e9d837f58cb8a8546844760c526ecb1a303b --'
    '>\\n# Generated session governance capsule\\n\\nThis projection is deriv'
    'ed by `agentsctl sync`; edit canonical `AGENTS.md`, `rules/`, `skills/`,'
    ' or `commands/`, never this output. The operator\'s newest request has p'
    'recedence. Provider hooks are delivery mechanisms, not policy owners.\\n'
    '\\n## Rule `architecture/engineering-core`\\n\\n# Engineering core\\n\\n'
    'For every implementation:\\n\\n1. Research repository owners, dependenci'
    'es, and canonical documentation.\\n2. Remove scope without a current req'
    'uirement or consumer (YAGNI).\\n3. Elect one writable authority; every o'
    'ther copy is a generated projection\\n   (SSOT).\\n4. Apply SOLID only t'
    'o a responsibility or dependency boundary under change.\\n5. Implement t'
    'hrough the owner and simplify without weakening behavior.\\n6. Remove du'
    'plication and god components; recheck YAGNI, SSOT, SOLID.\\n7. Exercise '
    'runtime behavior, run every applicable native gate, and complete\\n   th'
    'e approved landing cycle before changing phase.\\n\\nAt a cross-boundary'
    ' failure, prove the producer contract and output. Fix its\\nowner when i'
    'nvalid or the receiver when it conforms. Never alter a correct\\nadjacen'
    't owner for an invalid consumer; symptom workarounds are defects.\\n\\nH'
    'ardcodes, normalized failure, failover, retry, fallback, compatibility,'
    '\\npartial execution, keyring, and unevidenced success are defects. Type'
    'd owners\\nkeep defaults. The first exception escapes its CLI with trace'
    'back and cause.\\n\\nGit, runtime, build, and tests are baseline. Auxili'
    'ary tracking is a capability.\\nAuxiliary capabilities apply only when a'
    'uthorized and selected; installation\\nnever selects. Do not load, probe'
    ', or gate dormant capabilities. Invalid\\nselected authorization, config'
    'uration, readiness, or result fails without\\nfallback. Require only non'
    '-derivable values.\\n\\nAn external token validation without its token i'
    's not executed and is recorded\\nas `NOT EXECUTED`, never green; it does'
    ' not block offline gates, landing, or\\npost-merge proof. Direct invocat'
    'ion selects it: the token becomes required and\\nany failure escapes wit'
    'hout skip, catch, fallback, or normalization.\\n\\nCompose with `general'
    'ized ownership` (rule file),\\n`strict execution` (rule file),\\n`runtim'
    'e evidence` (rule file),\\n`storage isolation` (rule file),\\n`security '
    'closure` (rule file).\\n\\n## Rule `coordination/operator-precedence`\\n'
    '\\n# Newest operator instruction wins; adjust artifacts to it\\n\\nAutho'
    'rity order: operator request > declared orchestration contract > canonic'
    'al\\ntracker > ADRs > skills > docs, and newest supersedes oldest. On co'
    'nflict,\\nadjust the lower or older artifact to match; never override th'
    'e operator to\\nsatisfy stale guidance.\\n\\nWhile orchestration and tra'
    'cker runtimes are suspended, do not invoke them.\\nCreate no substitute '
    'tracker or ledger, preserve implementation evidence only\\nin separately'
    ' authorized Git/PR/CI, and leave phase closure open.\\n\\nExact operator'
    ' authorization naming targets, disposition, recovery, and\\nvalidation s'
    'urvives interruption, divergence, and red gates; re-preflight and\\ncont'
    'inue. Ask only when the effect expands beyond it or two evidenced curren'
    't\\nintentions conflict. State alone proves no intention, actor, or proc'
    'ess.\\n\\n## Rule `ethics/professional-integrity`\\n\\n# Professional in'
    'tegrity is absolute\\n\\nNever lie, fabricate evidence, hide a blocker, '
    'bypass a gate, or patch a symptom\\nonly to make a check pass. Fix the g'
    'eneralized root cause with full context and\\nreport exact command, work'
    'ing directory, exit code and decisive output.\\n\\n## Rule `runtime/stri'
    'ct-execution`\\n\\n# Strict execution is universal and non-optional\\n'
    '\\nEvery project and projected agent applies all of these policies toget'
    'her:\\n\\n- `fail loud` (rule file);\\n- `no fallback` (rule file);\\n- '
    '`preflight before effects` (rule file);\\n- `required environment` (rule'
    ' file);\\n- `atomic effects` (rule file);\\n- `causal subprocess propaga'
    'tion` (rule file);\\n- `no keyring` (rule file);\\n- `zero residue` (rul'
    'e file).\\n\\nThe policies are cumulative. A project rule may make them '
    'narrower or reject\\nmore inputs; it cannot relax, catch, normalize, ski'
    'p, defer, or route around any\\nof them. Existing opposing behavior is a'
    ' blocking violation to exterminate at\\nits owner, never grandfathered c'
    'ompatibility.\\n\\nResolve gate applicability before invocation. A dorma'
    'nt external-token gate is\\nnot executed; selecting or invoking it appli'
    'es every policy above.\\n\\n## Capability indexes\\n\\nSkills: caveman, '
    'context-canary, fix-forward-collaboration, governance-audit, operator-co'
    'rrection-learning, plan-focus-recovery, sprint-closure, strategic-compac'
    't, verification-loop\\nCommands: add-language-rules, database-migration,'
    ' feature-development, ghi-list, pr-list, ralph-loop, security-triage, sy'
    'nthesize-governance\\n"}]}',
)
json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
