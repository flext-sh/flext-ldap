#!/usr/bin/env python3
"""AI Hub hook projection: copilot-subagentstart.py.

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
    '{"additionalContext":"<!-- AIHUB-GOVERNANCE-CAPSULE v1 sha256:5888ee9f81'
    '47f63364a4f7cd6906e9d837f58cb8a8546844760c526ecb1a303b -->\\n# Generated'
    ' session governance capsule\\n\\nThis projection is derived by `agentsct'
    'l sync`; edit canonical `AGENTS.md`, `rules/`, `skills/`, or `commands/`'
    ', never this output. The operator\'s newest request has precedence. Prov'
    'ider hooks are delivery mechanisms, not policy owners.\\n\\n## Rule `arc'
    'hitecture/engineering-core`\\n\\n# Engineering core\\n\\nFor every imple'
    'mentation:\\n\\n1. Research repository owners, dependencies, and canonic'
    'al documentation.\\n2. Remove scope without a current requirement or con'
    'sumer (YAGNI).\\n3. Elect one writable authority; every other copy is a '
    'generated projection\\n   (SSOT).\\n4. Apply SOLID only to a responsibil'
    'ity or dependency boundary under change.\\n5. Implement through the owne'
    'r and simplify without weakening behavior.\\n6. Remove duplication and g'
    'od components; recheck YAGNI, SSOT, SOLID.\\n7. Exercise runtime behavio'
    'r, run every applicable native gate, and complete\\n   the approved land'
    'ing cycle before changing phase.\\n\\nAt a cross-boundary failure, prove'
    ' the producer contract and output. Fix its\\nowner when invalid or the r'
    'eceiver when it conforms. Never alter a correct\\nadjacent owner for an '
    'invalid consumer; symptom workarounds are defects.\\n\\nHardcodes, norma'
    'lized failure, failover, retry, fallback, compatibility,\\npartial execu'
    'tion, keyring, and unevidenced success are defects. Typed owners\\nkeep '
    'defaults. The first exception escapes its CLI with traceback and cause.\'
    '\n\\nGit, runtime, build, and tests are baseline. Auxiliary tracking is '
    'a capability.\\nAuxiliary capabilities apply only when authorized and se'
    'lected; installation\\nnever selects. Do not load, probe, or gate dorman'
    't capabilities. Invalid\\nselected authorization, configuration, readine'
    'ss, or result fails without\\nfallback. Require only non-derivable value'
    's.\\n\\nAn external token validation without its token is not executed a'
    'nd is recorded\\nas `NOT EXECUTED`, never green; it does not block offli'
    'ne gates, landing, or\\npost-merge proof. Direct invocation selects it: '
    'the token becomes required and\\nany failure escapes without skip, catch'
    ', fallback, or normalization.\\n\\nCompose with `generalized ownership` '
    '(rule file),\\n`strict execution` (rule file),\\n`runtime evidence` (rul'
    'e file),\\n`storage isolation` (rule file),\\n`security closure` (rule f'
    'ile).\\n\\n## Rule `coordination/operator-precedence`\\n\\n# Newest oper'
    'ator instruction wins; adjust artifacts to it\\n\\nAuthority order: oper'
    'ator request > declared orchestration contract > canonical\\ntracker > A'
    'DRs > skills > docs, and newest supersedes oldest. On conflict,\\nadjust'
    ' the lower or older artifact to match; never override the operator to\\n'
    'satisfy stale guidance.\\n\\nWhile orchestration and tracker runtimes ar'
    'e suspended, do not invoke them.\\nCreate no substitute tracker or ledge'
    'r, preserve implementation evidence only\\nin separately authorized Git/'
    'PR/CI, and leave phase closure open.\\n\\nExact operator authorization n'
    'aming targets, disposition, recovery, and\\nvalidation survives interrup'
    'tion, divergence, and red gates; re-preflight and\\ncontinue. Ask only w'
    'hen the effect expands beyond it or two evidenced current\\nintentions c'
    'onflict. State alone proves no intention, actor, or process.\\n\\n## Rul'
    'e `ethics/professional-integrity`\\n\\n# Professional integrity is absol'
    'ute\\n\\nNever lie, fabricate evidence, hide a blocker, bypass a gate, o'
    'r patch a symptom\\nonly to make a check pass. Fix the generalized root '
    'cause with full context and\\nreport exact command, working directory, e'
    'xit code and decisive output.\\n\\n## Rule `runtime/strict-execution`\\n'
    '\\n# Strict execution is universal and non-optional\\n\\nEvery project a'
    'nd projected agent applies all of these policies together:\\n\\n- `fail '
    'loud` (rule file);\\n- `no fallback` (rule file);\\n- `preflight before '
    'effects` (rule file);\\n- `required environment` (rule file);\\n- `atomi'
    'c effects` (rule file);\\n- `causal subprocess propagation` (rule file);'
    '\\n- `no keyring` (rule file);\\n- `zero residue` (rule file).\\n\\nThe '
    'policies are cumulative. A project rule may make them narrower or reject'
    '\\nmore inputs; it cannot relax, catch, normalize, skip, defer, or route'
    ' around any\\nof them. Existing opposing behavior is a blocking violatio'
    'n to exterminate at\\nits owner, never grandfathered compatibility.\\n\\'
    'nResolve gate applicability before invocation. A dormant external-token '
    'gate is\\nnot executed; selecting or invoking it applies every policy ab'
    'ove.\\n\\n## Capability indexes\\n\\nSkills: caveman, context-canary, fi'
    'x-forward-collaboration, governance-audit, operator-correction-learning,'
    ' plan-focus-recovery, sprint-closure, strategic-compact, verification-lo'
    'op\\nCommands: add-language-rules, database-migration, feature-developme'
    'nt, ghi-list, pr-list, ralph-loop, security-triage, synthesize-governanc'
    'e\\n"}'
)
json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
