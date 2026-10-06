#!/usr/bin/env python3
"""AI Hub hook projection: codex-sessionstart.py.

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
    '{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext'
    '":"<!-- AIHUB-GOVERNANCE-CAPSULE v1 sha256:5888ee9f8147f63364a4f7cd6906e'
    '9d837f58cb8a8546844760c526ecb1a303b -->\\n# Generated session governance'
    ' capsule\\n\\nThis projection is derived by `agentsctl sync`; edit canon'
    'ical `AGENTS.md`, `rules/`, `skills/`, or `commands/`, never this output'
    '. The operator\'s newest request has precedence. Provider hooks are deli'
    'very mechanisms, not policy owners.\\n\\n## Rule `architecture/engineeri'
    'ng-core`\\n\\n# Engineering core\\n\\nFor every implementation:\\n\\n1. '
    'Research repository owners, dependencies, and canonical documentation.'
    '\\n2. Remove scope without a current requirement or consumer (YAGNI).\\n'
    '3. Elect one writable authority; every other copy is a generated project'
    'ion\\n   (SSOT).\\n4. Apply SOLID only to a responsibility or dependency'
    ' boundary under change.\\n5. Implement through the owner and simplify wi'
    'thout weakening behavior.\\n6. Remove duplication and god components; re'
    'check YAGNI, SSOT, SOLID.\\n7. Exercise runtime behavior, run every appl'
    'icable native gate, and complete\\n   the approved landing cycle before '
    'changing phase.\\n\\nAt a cross-boundary failure, prove the producer con'
    'tract and output. Fix its\\nowner when invalid or the receiver when it c'
    'onforms. Never alter a correct\\nadjacent owner for an invalid consumer;'
    ' symptom workarounds are defects.\\n\\nHardcodes, normalized failure, fa'
    'ilover, retry, fallback, compatibility,\\npartial execution, keyring, an'
    'd unevidenced success are defects. Typed owners\\nkeep defaults. The fir'
    'st exception escapes its CLI with traceback and cause.\\n\\nGit, runtime'
    ', build, and tests are baseline. Auxiliary tracking is a capability.\\nA'
    'uxiliary capabilities apply only when authorized and selected; installat'
    'ion\\nnever selects. Do not load, probe, or gate dormant capabilities. I'
    'nvalid\\nselected authorization, configuration, readiness, or result fai'
    'ls without\\nfallback. Require only non-derivable values.\\n\\nAn extern'
    'al token validation without its token is not executed and is recorded\\n'
    'as `NOT EXECUTED`, never green; it does not block offline gates, landing'
    ', or\\npost-merge proof. Direct invocation selects it: the token becomes'
    ' required and\\nany failure escapes without skip, catch, fallback, or no'
    'rmalization.\\n\\nCompose with `generalized ownership` (rule file),\\n`s'
    'trict execution` (rule file),\\n`runtime evidence` (rule file),\\n`stora'
    'ge isolation` (rule file),\\n`security closure` (rule file).\\n\\n## Rul'
    'e `coordination/operator-precedence`\\n\\n# Newest operator instruction '
    'wins; adjust artifacts to it\\n\\nAuthority order: operator request > de'
    'clared orchestration contract > canonical\\ntracker > ADRs > skills > do'
    'cs, and newest supersedes oldest. On conflict,\\nadjust the lower or old'
    'er artifact to match; never override the operator to\\nsatisfy stale gui'
    'dance.\\n\\nWhile orchestration and tracker runtimes are suspended, do n'
    'ot invoke them.\\nCreate no substitute tracker or ledger, preserve imple'
    'mentation evidence only\\nin separately authorized Git/PR/CI, and leave '
    'phase closure open.\\n\\nExact operator authorization naming targets, di'
    'sposition, recovery, and\\nvalidation survives interruption, divergence,'
    ' and red gates; re-preflight and\\ncontinue. Ask only when the effect ex'
    'pands beyond it or two evidenced current\\nintentions conflict. State al'
    'one proves no intention, actor, or process.\\n\\n## Rule `ethics/profess'
    'ional-integrity`\\n\\n# Professional integrity is absolute\\n\\nNever li'
    'e, fabricate evidence, hide a blocker, bypass a gate, or patch a symptom'
    '\\nonly to make a check pass. Fix the generalized root cause with full c'
    'ontext and\\nreport exact command, working directory, exit code and deci'
    'sive output.\\n\\n## Rule `runtime/strict-execution`\\n\\n# Strict execu'
    'tion is universal and non-optional\\n\\nEvery project and projected agen'
    't applies all of these policies together:\\n\\n- `fail loud` (rule file)'
    ';\\n- `no fallback` (rule file);\\n- `preflight before effects` (rule fi'
    'le);\\n- `required environment` (rule file);\\n- `atomic effects` (rule '
    'file);\\n- `causal subprocess propagation` (rule file);\\n- `no keyring`'
    ' (rule file);\\n- `zero residue` (rule file).\\n\\nThe policies are cumu'
    'lative. A project rule may make them narrower or reject\\nmore inputs; i'
    't cannot relax, catch, normalize, skip, defer, or route around any\\nof '
    'them. Existing opposing behavior is a blocking violation to exterminate '
    'at\\nits owner, never grandfathered compatibility.\\n\\nResolve gate app'
    'licability before invocation. A dormant external-token gate is\\nnot exe'
    'cuted; selecting or invoking it applies every policy above.\\n\\n## Capa'
    'bility indexes\\n\\nSkills: caveman, context-canary, fix-forward-collabo'
    'ration, governance-audit, operator-correction-learning, plan-focus-recov'
    'ery, sprint-closure, strategic-compact, verification-loop\\nCommands: ad'
    'd-language-rules, database-migration, feature-development, ghi-list, pr-'
    'list, ralph-loop, security-triage, synthesize-governance\\n"}}',
)
json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
