#!/usr/bin/env python3
"""AI Hub hook projection: gemini-beforeagent.py.

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
    '{"hookSpecificOutput":{"hookEventName":"BeforeAgent","additionalContext"'
    ':"<!-- AIHUB-GOVERNANCE-CAPSULE v1 sha256:5888ee9f8147f63364a4f7cd6906e9'
    'd837f58cb8a8546844760c526ecb1a303b -->\\n# Generated session governance '
    'capsule\\n\\nThis projection is derived by `agentsctl sync`; edit canoni'
    'cal `AGENTS.md`, `rules/`, `skills/`, or `commands/`, never this output.'
    ' The operator\'s newest request has precedence. Provider hooks are deliv'
    'ery mechanisms, not policy owners.\\n\\n## Rule `architecture/engineerin'
    'g-core`\\n\\n# Engineering core\\n\\nFor every implementation:\\n\\n1. R'
    'esearch repository owners, dependencies, and canonical documentation.\\n'
    '2. Remove scope without a current requirement or consumer (YAGNI).\\n3. '
    'Elect one writable authority; every other copy is a generated projection'
    '\\n   (SSOT).\\n4. Apply SOLID only to a responsibility or dependency bo'
    'undary under change.\\n5. Implement through the owner and simplify witho'
    'ut weakening behavior.\\n6. Remove duplication and god components; reche'
    'ck YAGNI, SSOT, SOLID.\\n7. Exercise runtime behavior, run every applica'
    'ble native gate, and complete\\n   the approved landing cycle before cha'
    'nging phase.\\n\\nAt a cross-boundary failure, prove the producer contra'
    'ct and output. Fix its\\nowner when invalid or the receiver when it conf'
    'orms. Never alter a correct\\nadjacent owner for an invalid consumer; sy'
    'mptom workarounds are defects.\\n\\nHardcodes, normalized failure, failo'
    'ver, retry, fallback, compatibility,\\npartial execution, keyring, and u'
    'nevidenced success are defects. Typed owners\\nkeep defaults. The first '
    'exception escapes its CLI with traceback and cause.\\n\\nGit, runtime, b'
    'uild, and tests are baseline. Auxiliary tracking is a capability.\\nAuxi'
    'liary capabilities apply only when authorized and selected; installation'
    '\\nnever selects. Do not load, probe, or gate dormant capabilities. Inva'
    'lid\\nselected authorization, configuration, readiness, or result fails '
    'without\\nfallback. Require only non-derivable values.\\n\\nAn external '
    'token validation without its token is not executed and is recorded\\nas '
    '`NOT EXECUTED`, never green; it does not block offline gates, landing, o'
    'r\\npost-merge proof. Direct invocation selects it: the token becomes re'
    'quired and\\nany failure escapes without skip, catch, fallback, or norma'
    'lization.\\n\\nCompose with `generalized ownership` (rule file),\\n`stri'
    'ct execution` (rule file),\\n`runtime evidence` (rule file),\\n`storage '
    'isolation` (rule file),\\n`security closure` (rule file).\\n\\n## Rule `'
    'coordination/operator-precedence`\\n\\n# Newest operator instruction win'
    's; adjust artifacts to it\\n\\nAuthority order: operator request > decla'
    'red orchestration contract > canonical\\ntracker > ADRs > skills > docs,'
    ' and newest supersedes oldest. On conflict,\\nadjust the lower or older '
    'artifact to match; never override the operator to\\nsatisfy stale guidan'
    'ce.\\n\\nWhile orchestration and tracker runtimes are suspended, do not '
    'invoke them.\\nCreate no substitute tracker or ledger, preserve implemen'
    'tation evidence only\\nin separately authorized Git/PR/CI, and leave pha'
    'se closure open.\\n\\nExact operator authorization naming targets, dispo'
    'sition, recovery, and\\nvalidation survives interruption, divergence, an'
    'd red gates; re-preflight and\\ncontinue. Ask only when the effect expan'
    'ds beyond it or two evidenced current\\nintentions conflict. State alone'
    ' proves no intention, actor, or process.\\n\\n## Rule `ethics/profession'
    'al-integrity`\\n\\n# Professional integrity is absolute\\n\\nNever lie, '
    'fabricate evidence, hide a blocker, bypass a gate, or patch a symptom\\n'
    'only to make a check pass. Fix the generalized root cause with full cont'
    'ext and\\nreport exact command, working directory, exit code and decisiv'
    'e output.\\n\\n## Rule `runtime/strict-execution`\\n\\n# Strict executio'
    'n is universal and non-optional\\n\\nEvery project and projected agent a'
    'pplies all of these policies together:\\n\\n- `fail loud` (rule file);'
    '\\n- `no fallback` (rule file);\\n- `preflight before effects` (rule fil'
    'e);\\n- `required environment` (rule file);\\n- `atomic effects` (rule f'
    'ile);\\n- `causal subprocess propagation` (rule file);\\n- `no keyring` '
    '(rule file);\\n- `zero residue` (rule file).\\n\\nThe policies are cumul'
    'ative. A project rule may make them narrower or reject\\nmore inputs; it'
    ' cannot relax, catch, normalize, skip, defer, or route around any\\nof t'
    'hem. Existing opposing behavior is a blocking violation to exterminate a'
    't\\nits owner, never grandfathered compatibility.\\n\\nResolve gate appl'
    'icability before invocation. A dormant external-token gate is\\nnot exec'
    'uted; selecting or invoking it applies every policy above.\\n\\n## Capab'
    'ility indexes\\n\\nSkills: caveman, context-canary, fix-forward-collabor'
    'ation, governance-audit, operator-correction-learning, plan-focus-recove'
    'ry, sprint-closure, strategic-compact, verification-loop\\nCommands: add'
    '-language-rules, database-migration, feature-development, ghi-list, pr-l'
    'ist, ralph-loop, security-triage, synthesize-governance\\n"}}',
)
json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
