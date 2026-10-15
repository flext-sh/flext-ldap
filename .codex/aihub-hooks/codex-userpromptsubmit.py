#!/usr/bin/env python3
"""AI Hub hook projection: codex-userpromptsubmit.py.

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
    '{"hookSpecificOutput":{"hookEventName":"UserPromptSubmit","additionalCon'
    'text":"<!-- AIHUB-GOVERNANCE-CAPSULE v1 sha256:5888ee9f8147f63364a4f7cd6'
    "906e9d837f58cb8a8546844760c526ecb1a303b -->\\n# Generated session govern"
    "ance capsule\\n\\nThis projection is derived by `agentsctl sync`; edit c"
    "anonical `AGENTS.md`, `rules/`, `skills/`, or `commands/`, never this ou"
    "tput. The operator's newest request has precedence. Provider hooks are "
    "delivery mechanisms, not policy owners.\\n\\n## Rule `architecture/engin"
    "eering-core`\\n\\n# Engineering core\\n\\nFor every implementation:\\n"
    "\\n1. Research repository owners, dependencies, and canonical documentat"
    "ion.\\n2. Remove scope without a current requirement or consumer (YAGNI)"
    ".\\n3. Elect one writable authority; every other copy is a generated pro"
    "jection\\n   (SSOT).\\n4. Apply SOLID only to a responsibility or depend"
    "ency boundary under change.\\n5. Implement through the owner and simplif"
    "y without weakening behavior.\\n6. Remove duplication and god components"
    "; recheck YAGNI, SSOT, SOLID.\\n7. Exercise runtime behavior, run every "
    "applicable native gate, and complete\\n   the approved landing cycle bef"
    "ore changing phase.\\n\\nAt a cross-boundary failure, prove the producer"
    " contract and output. Fix its\\nowner when invalid or the receiver when "
    "it conforms. Never alter a correct\\nadjacent owner for an invalid consu"
    "mer; symptom workarounds are defects.\\n\\nHardcodes, normalized failure"
    ", failover, retry, fallback, compatibility,\\npartial execution, keyring"
    ", and unevidenced success are defects. Typed owners\\nkeep defaults. The"
    " first exception escapes its CLI with traceback and cause.\\n\\nGit, run"
    "time, build, and tests are baseline. Auxiliary tracking is a capability."
    "\\nAuxiliary capabilities apply only when authorized and selected; insta"
    "llation\\nnever selects. Do not load, probe, or gate dormant capabilitie"
    "s. Invalid\\nselected authorization, configuration, readiness, or result"
    " fails without\\nfallback. Require only non-derivable values.\\n\\nAn ex"
    "ternal token validation without its token is not executed and is recorde"
    "d\\nas `NOT EXECUTED`, never green; it does not block offline gates, lan"
    "ding, or\\npost-merge proof. Direct invocation selects it: the token bec"
    "omes required and\\nany failure escapes without skip, catch, fallback, o"
    "r normalization.\\n\\nCompose with `generalized ownership` (rule file),"
    "\\n`strict execution` (rule file),\\n`runtime evidence` (rule file),\\n`"
    "storage isolation` (rule file),\\n`security closure` (rule file).\\n\\n#"
    "# Rule `coordination/operator-precedence`\\n\\n# Newest operator instruc"
    "tion wins; adjust artifacts to it\\n\\nAuthority order: operator request"
    " > declared orchestration contract > canonical\\ntracker > ADRs > skills"
    " > docs, and newest supersedes oldest. On conflict,\\nadjust the lower o"
    "r older artifact to match; never override the operator to\\nsatisfy stal"
    "e guidance.\\n\\nWhile orchestration and tracker runtimes are suspended,"
    " do not invoke them.\\nCreate no substitute tracker or ledger, preserve "
    "implementation evidence only\\nin separately authorized Git/PR/CI, and l"
    "eave phase closure open.\\n\\nExact operator authorization naming target"
    "s, disposition, recovery, and\\nvalidation survives interruption, diverg"
    "ence, and red gates; re-preflight and\\ncontinue. Ask only when the effe"
    "ct expands beyond it or two evidenced current\\nintentions conflict. Sta"
    "te alone proves no intention, actor, or process.\\n\\n## Rule `ethics/pr"
    "ofessional-integrity`\\n\\n# Professional integrity is absolute\\n\\nNev"
    "er lie, fabricate evidence, hide a blocker, bypass a gate, or patch a sy"
    "mptom\\nonly to make a check pass. Fix the generalized root cause with f"
    "ull context and\\nreport exact command, working directory, exit code and"
    " decisive output.\\n\\n## Rule `runtime/strict-execution`\\n\\n# Strict "
    "execution is universal and non-optional\\n\\nEvery project and projected"
    " agent applies all of these policies together:\\n\\n- `fail loud` (rule "
    "file);\\n- `no fallback` (rule file);\\n- `preflight before effects` (ru"
    "le file);\\n- `required environment` (rule file);\\n- `atomic effects` ("
    "rule file);\\n- `causal subprocess propagation` (rule file);\\n- `no key"
    "ring` (rule file);\\n- `zero residue` (rule file).\\n\\nThe policies are"
    " cumulative. A project rule may make them narrower or reject\\nmore inpu"
    "ts; it cannot relax, catch, normalize, skip, defer, or route around any"
    "\\nof them. Existing opposing behavior is a blocking violation to exterm"
    "inate at\\nits owner, never grandfathered compatibility.\\n\\nResolve ga"
    "te applicability before invocation. A dormant external-token gate is\\nn"
    "ot executed; selecting or invoking it applies every policy above.\\n\\n#"
    "# Capability indexes\\n\\nSkills: caveman, context-canary, fix-forward-c"
    "ollaboration, governance-audit, operator-correction-learning, plan-focus"
    "-recovery, sprint-closure, strategic-compact, verification-loop\\nComman"
    "ds: add-language-rules, database-migration, feature-development, ghi-lis"
    't, pr-list, ralph-loop, security-triage, synthesize-governance\\n"}}',
)
json.dump(response, sys.stdout, ensure_ascii=False, separators=(",", ":"))
sys.stdout.write("\n")
