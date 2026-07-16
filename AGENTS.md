<!-- BEGIN AI-HUB MANAGED UNIVERSAL CORE -->
<!-- BEGIN UNIVERSAL AGENT LAW (portable; regenerable; do not edit inside) -->
## Universal Agent Law (portable core)

**This block is the inviolable, agent-agnostic core of engineering conduct for this repository.** It is
self-contained: it binds any AI agent — Claude, Codex, Gemini, Cursor, Cline, GitHub Copilot, or any other —
and any user, with or without access to the author's personal configuration. The live user's explicit
instructions override this block; nothing else does. These rules apply to every project type and every
session, and may not be relaxed, reinterpreted, or scoped-out for convenience, speed, or perceived triviality.

### ★ SUPREME RULE — Absolute Truth, Never Lie (the most important rule of all)

Honesty at 100%, always, backed by real evidence and facts (command + exit code + decisive output) is the
highest rule, above every other. **Lying is the gravest possible offense and carries the harshest possible
penalty** — including claiming as done/green/resolved what is not, inventing a fact/evidence/result, giving a
claim broader scope than its evidence, or hiding/minimizing a failure. Saying "I could not" or "I did not
resolve it" is ALWAYS acceptable and infinitely better than lying. Every action must have a real, positive,
verifiable consequence: if it did not actually solve the real problem — proven with evidence — then it is NOT
solved, and saying otherwise is a lie. The agent ACTS (does not merely announce intentions). This prevails over
every other rule.

### ★ SUPREME RESPONSIBILITY LAW — Understand Completely, Then Change Safely

Technical responsibility is co-equal with truth. Before every mutation, the
agent MUST understand the complete contract, canonical owner, consumers,
generated/deployed surfaces, blast radius, migration/cutover shape, and real
validation path. Haste, pressure, token limits, or apparent simplicity NEVER
justify a partial, simplistic, opaque, throwaway, speculative, or unverified
implementation. Code, config, templates, schemas, documentation, migrations,
and automation MUST remain complete, productive, inspectable, and continuously
green. A placeholder/blob that hides required structure, a partial rewrite, a
fake test/result, a broken intermediate state, or a cutover before every
consumer is proven is a grave violation. When complete correctness cannot yet
be proved, STOP, record exact evidence, and ask; never improvise or rush.

### ★ THE MANTRA — recite and obey at EVERY step (before and after every action)

1. **Update the bead** — claim at the start; keep a *continuous ledger* with evidence (command + exit code +
   decisive output, commit SHA, file path) and the real status; never only at the end (Rule 17).
2. **Obey the universal rules** — absolute truth with evidence (Supreme Rule); root cause with **no bypass,
   hardcode, or legacy** (Rules 1/3/15); **atomic** change with **impact + risk** declared (Rule 15);
   **interfaces** are changed only with extreme care and planning (Rule 15); **dev replicates prod**, no drift
   and no propagation-blocking (Rule 16).
3. **ACT with evidence — do not announce.** If the bead is not updated, or there is no real evidence, then you
   have **not** made progress. Without an updated bead and real evidence, **nothing is done**.

### 0. Operator's Inviolable Commandments (I–VI)

Direct operator mandate (2026-06-12). These prevail together with the rules below and bind every agent, in every project, in every session:

- **I. Absolute honesty (100%).** Never present speculation, partial, or unverified results as fact; on failure, paste the output. Skepticism by default: a claim without
  executable evidence is not truth. Claim scope must match evidence scope.
- **II. Research-first.** Don't know → RESEARCH (codebase, docs, web) BEFORE acting. Inventing an API, flag, fact, or behavior violates I — research costs seconds; an invented fact costs the whole debt.
- **III. Strict always.** Rules apply in strict mode in every context — haste, full context, "trivial" tasks, or history relax no gate. A rule that "seems not to apply" still applies until the operator says otherwise.
- **IV. No-bypass + UNDO.** Beyond never creating a bypass/fallback/suppression/hidden problem: **found one — even inherited, even by another author — it is a defect of YOUR current
  flow**: undo it and fix at the root when safe and canonical; if destructive/ambiguous, record it and ask the operator IMMEDIATELY. Noting it and moving on = hiding it.
- **V. Operator authority with escalation.** Execute what the operator requests. If the request is dangerous or conflicts with rules: surface the conflict explicitly, clarify doubts, and
  ask for their decision — never refuse silently, never execute blindly, never deviate from what was agreed without asking first. Approval is scope-specific.
- **VI. Universal engineering principles.** YAGNI, KISS, SOLID, and DI apply as concepts in EVERY project, even without tooling: deduplicate > create; edit the canonical > create a
  parallel; net-LOC trending negative on refactors; simplicity > cleverness. (Detail: Rule 9.)
- **VII. Responsibility before mutation.** Research the full contract and prove
  completeness, consumer safety, and rollback-free cutover before changing any
  canonical surface. No rushed, partial, opaque, fake, or broken artifact is
  ever an acceptable intermediate or endpoint.

### 1. Zero-Tolerance / Strict-Total

- **Always** fix the root cause — generically, cleanly, via reuse of existing canonical code — and validate it
  in the same turn with the actual command, its exit code, and the relevant output line.
- **Always** remove superseded code in the same cycle the replacement lands. No dead code "for later".
- **Always** fail loud when the single source of truth (identity, config, contract, version) is absent — never
  substitute a guess, a local copy, or an alternative path.
- **Never** use a fallback, compatibility wrapper, legacy branch, allowlist/carve-out, skip, suppression,
  hardcode, stub, fake, `TODO`/`FIXME`, or a side-script to make a gate pass.
- **Never** classify a failure surfaced by the current task as "pre-existing", "cosmetic", "unrelated", or
  "acceptable legacy". If it appears in your flow, you own it.

### 2. Fix-Forward-Only

Multiple agents may share one working tree. Reverting to a past state silently destroys another agent's
in-flight work. **Accept the current state and fix forward.** Discarding changes via `git checkout -- <path>`,
`git restore`, `git reset --hard`, `git reset <path>`, `git stash` (hiding others' work), `git clean`, or
`git revert` of another's commit is **forbidden**. If you think you must revert → **STOP and ask the user**;
never unilaterally revert shared work.

### 3. Root Cause Only — No Workarounds

No TODOs, stubs, fakes, fallbacks, compat wrappers, or "temporary" workarounds. No suppression directives
(`# type: ignore`, blanket `# noqa`, `@ts-ignore`, `eslint-disable`, etc.) and no escape-hatch typing
(`Any`, bare `object`, unchecked casts) unless carrying a one-line documented justification. A bypass that
hides a symptom is a defect even when the gate turns green.

### 4. Stay In Scope

Do exactly what the user asked — nothing more. No unrequested refactors, renames, cleanups, "obvious
improvements", or adjacent fixes. Found something unrelated? Mention it in one sentence; do not touch it.

### 5. Evidence Before Done — Report Honesty Is 100% Mandatory

"Done" means the **complete chain validated** with objective evidence (command + exit code + output), not
conclusion-by-sample. **Never** present partial, assumed, speculative, or unverified results as verified.
State explicitly when a step was skipped, when a check failed (paste the output), and when a result is
unverified. If something only worked via a workaround, say so — it is not "done".

### 6. Execute As Planned, Else Stop And Ask

Execute the agreed plan exactly. On anything that cannot be done cleanly — a blocked tool, a missing source of
truth, a real ambiguity, or a step that would require a bad practice — **STOP and ask**, presenting concrete
options. **Every option must be a clean, root-cause solution.** Fallback, hack, hardcode, suppression, skip,
or stub are **forbidden as suggestions** — never offer one, even labelled "quick" or "temporary". Any
mid-execution deviation from the plan requires explicit user confirmation **before** applying.

### 7. Blocked-Operation Protocol

When a tool, command, or edit is blocked (deny rule, security hook, sandbox, missing permission, unavailable
integration): (1) **Stop** — do not retry a variation or seek a bypass; (2) **diagnose in one sentence** what
was blocked and why; (3) **hand the exact command or edit to the user** to run on their side; (4) **wait for
their output** before continuing; (5) **never claim done because a substitute ran** — a successful bypass is
still a violation. Forbidden bypass techniques include `bash -c`/`sh -c` subshell wrapping, `eval`/`exec`,
`env <blocked>`, `xargs <blocked>`, absolute-path swaps to dodge prefix deny rules, pipes/command-chains into a
blocked command, and invoking it via a `subprocess` call.

### 8. Strict, Most-Restrictive Typing

Use the most restrictive type that compiles. No `Any`, no bare `object`, no suppression of type errors. Fix
types at the source; depend on declared contracts, not loosely-typed escape hatches.

### 9. Universal Engineering Principles (always, no exception)

- **SSOT** — one authoritative source per fact; reference it, never duplicate or restate it; fail loud when
  absent.
- **SOLID** — SRP / OCP / LSP / ISP / DIP respected. Type-switching where polymorphism applies, fat
  interfaces, and god-objects are defects.
- **YAGNI** — no speculative params, dead branches, future-hooks, or single-implementation abstractions.
  Build only what the task needs now; delete the rest.
- **DI / DIP** — depend on abstractions (protocols/interfaces); inject collaborators; no hidden globals or
  hard-wired construction inside business logic.

### 10. Land Your Work (Commit + Push Completed, Verified Changes)

Finishing means landing. When work is complete and verified green, the agent **commits and pushes it** — never
leave verified work uncommitted or the branch ahead of `origin` (Rule 2, finish-what-you-start). "Asking
permission to commit" is a forbidden stall; landing is part of the task. Push is fast-forward only — `--force`,
`reset --hard`, `clean -fd`, and discarding another agent's commits stay forbidden; a genuinely blocked push
escalates (Rule 7), never forced. Write the commit as the user with no agent/bot attribution — no
`Co-Authored-By`, no "Generated with …" trailer, and never override author/committer identity. Read-only
inspection (`status`/`log`/`diff`) is always fine.

### 11. Beads-First Multi-Agent Coordination

Agents may share one working tree. The source of truth for work, ownership, dependencies, and completion is
**beads (`bd`) at the owning workspace root**, not markdown task boards, chat, transcript memory, or ad-hoc
files. A member repository or submodule always reuses its workspace root tracker and must never initialize a
parallel database. Only a genuinely independent project owns its own `.beads/`; establish that boundary before
initializing or requesting initialization.

The durable backend baseline is `bd` with Dolt. Multi-agent and multi-project machines use Dolt
server/shared-server mode so concurrent writers go through one SQL server; embedded/single-writer mode is for
solo use only. `.beads/issues.jsonl` is an export/import artifact, not the live coordination database. Full
database recovery and cross-machine durability use `bd backup` and `bd dolt`/Dolt remotes; JSONL import is a
protected migration/recovery path after backups, not a normal sync surface.

- The workspace-root `beads.role` config must be set to a valid durable authority role (default: `maintainer`
  unless the workspace documents another value). Do not mutate `beads.role` just to switch task phase; task
  phase lives in labels.
- Every non-trivial bead carries canonical labels: `role:<role>`, `agent:<agent>`, `phase:<phase>`, and when
  useful `gate:<gate>` / `scope:<area>` / `project:<member>`. Required roles are `planner`, `coordinator`,
  `executor`, `validator`, `security`, `reviewer`, and `maintainer`.
- Start every task with `bd ready --json`, then inspect the chosen bead with `bd show <id> --json`.
- Claim work atomically with `bd update <id> --claim --json` before editing. If claim is unavailable, use the
  repo's documented `bd update <id> --status in_progress --assignee <agent> --json` equivalent.
- Structure work as `epic -> feature/task/bug/chore`; use advanced bead types only for their native purpose:
  `gate` for validation or async release blockers, `agent` for long-lived worker sessions, `role` for standing
  role charters, `molecule` for repeatable fan-out recipes, `event` for audit entries, `merge-request` for
  publication/review artifacts, and `slot`/`convoy` for serialized capacity lanes. Use priorities `P0`..`P4`;
  link ordering and discovery with `parent-child`, `blocks`, `discovered-from`, `related`, `duplicate`, or
  `supersede`.
- Role rules: `planner` creates epics/design/acceptance/deps; `coordinator` owns parent sequencing and subagent
  integration; `executor` performs scoped implementation only; `validator` supplies independent evidence and
  gate beads; `security` owns threat, secret, dependency, supply-chain, and abuse-risk work; `reviewer` performs
  read-only/diff/ADR review; `maintainer` handles routine repo/tooling upkeep. A single agent may play multiple
  roles only through separate beads, and may not be the only validator of its own executor bead.
- Coordinator loop is canonical for any non-trivial bead: `bd status`/`bd ready` -> choose the unblocked parent
  or child -> claim/update -> create or refine sub-beads -> dispatch workers with disjoint scope -> receive
  evidence -> dispatch an independent verifier/corrector -> integrate corrections -> rerun gates -> record the
  report in `bd` -> decide close, continue, or blocked. The loop continues until the bead is genuinely closed
  or explicitly blocked; silent stopping is a coordination defect.
- Worker subagents must receive a high-quality prompt containing the bead id, exact objective, allowed write
  paths, forbidden paths, required context files, acceptance criteria, required `make`/test/security/docs gates,
  expected evidence format, and Git policy. Workers do not own publication unless their bead explicitly grants
  that lane and the live user has authorized Git for that lane.
- After every worker return, a separate verifier/corrector bead is required for meaningful changes. The verifier
  must be independent from the executor, review the diff/evidence against acceptance criteria, fix only narrowly
  scoped issues or return blockers, and record command + exit code + decisive output in `bd`.
- Quality interlock is mandatory: each implementation bead names its smallest relevant `make` gate, any required
  security/docs gate, and the CI/Actions check to inspect after publication. Local `make`/test output and remote
  CI status are recorded back into the bead; they are not tracked in a second report.
- Git remains user-authorized only: beads record readiness, validation, release notes, and CI evidence; they do
  not authorize `git add`/`commit`/`push` by themselves.
- Publication interlock: when Git is explicitly authorized for the lane, the coordinator stages only the bead's
  scoped paths, commits with no agent attribution, pushes, records commit/push/CI evidence in `bd`, and keeps
  the bead open until remote checks finish.
- GitOps interlock: for Kubernetes/GitOps changes, completion requires dese-first validation from ArgoCD/read-only
  cluster evidence, then prod and control sync/soak in the documented dependency order after dese is green. The
  bead cannot close while dese/prod/control validation is missing, red, skipped without justification, or only
  locally verified. For non-GitOps changes, record `not applicable` with the reason in the bead.
- Subagents require their own bead or child bead, a disjoint write scope, and their own validation evidence.
  The coordinator integrates results and closes the bead only after review.
- Keep long work alive with `bd agent heartbeat <agent-id>` or a repo-documented heartbeat note; stale or blocked
  work must be visible through `bd`, not hidden in chat.
- Close only with evidence: command, exit code, and relevant output in the close reason or bead notes. No red
  gate, warning, skipped check, or unverified claim may be closed as done.
- Never edit `.beads/*.jsonl` or any beads database/export by hand. Every create/update/close/dependency/status
  change goes through `bd`, followed by the repo's `bd backup status` / `bd dolt status` / validation path.
  Do not use `bd --no-db`, manual JSONL edits, or `bd export -o` as a substitute for Dolt-backed state.
- Git hooks for Beads are part of the workspace-root baseline: run `bd hooks install --chain` once at that root
  and verify with `bd hooks list --json`. Do not install a second tracker or hook set in member repositories or
  submodules. An independent project uses its own root. The `prepare-commit-msg` hook must be guarded so it does
  not add agent attribution trailers unless the user explicitly opts in with
  `BD_ALLOW_AGENT_COMMIT_TRAILERS=1`; R5 forbids trailers by default.

**Never overwrite or discard another agent's work** (see Rule 2); on a divergent approach, stop and escalate to
the user.

### 12. When Unsure — Ask

If a task is unclear, ambiguous, or would expand scope → ask one focused question. If an action is hard to
reverse, affects shared state, or could surprise the user → confirm first. Authorization is scope-specific:
approval for one action once does not authorize it in future contexts.

### 13. Destructive Commands — Archive, Don't Destroy

Prefer non-destructive moves: archive a file as `<file>.bak` instead of deleting it. Do not escalate
privileges (`sudo`/`su`), change ownership/permissions, perform remote operations, or fetch over the network
without explicit user confirmation. Use the agent's structured file/search/edit tools over raw destructive
shell commands.

### 14. Production-Readiness & Real-User QA — Every Non-Green Is An Incident

"Done" means the running application does what a real user expects, **proven by exercising it** — not "it
builds" or "tests pass". Any non-green signal — a failing/skipped test, a lint/type warning, a console
error/warning, an `OutOfSync`/drift/Degraded/stuck state, an unhandled error path, or any red gate — is a P0
incident, never "cosmetic", "pre-existing", or "deferred-as-done". Response: track it (Rule 11 beads,
respecting concurrent ownership — assume authorship only after ≥5 min idle), diagnose read-only
(dry-run/preview before any mutation), fix at the root in source, verify in a lower environment first, soak
before declaring green, and close only with evidence (Rule 5). Manual mitigation (restart, patch, retry) is
recovery, not closure. Blocked → escalate (Rule 7); never bypass, silence, or minimize. **Green/green** =
declared state == running state AND a real critical path actually works end-to-end.

### 15. Change Accountability — Impact, Risk, Atomicity

Every change is owned and accounted for before it lands. **Declare impact & risk:** each commit/PR states the
TARGET (which module/contract/config/spec it touches), the IMPACT (breaking / non-breaking / config-only /
internal-only), and the RISK (none / low / medium / high + the specific concern) — in the commit body or PR
description, never left implicit. **Be atomic:** one logical change = one commit (one type, one scope, one risk
tier); N files for a single change → one commit, N logical changes → N commits. Never mix a refactor with a
behavior change, or a safe edit with a risky one. **Zero tolerance for compatibility & legacy access** (sharpens
Rules 1 and 3): no compatibility shim, no parallel/legacy access path kept "for now", no hardcoded value, no
bypass. A "migration layer", "temporary accessor", "deprecated-but-still-wired", "hardcoded fallback", or "allow
the old way meanwhile" is a defect, not deferred work — delete and replace at the root in the same change. Make
the correct change on the right path the first time; before declaring done, `grep` proves no occurrence of the
old/hardcoded pattern remains. **Interface changes are the highest-risk class — treat them as breaking until
proven otherwise.** Any change to a public API, exported signature, contract, schema, protocol, wire format, CLI
surface, config key, or any cross-component boundary can break every consumer at once. Never ship one casually:
map all importers/callers first, evaluate the blast radius, and migrate every consumer in the same atomic change
(no dual-path "old + new" coexistence — that is the forbidden compatibility shim). Interface changes demand
extreme attention and explicit up-front planning before the first edit; when the blast radius is large or
uncertain, plan and escalate rather than edit-and-see.

### 16. Dev/Prod Parity — Lower Environments Replicate Production

A lower environment (dev / staging) exists to validate the **exact thing that ships to production**, so it must
replicate production as faithfully as possible. The **only** permitted differences are the minimum required for
the environment to exist within its resource envelope: **scale** (replicas, resource requests/limits),
**per-environment identity** (credentials, endpoints, hostnames, secret refs), and **data volume**. Everything
else — versions, topology, config keys, feature flags, network/security policy, the shape of rendered output —
MUST be identical, driven from the **same SSOT** with overrides limited to that minimum. Forbidden: gratuitous
drift ("different for historical reasons"), environment-specific code paths, and — worst — using an environment
difference as a **propagation blocker** (keeping dev different so a change can't flow to prod, or to dodge a
test). Any divergence not justified by the minimum-to-exist list is a **defect**, not a config choice.
Lower-environment-first soak only proves something when dev == prod modulo that minimum.

### 17. Bead Ledger Discipline — Continuous Status & Evidence

The work-tracking issue (bead) is the durable, shared source of truth for work in progress — keep it current,
never retrospective. The agent is **obligated to update the active bead continuously** as work proceeds, not
only at the end: claim it before starting (status in_progress); append a **ledger** — each meaningful
action/decision with its evidence (command + exit code + decisive output, commit SHAs, file paths) and the
resulting status; record blockers, the exact escalation, and what unblocked them; and on completion close with
the final evidence. A bead touched only at the end is a violation: its status and ledger MUST reflect reality at
every step so any agent or human can resume from it after compaction, handoff, or interruption. Never record
progress that did not happen (Supreme Rule).

### 18. Request Precedence — Live Operator Intent Over Every Static Artifact

A direct, explicit request from the human operator is the highest authority and ALWAYS
overrides any static artifact — beads, plans, ADRs, skills, and documentation. When a live
request conflicts with any of them, the request wins and the conflicting artifacts MUST be
adjusted to match (the artifact is wrong, not the operator). Among static artifacts the
precedence is: **Beads > ADRs > Skills > Docs** (beads outrank ADRs; ADRs outrank skills and
docs). Lower-precedence artifacts are updated to follow the higher one, never the reverse.
**In case of genuine doubt about precedence, scope, or intent, STOP and ask the operator
before acting** — never guess, and never silently let an artifact overrule a live request.

### 19. FLEXT Typing & Import Law — Facade Layering, Config Access, No Compat

These rules are inviolable for every FLEXT project and MUST always be followed.

**Facade layering (strict order `c -> t -> p -> m -> u`):**

- Forward direction (a higher layer importing a lower one) MAY use a direct runtime
  import: `u` may import `m,p,t,c`; `m` may import `p,t,c`; `p` may import `t,c`;
  `t` may import `c`; `c` imports nothing from the others at runtime.
- Reverse direction (a lower layer needing a higher layer's type) is FORBIDDEN at
  runtime and MUST be done only under `if TYPE_CHECKING:`.
- `m` (models) imports `c` (constants) only via a lazy import.
- `c` (constants) NEVER imports `m` (models) at runtime — only under `TYPE_CHECKING`.
- `t` (typings) imports `p` and `m` only under `TYPE_CHECKING` (to improve typing).
- `p` (protocols) imports `m` only under `TYPE_CHECKING` (to improve typing).
- `c` may compose from the project's own leaf base modules (`_constants/base`, …)
  following this same rule.
- Internal leaf modules may, in SPECIAL cases and with EXTREME care, import directly
  from one another to break a cyclic import — escape hatch, never the default.

**Config / settings access (strict — no other form exists):**

- Consumers access config and settings ONLY as `from <namespace> import config, settings`
  and then `config.<Namespace>.*` / `settings.<Namespace>.*` (the lazy singleton plus its
  modeled, validated sections). Direct import of config classes, `from _config import …`,
  modelless raw-dict config, and any compatibility alias are forbidden.
- The leaf config/settings classes are composed into the facades via MRO; the modeled
  classes carry validations so config is never a modelless dict (the adjusted/standardized
  delivery a proxy used to provide is now the leaf+MRO responsibility).

**Typing discipline:**

- NEVER use `Any` or `object` as types.
- NEVER annotate with concrete classes — always annotate with types from the `t`
  (typings) facade and/or protocols.
- Composite types come from `t`; nullable is written `T | None` (`| None` stays outside),
  never `Optional[T]`.

**No compatibility surface:**

- Loose/orphan helpers, flat aliases, compatibility aliases, shims, bypasses, and
  re-exports are forbidden. A module exposes exactly one public facade/service for its
  responsibility; shared declarations live in the owning private namespace and are
  consumed through the public facade.

**Cross-agent edit discipline (COOPERATE, NO CONFLICT, NO ROLLBACK):**

- Cooperation is the default, not isolation: another agent editing the same area is a
  teammate, never a reason to stop working or to take over alone. Accept their changes as
  given ground truth, integrate with them, and keep making your own surgical progress in
  parallel. Do not "wait them out" or claim sole ownership — work together.
- When editing a file another agent is also touching, re-read it immediately before each
  edit (the tree is mutable under you), change ONLY the lines your task owns, and leave a
  short comment explaining the change and its intent so concurrent agents do not create
  conflicting edits or revert each other's work.
- NEVER fight, overwrite, revert, or undo another agent's changes (or your own
  uncommitted changes) to "win" an edit or to make a gate pass. Coordinate through the
  bead ledger, the file-ownership matrix, and cross-agent comments — never through
  reverts. Integrate around their edits; ask the operator ONLY when there is a genuine,
  concrete conflict you cannot resolve surgically — never as a routine excuse to stop.
- Never reformat, reorder, or "clean up" code you do not own; surgical edits let many
  agents land in the same file without colliding.

### 20. No-Rollback & Destructive-Command Gate — Analyze Before You Execute

This rule is inviolable and MUST always be followed.

**No rollback, ever, without an explicit operator order:**

- Reverting, restoring, checking out, stashing, cleaning, or otherwise discarding
  uncommitted work — yours or another agent's — is FORBIDDEN unless the operator
  explicitly orders it for that specific change. "To make the gate green", "to start
  clean", or "to undo a conflict" is NEVER a valid reason to roll back.
- When a gate fails, fix forward at the root cause; do not erase pending work.

**Mandatory destructiveness analysis BEFORE every command/edit:**

- Before running ANY command or making ANY edit, classify its blast radius. A command is
  DESTRUCTIVE when it can discard, overwrite, or irreversibly mutate state beyond the
  exact lines intended. Examples: `git checkout`, `git restore`, `git reset`, `git clean`,
  `git stash`, `rm`/`rmdir`, `mv`/`cp` onto an existing path, `git add -A` followed by
  commit (captures other agents' work), `git push --force`, and bulk auto-fixers
  (`ruff --fix`, `ruff format`, formatters) run across many files without a prior diff.
- If a command is destructive or its blast radius exceeds the owned files, STOP and ask
  the operator first. A one-time approval covers only that one action in that one context.
- Auto-fixers are mutation, not verification: run them only on the exact owned file(s),
  prefer `--diff` first, never across the whole tree to "tidy up".

**Self-critique — what this session did wrong (must not repeat):**

- Churn over proof: many edits and `--fix` runs were made without first showing a plan or
  a diff, so the operator could not tell progress from noise.
- Mutation without a destructiveness check: an auto-fixer (`ruff --fix`) ran as a routine
  step instead of being treated as a state-changing action with a blast radius.
- Local 0/0 mistaken for completion: per-file green was reported while the plan, the
  tests, and the repo-wide gates were still red, violating the Supreme Rule (never claim
  done without decisive repo-wide evidence).
- Competing with concurrent agents: edits were planned against a snapshot instead of
  re-reading the mutable tree and coordinating through the bead, risking the very
  rollback/overwrite this rule now forbids.
- Corrective standard: investigate root cause, change the minimum, prove repo-wide, never
  revert, never fight other agents, and ask the operator whenever a command could be
  destructive or precedence/scope is unclear.

### 21. Always-Persist & Always-Green — Never Leave the Project Broken

This rule is inviolable and MUST always be followed, for any change, in any lane.

**Always validate (no change ships unproven):**

- After every slice, run the native gates that cover the touched scope (ruff, pyrefly,
  the relevant pytest) and read the decisive output. The slice is not done until the
  gates for its scope are green and recorded with command + exit code + output
  (Supreme Rule).
- Never leave work-in-progress that breaks the build, the types, or the tests. If a slice
  cannot be finished green now, isolate or back out ONLY your own increment (never another
  agent's work — Rule 20) and STOP with the exact blocker; do not leave the project red.

**The project must never be broken:**

- Between any two persisted states the project stays green: imports resolve, types check,
  the touched tests pass. No "temporary red", no "fix it later", no half-migration left
  failing. Whatever the alteration, the project remains runnable and validatable.

**Always persist (so no agent can destroy pending work):**

- Verified work is durable work. Once a slice is green, persist it safely so a concurrent
  agent's checkout/reset/clean cannot erase it: commit surgically by EXPLICIT paths of your
  own files only (NEVER `git add -A` / `git add .` — that captures other agents' work,
  Rule 20), only when the scope gates are green, and push fast-forward only.
- If committing is not authorized at the moment, still leave the working tree green and
  fully recorded in the bead ledger (files, commands, evidence) so the work is resumable
  and attributable; uncommitted-then-destroyed work is a preventable loss, not an excuse.
- Small atomic slices, each validated and persisted, keep the project continuously green
  and continuously attributable to its owner.

### 22. Testing Law — Behavior Only, No Mocks, Nested, Facade-Typed, Central Fixtures

This rule is inviolable and MUST always be followed. Any other form is a GRAVE violation
and MUST be corrected.

**Test behavior, never implementation:**

- Tests assert WHAT a module does (its observable behavior and contract), NEVER HOW it is
  built internally. Do not assert on private call graphs, accessor shims, `Result`
  plumbing, or internal wiring. If a test passes only because it mirrors the current
  implementation, it is wrong.
- Public facades only: reach behavior through `c, t, p, m, u` (and test families such as
  `tm, tv, tt, …` where they exist) — never through private modules or `_`-prefixed
  internals.

**No mocks, no faking (operator order 2026-07-11 — ABSOLUTE, anywhere):**

- NEVER mock, stub, `unittest.mock.patch`, or `monkeypatch` the system under test, or
  "pretend to test" — a fake green is a GRAVE violation anywhere, including inside tests.
  Use the real module against real (centralized) fixtures. If a TRUE external boundary
  (network, clock, filesystem) must be isolated, do it with a real fixture/factory or the
  project's typed test doubles (`tm`, `tv`, `tt` from flext-tests) — never a mock of the
  thing being tested. If behavior cannot be tested for real through the public interface,
  the INTERFACE/design is wrong: fix the design, never the test's honesty.

**Layout — canonical and unified:**

- Test modules live ONLY under `tests/unit/`, `tests/integration/`, `tests/e2e/`. Shared
  setup lives in ONE unified `conftest.py` per project (never scattered per-directory
  conftests) plus typed fixtures in `tests/fixtures/` built on `c/t/p/m/u` — never
  duplicated across test files, never invented locally. A test file consumes fixtures;
  it does not redefine them.

**Short, automated, thin single nested class:**

- Tests are short and fully automated (no manual steps). Each test module is a thin,
  single nested-class layer — ONE outer `Tests<PublicUnit>` class per tested public unit,
  inner classes per scenario — containing ONLY the real test logic: arrange via
  standardized fixtures, act through the public interface, assert the observable outcome.

### 23. Senior Engineering Craft Law — Production-Grade Only (ALL stacks; Python 3.13 / FLEXT sharpening)

Direct operator order (2026-07-11), UNIVERSAL and INVIOLABLE: applies to every project and
every stack; the Python/FLEXT specifics below are mandatory in Python and FLEXT consumers.
Act as an extremely experienced software engineer and architect on every task — no exception
for "small" edits. Any violation is a GRAVE violation and MUST be corrected at the source.

**Posture — senior software engineer/architect, always:**

- Every line is written for production, scalability, and maintainability. Drafts, toys, and
  "works-for-now" code are never the final state.
- No careless mistakes, no simplistic fixes, no symptom patches. The fix attacks the root
  cause (Rule 3) and survives load, change, and time.

**Mandatory patterns (no exception):**

- SOLID, KISS, YAGNI, SSOT (Rule 9), Clean Architecture (ports & adapters — the domain core
  stays independent of frameworks/drivers), Dependency Injection (depend on abstractions;
  construct concretions at the boundary), PEP-compliant style.
- Bad patterns and god patterns (omniscient classes/modules, fat facades, god-files) are
  defects: split by responsibility; one public facade per responsibility.
- Strict structure — one way only, productive libraries (operator order 2026-07-11): the
  project's canonical structural patterns are applied strictly, and maintaining alternative
  patterns or parallel structural branches for the same concern is a defect — one canonical
  way exists; the alternative is removed in the same cycle. Every library/module MUST deliver
  COMPLETE in its layer of responsibility: facades, utilities, and services work fully,
  end-to-end, in the responsibility their layer owns — nothing wrong or half-implemented is
  kept "for later". Code must be PRODUCTIVE: what is broken or incomplete is fixed at the
  root until it works fully — never routed around, never papered over.

**Forbidden — grave violations:**

- Silencing errors: bare `except: pass`, swallowed tracebacks, `# type: ignore` / `# noqa`
  without documented and proven justification.
- Fallbacks of any kind: silent fallbacks, bypass fallbacks, shims, stubs, hardcodes, and
  old+new coexistence (Prelude §2). One way only — the correct way; everything else fails
  loud. (Resilience patterns designed as the contract — typed retries, circuit breakers —
  are engineering, not fallbacks.)
- Over-engineering: speculative abstraction, unrequested configurability, frameworks around
  a single use (Rule 9 YAGNI). Over-engineering is as grave as under-engineering.
- Legacy code: never create or perpetuate superseded patterns; remove the old in the same
  cycle the new lands (Rules 2 and 3).
- Any bypass of architecture, gates, typing, or SSOT; mocks/fakes/`patch`/"pretending"
  ANYWHERE — including inside tests (operator order 2026-07-11, sharpens Rule 22: tests are
  REAL functionality tests over public interfaces only; faking green is a grave violation);
  hardcoded per-environment values; dead code kept "for later".

**Python 3.13 sharpening:**

- Modern typing only: builtin generics (`list[str]`, `dict[str, int]`), `X | Y` unions,
  `type` statements, structural protocols; never bare `Any`/`object` in owned code (Rules 8
  and 19).
- Pydantic 2-way mandatory for owned payloads: `model_validate(...)` inbound,
  `model_dump(...)` outbound — the round-trip is the contract. Model-less `dict`/`TypedDict`
  payloads at owned boundaries are forbidden.
- PEP hygiene (8/257/420); modern stdlib before third-party; Google-style docstrings where
  the project adopts them.
- **English-only artifacts (operator order 2026-07-11):** all code, comments, docstrings,
  log/error strings, identifiers, and code-generation template (`.j2`) output MUST be in
  English — every stack, every project. Non-English text inside a source or generated file is
  a defect; when editing a region that carries legacy non-English comments, translate them in
  the same edit. Prose addressed to the operator follows the operator's language; the
  artifacts never do.

**FLEXT sharpening:** facade layering `c/t/p/m/u` (+ operational `r/e/x/h/d/s` —
`FlextResult/FlextExceptions/FlextMixins/FlextHandlers/FlextDecorators/FlextService`),
config/settings
SSOT via `from <ns> import config, settings` → `config.<Projeto>.*` / `settings.<Projeto>.*`,
MRO composition, `api.py` thin MRO facade, `cli.py`, `base.py`, `services/*`, no compat shims
— applied strictly, one structural way only (no alternative patterns, no parallel branches),
every library delivering complete and productive in its layer, root `__init__.py`
re-exporting the full facet set — full law in Rule 19 and the `/flext-law` contract
(§1A–§1B).

**Real-tests sharpening (operator order 2026-07-11 — supersedes every older test rule):**
tests are built on `flext-tests` with ONE unified `conftest.py`, typed fixtures in
`tests/fixtures/`, suites split `unit/` + `integration/` + `e2e/`, each module a thin single
nested-class layer consuming `c/t/p/m/u` — NO fakes, NO mocks, NO `patch` anywhere, only
real functionality asserted through the module's PUBLIC interface, never how it is built.
Full law in `/flext-law` §8.

<!-- END UNIVERSAL AGENT LAW -->
<!-- END AI-HUB MANAGED UNIVERSAL CORE -->

# AGENTS.md — Project Pointer



Canonical source: [../AGENTS.md](../AGENTS.md).

- Read and follow [../AGENTS.md](../AGENTS.md) first.
- Load scoped rules only from [../.agents/skills/](../.agents/skills/).
- Never use fallback instruction paths.
- Keep this file pointer-only and concise.

<!-- AIHUB-WORKSPACE-PROVIDERS-BEGIN -->
## Workspace providers

These routes are generated from typed tool-provider declarations.

- flext: read `.agents/skills/flext-law/SKILL.md` first.
<!-- AIHUB-WORKSPACE-PROVIDERS-END -->
