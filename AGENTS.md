# AGENTS.md — Project Pointer

<!-- BEGIN UNIVERSAL AGENT LAW (portable; regenerable; do not edit inside) -->
## Universal Agent Law (portable core)

**This block is the inviolable, agent-agnostic core of engineering conduct for this repository.** It is
self-contained: it binds any AI agent — Claude, Codex, Gemini, Cursor, Cline, GitHub Copilot, or any other —
and any user, with or without access to the author's personal configuration. The live user's explicit
instructions override this block; nothing else does. These rules apply to every project type and every
session, and may not be relaxed, reinterpreted, or scoped-out for convenience, speed, or perceived triviality.

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

### 10. Land Scoped Work Immediately

After scoped green validation, run `git add`/`commit`/fast-forward `push` for the active bead lane using explicit pathspecs. The operator grants durable authorization for normal scoped landing; never leave verified work only in the working tree. Write commits as the user with no agent/bot attribution — no `Co-Authored-By`, no "Generated with …" trailer, and never override author/committer identity. Escalate only destructive, non-fast-forward, history-rewrite, rollback, tag, or cross-lane ambiguity.

### 11. Multi-Agent Coordination

Agents may share one working tree. Coordinate through a committed task board (e.g.
`<repo>/.agents/coordination/tasks.md`): claim a task with an ownership + lease entry before editing, heartbeat
the lease, set `done`/`blocked` on finish, and recover stale tasks from git history. Commit small and often so
a fresh agent rebuilds state from `git log`. **Never overwrite or discard another agent's work** (see Rule 2);
on a divergent approach, stop and escalate to the user.

### 12. When Unsure — Ask

If a task is unclear, ambiguous, or would expand scope → ask one focused question. If an action is hard to
reverse, affects shared state, or could surprise the user → confirm first. Normal scoped Git landing has durable operator authorization after validation. Confirm only destructive, non-fast-forward, cross-lane, or ambiguous actions.

### 13. Destructive Commands — Archive, Don't Destroy

Prefer non-destructive moves: archive a file as `<file>.bak` instead of deleting it. Do not escalate privileges (`sudo`/`su`), change ownership/permissions, force-push, rewrite history, tag releases, or fetch arbitrary network resources without explicit user confirmation. Normal scoped fast-forward push after validation is required by Rule 10. Use the agent's structured file/search/edit tools over raw destructive
shell commands.
<!-- END UNIVERSAL AGENT LAW -->

Canonical source: [../AGENTS.md](../AGENTS.md).

- Read and follow [../AGENTS.md](../AGENTS.md) first.
- Load scoped rules only from [../.agents/skills/](../.agents/skills/).
- Never use fallback instruction paths.
- Keep this file pointer-only and concise.
