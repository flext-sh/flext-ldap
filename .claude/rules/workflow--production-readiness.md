# Production readiness adopts every defect in scope

A version that is broken or incomplete never ships to production. Shipping is
blocked while any gate, test, check, review thread, or known defect in the
change's blast radius is red or unresolved.

- "Pre-existing", "not mine", "third-party", "cosmetic", and "out of scope"
  never exempt a defect surfaced inside the change's blast radius. Adoption is
  mandatory: the combined state is the deliverable.
- A defect outside the current slice becomes a tracked child item in the same
  cycle — no silent carry-over — and still blocks promotion if it leaves the
  delivered version broken or incomplete.
- Fix defects at their canonical owner with complete cutover; never patch a
  symptom, suppress a finding, or narrow a gate to make a check pass.
- Gates evaluate the delivered state, not the delta: a green change on top of a
  red base is a red delivery. Correct the owner and rerun until the delivered
  state is green.
- Adopt all concurrent work in the integration lane (`git merge --no-ff`),
  resolve every review comment with runtime evidence, and prove CI green before
  merge; post-merge proof closes the increment.

Compose with `rules/runtime/strict-execution.md`,
`rules/coordination/fix-forward-collaboration.md`, and
`rules/architecture/generalized-abstraction.md` (same-cutover pre-existing
offender removal).
