<!-- AUTO-GENERATED FILE — regenerate through `make gen` from the workspace root. -->
<!-- Source of truth: `<workspace-root>/docs/guides/using-pydantic.md`; adjust that workspace source, never this member projection. -->

# flext-ldap - Using Pydantic in FLEXT

> Project profile: `flext-ldap`

<!-- TOC START -->

- [Authority](#authority)
- [Where each Pydantic concern lives](#where-each-pydantic-concern-lives)
- [Library boundaries](#library-boundaries)
- [What consumers never do](#what-consumers-never-do)
- [Enforcement](#enforcement)
- [Static and runtime typing evidence](#static-and-runtime-typing-evidence)
  - [Analyzer rule review](#analyzer-rule-review)
  - [Analyzer declaration snapshot — 2026-10-28](#analyzer-declaration-snapshot-2026-10-28)
- [Source-derived protocol contracts](#source-derived-protocol-contracts)

<!-- TOC END -->

## Authority

The canonical, source-cited law is the `pydantic-development` skill
(`~/agents/skills/technology/pydantic-development/`, distributed to every agent home)
and the `rules/python/pydantic.md` rule. This guide maps that law onto the FLEXT
facades; it does not restate it. The Pydantic version in force is the one locked in
the committed `uv.lock` of the project that installs it; member locks and the
workspace lock that composes them agree by construction
(ADR-030).

Two 2026-10-25 operator rulings bind every FLEXT model (root `AGENTS.md`
"Pydantic law"; ADR-028 Decisions 14 and 19):

- models import `u` only from the upstream FLEXT project or, in very restricted
  cases, from a private `_utilities` class of their own namespace; they export no
  methods, and the Pydantic surface they need lives in `_models/pydantic.py`
  (tracker memory `operator-ruling-2026-10-25-models-u-imports-pydantic-home`);
- entity equality is Pydantic value equality with explicit identity by id
  (tracker memory `operator-ruling-2026-10-25-entity-equality-pydantic-way`; see
  Domain models).

## Where each Pydantic concern lives

| Concern | FLEXT owner | Consumer form |
| --- | --- | --- |
| Model configuration | `m.*` presets in `flext-core/src/flext_core/_models/_base/` | `class X(m.FrozenModel)` — never a raw base or a hand-written `ConfigDict` |
| Reusable constraints, validators, serializers | `t` aliases (`type X = Annotated[...]`) | `field: t.NonEmptyStr` |
| Closed domains | `StrEnum` classes in `c` | `kind: c.Shipping.EventKind`; union tags `Literal[c.Shipping.EventKind.CREATED]` |
| Dependency-typed fields | `@runtime_checkable` protocols in `p` | `sink: t.Port[p.ShipmentSink]` (`InstanceOf`) |
| Model protocols | generated into `p` by flext-infra during `make gen` | never hand-mirrored |
| Non-model adapters | module-level adapters owned by `u` / `t` | never `TypeAdapter(...)` inside a function |
| Outcomes | `r` / `p.Result[T]`; the `e`/`u` result boundary converts `ValidationError` | `u.model.validate_value(Model, raw, from_json=True)` |
| Runtime knobs | `settings.<Namespace>.*` (pydantic-settings) | read through the singleton, never `os.environ` |
| Static rules | `config.<Namespace>.*` from `config/*.yaml` | read through the singleton |

Only flext-core imports `pydantic`, `pydantic_settings` or `pydantic_core`.

## Library boundaries

Every payload a library returns enters FLEXT as an `m` model at the single adapter
that calls the library, and every payload FLEXT hands to a library leaves through
`model_dump` / `model_dump_json` at that adapter:

- JSON: `Model.model_validate_json(raw)`.
- YAML/TOML: the loaded value goes straight into `Model.model_validate(...)` or a
  module-level adapter — no `cast`, no `isinstance` walk.
- pydantic-settings custom sources return the mapping its `_read_file` contract
  requires; the settings model validates it.
- structlog processors receive a mapping built from the validated record in one place.

## What consumers never do

Re-validate a model they already received, `isinstance`/`cast` owned data, convert
between dict and model by hand, compare closed domains with string literals, hold a
second model for a shape an existing model already expresses, or call
`model_rebuild`, `model_construct` or `model_copy(update=...)` on validated data.

## Enforcement

Each banned form has an ast-grep rule with fixtures in
`flext-infra/src/flext_infra/config/rules/ast-grep/rules/`. `make mod` applies the
rewrites, `make check` fails on any remaining finding, and tests exercise models only
through the public facades (no mocks, private access or tautologies).

## Static and runtime typing evidence

The approved investigation is `flext-itpd1.13.11`; analyzer environment ownership
is ADR-003, Decision 5.
The canonical `pydantic-development` procedure owns the diagnosis sequence.
Keep runtime validation and static constructor checking distinct: typed
constructors remain enabled, and external data enters through public validation.

Compare the real public facade with the upstream declaration before calling a
diagnostic a false positive. Record the checker version, loaded configuration,
resolved imports, inferred type and runtime result. Cover inherited and nested
models, generic specialization, defaults, aliases, validators, computed fields
and settings. A descriptor returning the original callable at runtime does not,
by itself, prove that a checker recognizes its field-specifier identity.

Pydantic documents that static constructor synthesis does not interpret
`default`, `default_factory` and `alias` inside `Annotated`. Keep constraints as
metadata and expose constructor-relevant declarations in a statically
recognized form, preserving runtime behavior. Multiple-base configuration
composition also needs observed runtime evidence; ordinary Python MRO is not a
substitute for inspecting the effective model configuration.

References: [Pydantic fields](https://docs.pydantic.dev/latest/concepts/fields/),
[configuration inheritance](https://docs.pydantic.dev/latest/concepts/config/),
and [dataclass transforms](https://typing.python.org/en/latest/spec/dataclasses.html).

### Analyzer rule review

The effective policy is read from Infra's native tooling declarations and the
selected checker's own strict-mode defaults. The following review groups the
diagnostics relevant to this investigation; it is not another configuration
catalog. No row authorizes a severity change.

| Rule family | What it establishes | Required diagnosis and disposition |
| --- | --- | --- |
| Missing imports and module sources | The analyzer can resolve a declaration | Verify interpreter, environment parent, editable origins and execution-environment order before investigating MRO |
| Missing third-party stubs | Availability of an external typing contract | Preserve the existing approved policy; source inference does not make every external API precise |
| Unknown types and untyped bases/decorators | Type information survived the boundary | Follow the first unknown symbol through its declaring export; retaining an overload at runtime does not prove static field/decorator identity |
| Constructor calls and argument types | Requiredness, aliases and declared input types | Compare required/default/factory/alias forms with actual validation; preserve typed constructors and public field semantics |
| Assignment, generic arguments and overrides | Substitution and mutability contracts | Inspect inherited specialization, variance and effective model configuration; a successful coercion is not proof of substitutability |
| Optional and unbound access | A value is present before use | Prove the public invariant and narrow at its owner; do not silence these checks because a model validates other fields |
| Unnecessary operations and unused declarations | Reachability and redundant/dead code | Inspect the inferred type first; fix lost precision before interpreting a cascade as redundant code |
| Mypy plugin diagnostics | Pydantic-specific field and model semantics | Keep the plugin and current two-code exception; assess each diagnostic against the native model and the public facade |

Relevant native options include mypy's import-following, package-base, re-export,
untyped-body, equality, reachability and unused-ignore checks, and Pyright's
strict inference and `reportUnknown*`, constructor, override and decorator
diagnostics. Their values remain owned by the selected configuration, not by
this review table. Lowering strictness can remove evidence without restoring
inference; it is not a causal repair.

### Analyzer declaration snapshot — 2026-10-28

This snapshot records the inspected declarations, not a second policy owner or
proof of the configuration loaded by a running checker. The writable owners are
native tooling settings,
the Mypy projection,
and the Pyright projection.
Project overlays, inline directives, command arguments and editor state must be
included when establishing an individual diagnostic's effective policy.

#### Mypy and its Pydantic plugin

The inspected Mypy declaration does **not** enable `strict = true`; it selects
individual options. Calling this configuration strict in prose does not enable
Mypy's optional strict bundle. The native gate supplies its selected configuration
file; the running invocation and configuration identity still require a receipt.
[Mypy's configuration reference](https://mypy.readthedocs.io/en/stable/config_file.html)
defines option precedence and notes that the strict bundle can change by release.

| Declaration or diagnostic | Inspected selection | Detection impact and evidence needed |
| --- | --- | --- |
| `plugins` | Explicit `[pydantic.mypy]` | Verify the plugin actually loads from the selected environment; compare the same upstream and facade model |
| `init_typed`, `init_forbid_extra`, `warn_required_dynamic_aliases` | All explicitly `true` in `pydantic-mypy` | Preserve typed inputs, extra-argument policy and dynamic-alias checking; compare synthesized constructor, effective model configuration and real validation |
| `disable_error_code` | Derived from the declared `[call-arg, prop-decorator]` suspension | Missing/unexpected constructor arguments and property-decorator findings cannot prove detection through these suspended codes; retain invalid sentinels in the complete analyzer comparison |
| `arg-type`, `assignment`, `override` | Native diagnostics; not suspended by this declaration | Require precise field/method types and an incompatible public consumer; runtime coercion alone does not invalidate a constructor finding |
| `attr-defined`, `name-defined`, `misc`, `no-redef` | Native diagnostics; no suspension for these codes in the inspected owner | Trace exports and namespace bindings; older historical exceptions do not establish today's configuration |
| `allow_redefinition`, `local_partial_types` | Explicitly `true` | Do not infer that variable-redefinition support permits every class or facade binding; retain the exact offending declaration and inferred identity |
| `no_implicit_reexport` | Explicitly `true` | Inspect the generated public export and its static declaration rather than assuming an imported name is exported |
| `namespace_packages`, `explicit_package_bases` | Explicitly `true` | Record module identities and source roots when investigating missing or duplicate modules |
| `follow_imports`, `follow_untyped_imports` | Explicit `normal`, `true`; the `rope.*` override also selects `true` | Record the actual imported source and typing marker before attributing lost types to inheritance |
| `check_untyped_defs`, `extra_checks`, `strict_equality`, `warn_redundant_casts`, `warn_return_any`, `warn_unreachable`, `warn_unused_ignores` | Explicitly `true` | Inspect the earliest type loss before classifying downstream findings; these selections do not imply every optional Mypy check is enabled |
| `python_version`, `mypy_path`, `exclude`, `overrides` | Derived by the existing projection owners | Obtain the selected project's rendered configuration and import trace; the base declaration alone does not prove the effective search scope |

The [native Mypy diagnostic reference](https://mypy.readthedocs.io/en/stable/error_code_list.html)
distinguishes argument count/name checking from argument type checking. It also
documents the property-decorator limitation and the risk of losing useful types
when missing-attribute or redefinition diagnostics are suppressed. The
[Pydantic plugin reference](https://docs.pydantic.dev/latest/integrations/mypy/)
documents constructor synthesis, defaults, frozen models and dynamic aliases.
Those capabilities require the recognized native model and field declarations;
the configuration flags alone do not prove recognition through a facade.

#### Pyright defaults and explicit selections

The inspected owner explicitly selects `typeCheckingMode = "strict"`. The table
below distinguishes explicit selections from relevant inherited defaults in the
[Pyright 1.1.414 configuration reference](https://github.com/microsoft/pyright/blob/1.1.414/docs/configuration.md#diagnostic-settings-defaults).
That reference matches the investigation's declared version; it does not prove
the version launched by the CLI or editor.

| Declaration or diagnostic | Inspected selection | Detection impact and evidence needed |
| --- | --- | --- |
| `reportCallIssue`, `reportInconsistentConstructor` | Explicit `error` | Compare generated calls and `__init__`/`__new__` signatures through both import surfaces |
| `reportIncompatibleMethodOverride` | Explicit `error` | Compare inherited signatures and the invalid override sentinel |
| `reportArgumentType`, `reportAssignmentType`, `reportAttributeAccessIssue`, `reportIncompatibleVariableOverride`, `reportInvalidTypeArguments` | Inherited strict `error` | Check input, field, specialization and mutability contracts with precise inferred types |
| `reportUnknownArgumentType`, `reportUnknownLambdaType`, `reportUnknownMemberType`, `reportUnknownParameterType`, `reportUnknownVariableType` | Inherited strict `error` | Locate the first unknown declaration and its resolved source before interpreting cascades |
| `reportUntypedBaseClass`, `reportUntypedClassDecorator`, `reportUntypedFunctionDecorator`, `reportMissingTypeArgument`, `reportMissingParameterType` | Inherited strict `error` | Inspect base/decorator identity, preserved overloads and generic arguments |
| `strictListInference`, `strictDictionaryInference`, `strictSetInference` | Inherited strict `true` | Compare collection inference when checking factories and generic model fields |
| `reportMissingImports`, `reportMissingModuleSource` | Explicit `error` | Prove interpreter, search roots and installed source identity first |
| `reportMissingTypeStubs`, `useLibraryCodeForTypes` | Explicit `none`, `true` | Preserve the existing exception; source inference still needs a typed public boundary |
| `reportPrivateUsage`, `reportConstantRedefinition`, `reportUnnecessaryCast`, `reportUnnecessaryComparison`, `reportUnnecessaryIsInstance`, `reportUnusedClass`, `reportUnusedFunction`, `reportUnusedImport`, `reportUnusedVariable` | Explicit `error` | Inspect the public export and inferred type before treating a finding as an inheritance defect |
| `venv`, `venvPath`, `extraPaths`, `executionEnvironments`, `include`, `exclude`, `pythonVersion` | Derived by existing topology and configuration owners | Verify the selected physical environment and per-file environment order in root, attached-member and standalone contexts |

Every row remains unchanged by this audit. A proposed change requires a reproduced
diagnostic, upstream/facade comparison, preserved invalid-case detection, and the
operator's explicit old/new-key authorization under the lint-rule freeze. No row
classifies an unmeasured diagnostic as a false positive.

## Source-derived protocol contracts

ADR-018's model and service projection
owns the accepted 2026-10-28 contract for source-derived structural protocols and
automatic consumer migration. It applies to the complete native Python inventory,
not only production models that already have a consumer. Follow that owner's
source-module correspondence and native discovery requirements rather than
introducing a generated tree or a separate file for each model.

The projection describes a first-party model's data capability or a service's own
callable contract. Construction, validation, schemas and operational DI keep their
existing runtime owners. The separate prohibition on local typing stubs and
external SDK mirrors remains unchanged. The older protocol-retirement plan does
not prohibit the source-derived generation authorized by the newer amendment.

Use the existing flext-infra semantic path to close affected declarations,
imports, annotations and lazy exports together across all Python consumer
surfaces. Runtime and static comparisons must exercise the public composed
facade, including inherited and specialized contracts, before tests are updated.
The ADR owns distant-pilot selection, variation coverage, negative cases,
standalone proof, fixed point and profile-driven incremental performance. A
sampled passing import or a shorter diagnostic list does not establish that
acceptance. Cover every pilot variation before rolling out the same pattern to
the fleet, including all declarations and affected consumers. Complete the entire
pattern's real runtime, native gates and integration closure before beginning
another pattern. MRO/Pydantic environment and editor verification under ADR-003 remain
required; the protocol-first sequence does not mark those results complete.
