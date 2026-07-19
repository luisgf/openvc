# Contributing to openvc

## Development setup

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[all]"       # core + ebsi + data-integrity + dev tools
```

## The checks (all must pass)

```sh
pytest                        # offline: deterministic, no network
OPENVC_EBSI_LIVE=1 pytest     # optionally also the live EBSI smoke test
flake8 src tests              # lint (max line length 100)
mypy                          # type check (strict-ish; the code is fully typed)
gitlint                       # commit-message convention (see below)
```

CI runs the same on Python 3.10–3.14, plus a leg pinning the oldest supported
`pyld` and an advisory 3.15 pre-release leg (it reports but never blocks, and
installs `[ebsi,dev]` only — `lxml` has no cp315 wheel yet, so the suites behind
`[data-integrity]`, `[trustlist]` and `[schema]` skip themselves there).

Working without an extra installed is supported: those test suites
`importorskip`, and `mypy` ignores the missing optional imports.

## Docs

The API reference is generated from docstrings with mkdocs + mkdocstrings:

```sh
pip install -e ".[docs]"
mkdocs serve                  # live preview at http://127.0.0.1:8000
mkdocs build --strict         # what CI runs before publishing to gh-pages
```

## Architecture invariant (do not break)

`openvc` (the core) imports **nothing upward**: it must not import from
`openvc_ebsi` or from any consumer. `openvc_ebsi` depends on `openvc`, never the
reverse. Keep EBSI/network specifics out of the core.

## Naming conventions

Public names follow the patterns in [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md)
(class role-suffixes, verb-first functions, the `peek_*` untrusted-inspection
rule, the error hierarchy). New code should match them.

## Commit convention

Commits follow **Conventional Commits**, enforced by `gitlint` (`.gitlint`):

```
type(optional-scope): subject
```

- **Types:** `feat`, `fix`, `security`, `perf` (changelog-worthy); `docs`,
  `chore`, `ci`, `test`, `refactor`, `build`, `style`, `release` (silent —
  `release: vX.Y.Z` is what the /release runbook commits).
- **Scope** (optional): a lowercase area, e.g. `feat(ebsi):`, `feat(proof):`,
  `fix(fetch):`.
- **Subject:** imperative, lower-case, no trailing period; title ≤ 80 chars.
- `!` after the type/scope (or a `BREAKING CHANGE:` body trailer) marks a breaking
  change.
- **No `Co-Authored-By` and no "Generated with" trailers.**

Examples from the history:

```
feat(ebsi): recursive TI->TAO->RootTAO trust chain verification
feat(proof): Data Integrity suite (eddsa-rdfc-2022), W3C-vector-conformant
feat(fetch): pin did:web connection to validated IP (close DNS rebinding)
docs: fix stale docstrings and status/roadmap drift
```

Changelog-worthy commits (`feat`/`fix`/`security`/`perf`) should have a matching
entry under the top `## [x.y.z] — unreleased` heading in `CHANGELOG.md`.
