---
name: release
description: >
  End-to-end audit-and-publish runbook for the openvc library. Audits the repo
  (green flake8/mypy/pytest, clean tree, gitlint), runs a DOCUMENTATION
  ANTI-DRIFT check (README/ROADMAP/CHANGELOG/docstrings must match the code),
  computes the next SemVer version, dates the CHANGELOG, bumps the single-source
  openvc.__version__, commits and lightweight-tags `vX.Y.Z`, pushes to trigger
  the CI → PyPI Trusted-Publishing job, then verifies the package is live and
  cuts the GitHub Release. Use this whenever the user wants to ship or audit a
  release of openvc — "publica openvc", "saca/haz una release", "publica la
  vX.Y.Z", "sube openvc a PyPI", "audita y publica", "taguea y publica",
  "release openvc", "bump the version and publish", "check the docs for drift
  before release" — even if they only name a version or say "publícala". Do NOT
  use it to review a diff/PR (that is /code-review), to author CHANGELOG entries
  (those are written as features land), for an ordinary `git push` that is not a
  version release, to only tag a commit without publishing, or to publish a
  different project (this runbook is openvc-specific: src-layout, the [all]
  extras, PyPI Trusted Publishing).
---

# openvc release

## Arguments

`/release [level|version] [--dry-run]`

- `level|version` — force the bump as `major` / `minor` / `patch`, or pass an
  explicit `X.Y.Z`. **Default: derive it** from the CHANGELOG `unreleased`
  section cross-checked against commit types (STEP 1).
- `--dry-run` — do everything locally **up to but not including the push**: print
  the version, the doc-audit result, the CHANGELOG diff and the full verification,
  then stop. Nothing irreversible happens.

# HOW openvc PUBLISHES (mental model — read before acting)

- **Version has a single source of truth:** `src/openvc/__init__.py`
  `__version__`. `pyproject.toml` reads it dynamically (by AST via
  `[tool.setuptools.dynamic]`), so bumping that one line is the whole version
  change.
- **Publishing is CI-driven, tag-triggered.** Pushing a `vX.Y.Z` tag runs
  `.github/workflows/ci.yml`: the test matrix (3.10–3.14) then the **Publish to
  PyPI** job via `pypa/gh-action-pypi-publish` using **Trusted Publishing (OIDC)**
  — no API token. The tag push *is* the publish; it is the single irreversible,
  outward-facing act.
- **The CHANGELOG is written incrementally** under a `## [X.Y.Z] — unreleased`
  heading (Keep a Changelog). Releasing means **dating** that heading, not
  authoring it.
- **A version on PyPI can never be replaced** — only *yanked* and superseded by a
  new patch. That is why the pre-flight and gates below are strict.
- **Environment:** run every tool via `.venv/bin`. `pytest`/`mypy`/`flake8`/
  `gitlint` come from `pip install -e ".[all]"`; the `pyld`/`httpx`-gated tests
  only run with `[all]` (the DI/EBSI suites `importorskip` otherwise).

# THE RELEASE FLOW

Each step is a gate: do not advance past a failure. Nothing is irreversible until
STEP 6.

## STEP 0 — PRE-FLIGHT (abort on any failure; nothing changed yet)

- `gh auth status` succeeds and an `origin` remote exists
  (`git remote get-url origin`). **If there is no remote yet, STOP** — openvc
  cannot publish until the GitHub repo exists and PyPI Trusted Publishing is
  configured for it (repo + `ci.yml` + the `pypi` environment). Report this and
  stop; it is a one-time human setup, not something this skill can do.
- On branch `main`; `git fetch origin` then confirm local is **level with
  `origin/main`**.
- **Working tree clean for tracked files.** Stage files explicitly by path;
  **never `git add -A`** (it would stage `.claude/` local state or stray files).
- After STEP 1 fixes the version, assert the release does not already exist: tag
  `vX.Y.Z` absent locally and on `origin`, and the version **not already on PyPI**
  (`curl -s -o /dev/null -w '%{http_code}' https://pypi.org/pypi/openvc-core/X.Y.Z/json`
  must be `404`). If any exist, this is a resume — see RECOVERY.

## STEP 1 — DETERMINE THE VERSION

1. Read the top `## [X.Y.Z] — unreleased` heading in `CHANGELOG.md`.
2. **Independently compute** the expected bump from commit types since the last
   tag (`git log $(git describe --tags --abbrev=0 2>/dev/null || echo '')..@
   --format=%s`), using the `.gitlint` vocabulary: a `!`/`BREAKING CHANGE:` →
   **major**; else any `feat` → **minor**; else `fix`/`security`/`perf` →
   **patch**; only silent types → no release-worthy change (warn and stop).
   (For the first release there is no prior tag — the whole history counts.)
3. The declared version and computed bump **must agree**. An explicit argument
   wins but still cross-check; on a mismatch **STOP and ask**.

## STEP 2 — DOCUMENTATION ANTI-DRIFT AUDIT (gate; the docs must match the code)

Stale docs are worse than none. Before dating anything:

- Run the mechanical checker: `.venv/bin/python .claude/skills/release/scripts/check_docs.py`.
  It fails on: an extra named in `README.md`/`CONTRIBUTING.md` that is not in
  `pyproject` `[project.optional-dependencies]`; a `README` python quick-start
  whose `import`/`from … import …` does not resolve (renamed/removed symbol); and
  `openvc.__version__` not matching the top `CHANGELOG` heading.
- Then read, as an agent, and reconcile against the code: `README.md` (layout
  tree lists real modules; "Status"/features match what exists), `docs/ROADMAP.md`
  ("Done" ⊇ shipped features; nothing implemented still under "Next"), and the
  **module docstrings** of anything touched since the last release (they must not
  claim a feature is "later"/"not yet"/"the next step" when the code implements
  it — this is the exact drift class the audit keeps catching).
- Any drift found here is fixed **now** (as `docs:` edits) before proceeding. A
  release must not ship docs that describe a past state.

## STEP 3 — BUMP + DATE (local edits only)

- Set `__version__` in `src/openvc/__init__.py` to `X.Y.Z` (the **only** place).
- Change the CHANGELOG heading `## [X.Y.Z] — unreleased` → `## [X.Y.Z] — <today>`
  (ISO `YYYY-MM-DD`) and confirm its `[X.Y.Z]: …/tag/vX.Y.Z` link.

## STEP 4 — LOCAL VERIFICATION GATE (must be fully green before any commit/tag)

Via `.venv/bin`, require all green with no unexpected skips:

- `flake8 src tests`
- `mypy`
- `pytest -q`  (the `[all]` extra must be installed so the DI/EBSI tests run —
  `.venv/bin/python -c "import pyld, httpx"`; if missing, `pip install -e ".[all]"`)
- `python -m build` then `twine check dist/*` — the sdist+wheel must build and the
  metadata pass (confirms the dynamic version, PEP 639 license, and that `py.typed`
  + the bundled contexts ship). Remove `dist/` afterwards.

If anything is red: **STOP**, report, do not proceed. Never tag a red tree.

## STEP 5 — COMMIT + TAG (local, still reversible)

- Stage **only** the release files by path: `git add src/openvc/__init__.py
  CHANGELOG.md` (plus any `docs:` fixes from STEP 2, by path).
- Commit `release: vX.Y.Z` (gitlint-conformant; title ≤ 80). **No `Co-Authored-By`
  / "Generated with" trailers.** Verify: `.venv/bin/gitlint --commits HEAD~1..HEAD`.
- Create a **lightweight** tag: `git tag vX.Y.Z`.

## STEP 6 — CONFIRM, THEN PUSH (point of no return)

- The tag push triggers the **irreversible** PyPI publish. Unless `--dry-run` and
  unless the user already clearly authorized publishing this turn, **confirm**.
- `git push origin main vX.Y.Z`.
- With `--dry-run`: **stop here** and print the plan instead of pushing.

## STEP 7 — VERIFY THE PUBLISH LANDED

- Watch the tag's CI run: `gh run list --workflow=ci.yml --limit 5` → the entry
  whose head ref is `vX.Y.Z`; `gh run watch <id> --exit-status`. Require every
  matrix job **and** the Publish job = success.
- Confirm live: poll `https://pypi.org/pypi/openvc-core/X.Y.Z/json` until HTTP `200`
  (Fastly CDN can lag; the per-version endpoint is authoritative).

## STEP 8 — GITHUB RELEASE

- Draft notes from the `CHANGELOG.md` section for `X.Y.Z`. Only claim checks you
  actually ran.
- `gh release create vX.Y.Z --verify-tag --latest --title "vX.Y.Z" --notes-file <notes>`.

# RECOVERY / IDEMPOTENCY

One irreversible step (the tag push). Re-running must never double-commit/tag:

- Tag exists locally but not on origin → resume at STEP 6.
- Tag on origin but CI failed → the code is public but unpublished; do **not**
  move the tag — fix forward with a new patch (a pushed tag's PyPI artifact cannot
  be replaced).
- Version on PyPI but no GitHub Release → resume at STEP 8.
- Release already exists → nothing to do; report state.

# WHAT THIS SKILL DOES NOT DO

- It does not create the GitHub remote or configure PyPI Trusted Publishing —
  those are one-time human setup (STEP 0 stops if absent).
- It does not author CHANGELOG entries (written as features land; this dates them).
- It does not `git add -A`, never adds `Co-Authored-By`, never edits license
  headers.

# GUARDRAILS (recap)

- Never `git add -A`; stage release/doc files by path.
- Never tag or push a red tree, or one whose docs still drift (STEP 2 is a gate).
- Confirm before the irreversible tag push (unless `--dry-run` or already
  authorized).
- Remember there is no PyPI rollback — only yank + a new patch.
