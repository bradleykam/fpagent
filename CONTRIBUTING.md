# Contributing to fpagent

Thanks for wanting to help. fpagent is small by design, so the contribution
surface is narrow: bug fixes and packaging improvements move fast, and
anything that touches the fingerprinting algorithm, canonicalization, or
manifest format needs a spec change first.

## Code changes

1. Fork and clone the repo.
2. Create a branch off `main`.
3. Set up the dev environment:

   ```
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

4. Run the tests — they should all pass before you start:

   ```
   pytest tests/
   ```

5. Make your change. Add a test that fails before and passes after.
6. Run the tests again. `pytest tests/` must be green.
7. Open a PR describing the change, the motivation, and any follow-ups.

We use GitHub Actions to run the test matrix (Python 3.10, 3.11, 3.12 on
Linux, macOS, Windows) on every PR. CI must be green before merge.

### Tests

Tests run with [pytest](https://docs.pytest.org/). See `pytest tests/`.
Coverage comes from `pytest-cov`; CI runs `pytest tests/ -v --cov=fpagent`
and uploads to Codecov.

The `tests/fixtures/conformance/` vector is the **authoritative check** that
an implementation matches the spec. If you change fingerprinting code and
the conformance test still passes, you haven't regressed output. If it fails,
one of two things happened: a bug (fix it), or an intentional spec change
(see below — don't silently regenerate the vector).

## Spec changes

Changes to canonicalization, fingerprint algorithms, ID-detection heuristics,
or the manifest format are spec changes. They follow a lightweight RFC flow:

1. Open an issue describing the problem you're solving.
2. Write an RFC at `docs/rfcs/NNNN-title.md` (use the next free number).
   Include: motivation, proposed change, migration plan, compatibility
   impact.
3. Post a PR with the RFC and loop in maintainers. Expect at least 2
   maintainer approvals before merging.
4. After the RFC merges, land the implementation as a separate PR that bumps
   `SPEC_VERSION` per the rules in `SPEC.md` §1, regenerates the conformance
   vector, and updates `CHANGELOG.md`.

A change that breaks existing manifests is a major spec bump; a change that
adds a field or a non-breaking heuristic tweak is a minor; documentation
clarifications are a patch.

## Security issues

Please read [SECURITY.md](SECURITY.md) before reporting anything security-
relevant. Do not open public issues for vulnerabilities.

## Releasing (maintainers)

Releases are automated via `.github/workflows/release.yml` on a version tag
push:

1. Update `CHANGELOG.md` — move `[Unreleased]` entries under a dated release
   heading.
2. Bump `version` in `pyproject.toml` and `src/fpagent/version.py`.
3. Commit, tag `v0.X.Y`, push the tag.
4. The release workflow builds sdist and wheel, verifies the wheel installs
   and `fpagent --version` works, and opens a GitHub Release with the
   changelog entry as the body and the built artifacts attached.

Users install with `pip install git+https://github.com/bradleykam/fpagent`
or by downloading a wheel from the Releases page. PyPI publishing is not
configured; add it later if there's demand.

## House rules

- Keep the public API small. If you're about to add a parameter, ask whether
  it can be defaulted or inferred.
- No networking. The agent is local-only by design.
- No new dependencies without a motivating RFC.
- Format code with `ruff` (config lives in `pyproject.toml` when added).
