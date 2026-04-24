# Supply-chain verification

Every fpagent GitHub Release carries three things beyond the wheel and sdist:

- **CycloneDX SBOM** (`fpagent-<version>.cdx.json`) — the dependency closure
  of the installed wheel, generated with
  [`cyclonedx-bom`](https://pypi.org/project/cyclonedx-bom/) in CI.
- **Sigstore signatures** (`*.sigstore.json`) — one per artifact, signed via
  GitHub OIDC during the release workflow using
  [`sigstore-python`](https://github.com/sigstore/sigstore-python).
  Keyless: the signer identity is the GitHub Actions workflow run, not a
  long-lived key you have to trust separately.

This page is the shortest set of commands that verifies each one.

## Requirements

```
pip install sigstore
```

## Verify a wheel against its Sigstore bundle

1. Download the wheel and its `.sigstore.json` from the release page.
2. Run:

   ```
   sigstore verify github \
     --cert-identity https://github.com/bradleykam/fpagent/.github/workflows/release.yml@refs/tags/v0.2.0 \
     --cert-oidc-issuer https://token.actions.githubusercontent.com \
     --bundle fpagent-0.2.0-py3-none-any.whl.sigstore.json \
     fpagent-0.2.0-py3-none-any.whl
   ```

   Swap `v0.2.0` for whichever tag you're verifying.

Any failure exits non-zero. A passing verification proves the wheel was
signed by the published release workflow running on the bradleykam/fpagent
repository at that tag — not by anyone else's token or a stolen key.

## Check the SBOM

The SBOM is a standard CycloneDX 1.5 JSON document. The fastest useful check
is "what am I actually installing?":

```
jq '.components[] | {name, version, purl}' fpagent-0.2.0.cdx.json
```

For structural validation against the CycloneDX schema:

```
pip install cyclonedx-bom
cyclonedx-py validate --input-file fpagent-0.2.0.cdx.json
```

And for vulnerability scanning — point your SCA tool at the JSON. fpagent
doesn't ship its own scanner.

## What's not here

- **SLSA build provenance.** Deliberately not wired for 0.x. The Sigstore
  keyless signature already carries the workflow identity (same signal),
  so SLSA would be a second layer of the same fact for a pre-1.0 alpha with
  no enterprise consumers demanding it. Reopen the question at 1.0.
- **PyPI attestations.** fpagent is not published to PyPI; the install
  surface is `pip install git+https://github.com/bradleykam/fpagent` or a
  wheel from the Releases page. See CONTRIBUTING.md § Releasing.

## If verification fails

- Check you have the exact files the release page serves (not a cached or
  re-compressed copy).
- Check the release-workflow tag in `--cert-identity` matches the tag you
  downloaded. A bundle signed for `v0.2.0` will not verify against a
  `v0.1.0` artifact.
- Open an issue with the command you ran and its output.
