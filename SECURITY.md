# Security Policy

## Reporting vulnerabilities

If you discover a security issue in fpagent, please **do not** open a public
GitHub issue. Email the maintainers at **security@fpagent.dev** (placeholder —
maintainer to replace before first public release) with:

- A description of the issue and its impact.
- Reproduction steps or a minimal proof of concept.
- Your suggested fix, if any.

We aim to acknowledge reports within 3 business days and to ship a fix or
mitigation within 30 days for high-severity issues. Once a fix is released we
will credit reporters in the release notes unless you ask to stay anonymous.

A GPG key for encrypted reports will be published on the project's first
security advisory; until then, please send plaintext and avoid including
sensitive sample data.

## Known v1 caveat: manifest signing

The v1 manifest signature is a **SHA-256 self-sum** of the manifest body.
This detects accidental corruption or casual tampering but is **not**
cryptographically secure against a determined adversary: anyone holding the
manifest can recompute the sum after modifying it.

Production deployments that need authenticity (a buyer trusting that a
manifest was genuinely produced by a given seller) should wait for v2, which
will use Ed25519 signatures over canonicalized manifest bytes with public
keys published out-of-band.

Until v2 ships, treat the v1 signature the same way you'd treat a checksum:
useful for integrity, not for authenticity.

## Supported versions

Only the latest `0.x` release receives security fixes during the alpha phase.
Once 1.0 ships, we will support the current major version and backport
critical fixes to the previous major for at least 6 months.
