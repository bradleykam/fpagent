# Signing manifests

fpagent 0.2.0+ signs manifests with Ed25519 under spec v1.1.0. Old SHA-256
self-sum manifests (v1.0.0) still verify, with a clear warning that they're
unsigned-in-the-cryptographic-sense.

## Why Ed25519

Before 0.2.0 a manifest carried a SHA-256 of its own body. That detects
accidental corruption but is useless against a determined adversary — anyone
can recompute the hash after modifying the manifest.

Ed25519 binds the manifest to a specific private key. A verifier who trusts
the corresponding public key (via out-of-band distribution) can confirm:

- The manifest bytes have not been modified since signing.
- The manifest was produced by someone holding that private key.

What it does **not** prove: that the source data is correct, that the signer
is honest, or that you should trust the signer at all. See SPEC.md §7.4.

## Generate a keypair

```
$ fpagent keygen --output ~/keys/fpagent
✓ Private key: /Users/you/keys/fpagent (0600)
✓ Public key:  /Users/you/keys/fpagent.pub
  Distribute the .pub file out-of-band to anyone who verifies your manifests.
```

The private key is written with `0600` permissions. Treat it the same way you
treat an SSH private key: never commit it, never email it, never leave it in
CI secrets that get echoed to logs.

## Sign a manifest

```
fpagent fingerprint \
  --input ./mydata.jsonl \
  --output manifest.json \
  --signing-key ~/keys/fpagent
```

The manifest's `signature` field becomes an object:

```json
{
  "algorithm": "ed25519",
  "value": "<base64 signature>",
  "public_key_fingerprint": "<sha256 hex of public key bytes>"
}
```

and `spec_version` is bumped to `1.1.0`.

Omit `--signing-key` to fall back to the v1.0.0 SHA-256 self-sum — useful
when you don't need authenticity, e.g. for internal checksums.

## Verify a signed manifest

Share the `.pub` file with the verifier via an out-of-band channel they trust.
They pass it to `verify`:

```
fpagent verify \
  --manifest manifest.json \
  --input ./mydata.jsonl \
  --public-key ~/keys/fpagent.pub
```

Or point at a directory of trusted `*.pub` files:

```
fpagent verify \
  --manifest manifest.json \
  --input ./mydata.jsonl \
  --public-key ~/keys/trusted_signers/
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | content matches AND signature verifies |
| 1 | content mismatch (records differ from manifest) |
| 2 | schema-invalid manifest |
| 3 | signature failure only (signature bad; content fine) |

Exits 1 and 3 are distinct on purpose: CI pipelines can triage accordingly.
A content mismatch usually means the input changed; a signature failure
means the manifest was tampered with or signed by a key you don't trust.

## Distributing public keys

There is no PKI. The trust decision is yours. Reasonable options:

- Publish the `.pub` file on your organization's website over HTTPS.
- Include it in the release of whatever software produces the manifests.
- Pin the 64-character `public_key_fingerprint` in your verifier's config and
  refuse to match anything else.

The fingerprint is what verifiers should pin — it's short, copy-pasteable, and
does not change if you re-encode the key.

## Key rotation

fpagent does not build in an expiration or revocation mechanism. Rotate keys
on your own cadence:

1. Generate a new keypair.
2. Publish the new `.pub` alongside the old one.
3. Start signing new manifests with the new key.
4. After a grace period, stop honoring the old key in verifier configurations.
5. Announce any compromise out-of-band and invalidate affected manifests.

For most use cases, one keypair per signing service with a yearly rotation is
overkill — but the machinery to rotate is there when you need it.

## Backward compatibility

A v1.0.0 manifest (string signature) still verifies:

```
fpagent verify --manifest old.json --input ./data.jsonl
⚠ SHA-256 self-sum verified — integrity only, NOT cryptographic authenticity
```

Exit code 0 on match. The warning is unconditional when a v1.0.0 signature
is observed; there's no way to suppress it. If you care about authenticity,
re-sign the manifest with Ed25519.
