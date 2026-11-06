# Security policy

## Reporting a vulnerability

If you have found a security vulnerability, please do not open a GitHub
issue: an issue is public from the moment it is filed, and so is the
window between filing it and a fix being released.

Report it privately instead, by
[opening a security advisory](https://github.com/btclib-org/bip32-descriptors/security/advisories/new).
Only the maintainers can see it, the discussion stays private until an
advisory is published, and a CVE can be requested from it if the
vulnerability warrants one.

If you have no GitHub account, or would rather not use it for this,
responsible disclosure by email to *security at btclib dot org* is
equally welcome.

A report is acknowledged within 7 days, and a fix or a published advisory
follows within 90 days.

A report triaged as easy to rediscover is fixed as soon as possible, since
anyone can find it in the meantime, and its advisory is published with the
fix.

## What belongs here, and what belongs upstream

This package is built on [btclib](https://github.com/btclib-org/btclib),
which holds the codecs, scripts, addresses and taproot, and on
[ecc](https://github.com/btclib-org/ecc), which holds the curve
arithmetic and the signature schemes. secp256k1 arithmetic is delegated
further down to
[btclib-secp256k1](https://github.com/btclib-org/btclib-secp256k1) and
[libsecp256k1](https://github.com/bitcoin-core/secp256k1). A flaw in the
curve arithmetic, in a codec or in a script template most likely belongs
to one of those, each with its own security policy.

What belongs here is everything this package does on top of them:

- BIP32: extended key serialization, private and public derivation,
    derivation paths and key origins
- the parsing of output descriptors, key expressions, miniscript and
    wallet policies, the validation that decides what is accepted, and
    the scripts, addresses and witnesses they are expanded to
- the distributions published to PyPI and their provenance

A refusal that prints a value that may be secret belongs here: [*A refusal
carries no
secret*](https://github.com/btclib-org/.github/blob/main/README.md#a-refusal-carries-no-secret)
says what a refusal may print.

Report it wherever you found it, though: routing a report is the
maintainers' job, not the reporter's, and a doubt about which project
owns a flaw is not a reason to keep it to yourself.

## Security review

No security review has been done yet. The
[assurance case](./ASSURANCE_CASE.md) is what one is done against.

## Supported versions

Only the latest release is supported. Versions are calendar-based
(`YYYY.M.D`), a fix is published as a new release, and nothing is
backported.

Wheels and sdist are published to PyPI with PEP 740 attestations, through
a workflow that no long-lived token can authenticate for (PyPI Trusted
Publishing), so a distribution can be traced back to the workflow run and
the commit it was built from.

The same files are attached to the GitHub release, and those copies carry
a build provenance attestation of their own, signed in the run that built
them:

```shell
signer=btclib-org/.github/.github/workflows/reusable-build.yml
id=$(gh api repos/btclib-org/bip32-descriptors --jq .id)
cert='.[].verificationResult.signature.certificate'
```

```shell
gh attestation verify <file> --owner btclib-org \
  --signer-workflow "${signer:?}" \
  --source-ref refs/tags/v<version> --format json \
  --jq "${cert:?}.sourceRepositoryIdentifier" | grep -qx "${id:?}"
```

The exit code is `0` only where a verified attestation names this
repository. The repository is compared by its id, which a rename keeps:
`--repo` compares the current name and refuses every release signed
before a rename.

`<file>` is a distribution file from the release.

`--signer-workflow` is what makes that say which workflow signed, rather
than accepting any attestation this repository has: the signing runs in
`btclib-org/.github`'s `reusable-build.yml`, which `release.yml` calls,
and `--source-ref` is what keeps a build of a branch from passing as the
release.
A CycloneDX bill of materials is attached beside them, generated from the
built wheel and covered by the same attestation. Either distribution file
can also be rebuilt from its tag and compared, the build being
reproducible: RELEASING.md has that command.

## Where constant time ends

The [assurance case](./ASSURANCE_CASE.md) is the threat model these are
written against, and the argument for what this file does promise.

These are known and inherent, and worth stating because this package is
used to teach and to prototype as much as to build.

- **The arithmetic is ecc's, and so is its notice.** BIP32's derivation
    reaches libsecp256k1 through ecc, where ecc's own predicate lets it,
    and runs ecc's Python arithmetic otherwise — which is validated
    against the bindings but is not constant-time. Which operations
    cross the boundary, under which conditions, and what the Python path
    leaks is
    [ecc's SECURITY.md](https://github.com/btclib-org/ecc/blob/main/SECURITY.md),
    and this file does not restate it.
- **An install decides whether the boundary is there.**
    `pip install "bip32-descriptors[secp256k1]"` installs the bindings,
    through ecc's own extra; `pip install bip32-descriptors` installs no
    C, and every secret then meets the Python arithmetic.
    Nothing raises to say so, and `ecc.curves.is_libsecp256k1_serving()`
    is how a caller asks which of the two it has.
- **BIP32's private derivation delegates where it can**: it is ecc's
    `prv_key_tweak_add`, so with the bindings serving the child key is
    `secp256k1_ec_seckey_tweak_add`'s; without them it is a sum of Python
    integers, variable in time with the operands.
- **Secret material lives in Python objects**, which are immutable and
    not zeroized: an extended private key, or a private key a descriptor
    carries, stays in the process memory until garbage collection, and
    may have been copied by the interpreter meanwhile.
    `bip32._cached_base58_decode` extends this by one step for an xprv
    string handed to a derivation: the decoded key stays reachable from
    that cache, bounded by its `maxsize`, past whatever reference the
    caller itself still holds.
