# Changelog

<!-- markdownlint-configure-file
  {
    // MD024/no-duplicate-heading - every release repeats the same few
    // headings, which is what keeps the page readable scrolling down it;
    // only a duplicate under the same release heading would be the
    // accident this rule looks for
    "MD024": { "siblings_only": true }
  }
-->

The release's own pull request writes its section here, from the squash
subjects since the previous tag; a pull request adds no entry
(`CONTRIBUTING.md`'s *Pull requests*, section 9 of [the organization
standard][std]). [RELEASE_NOTES.md](./RELEASE_NOTES.md) has the release
notes, which say what a user has to act on; this file is the record
behind them.

[std]: https://github.com/btclib-org/.github

## v2026.11.7

### BIP32 derives through ecc

`bip32` derives through ecc and imports no bindings; ecc's floor is
2026.11.6, and the `secp256k1` extra names `ecc[secp256k1]` (closes #21).

### str() keeps the key path's hardened marker, as Core does

A hardened step of the key path decides the marker before the wildcard's,
so `str()` writes Core's string and checksum (closes #9).

### Tests

Tests only: `satisfy`, an andor's op count, a tap tree's depth, checksum
tails, `from_script`'s refusals and a run-time tapscript context
(closes #36) (closes #37) (closes #38) (closes #39) (closes #40).

### Sourcery

Sourcery runs on every pull request, and its findings in `src` are
cleared (issue btclib-org/.github#2005).

### CI and the lock

Every call into btclib-org/.github moves to v2026.11.5, `release.yml`'s
among them (issue btclib-org/.github#2005); setup-uv moves (#83); btclib
is locked at 2026.11.2 (closes #5).

### The metadata and the prose

The homepage is `https://btclib.org/bip32-descriptors/` (closes #48);
the files shared with btclib-org/.github follow it, and comments name the
`functional-tests` and `ecc` repositories (closes #25) (closes #61).

## v2026.11.4

### infer_descriptor answers what parse reads back

Where `parse` does not read what `infer_descriptor` infers back to the
script, `infer_descriptor` answers the `addr()` of the output, or its
`raw()` where the output has no address (closes #44).

### A tree's twins are written out up to 1024 leaves

`infer_descriptor` writes out a repeated subtree of a `tr()` only where
the tree then holds at most 1024 leaves, and past that answers each twin
as the `rawnode()` of its hash (closes #45).

### bip32.py's refusal messages are tested whole

Tests only: refusal messages are compared whole, and boundaries no test
reached are tested (closes #33) (closes #32) (closes #34) (closes #35).

### CI

`os-macos.yml` and `pypi-install.yml` run macOS on arm64 alone (issue
btclib-org/.github#1982). The actions group's pins move, `release.yml`'s
among them (#1), and so do the pre-commit hook revisions (#65).

### The prose

The shared part of `CONTRIBUTING.md` follows btclib-org/.github (#58),
and `RELEASING.md` names the lint jobs a release run skips (issue
btclib-org/.github#1989).

## v2026.11.2

### rawnode, rawleaf, rawpkh and nested raw, and a tr() inference

`parse` reads `rawnode()`, `rawleaf()`, `rawpkh()`, and `raw()` in `sh()`
and `wsh()`; `infer_descriptor` uses them for a `tr()` it reads in part;
`raw()` refuses an empty or whitespace HEX (closes #7) (closes #6).

### A deeply nested tr() leaf infers as its miniscript, on any interpreter

`infer_descriptor` walks a leaf without recursion, so the interpreter's
stack no longer decides what it answers (closes #54).

### A tr() tree is read leaf by leaf, as Core's tr() loop does

A fault inside a leaf gets Core's answer instead of `unbalanced braces`
(closes #13) (issue #19).

### Core's miniscript fallback beyond timelocks and multisig context

Wrappers, numbers, hashes, unbalanced brackets and trailing text get the
refusal Core falls back to (closes #10).

### A key spelled twice in a fragment takes v32.1's origin

`Descriptor.provider` gives Bitcoin Core v32.1's origin, and
`_taproot_derivations` says why the updater keeps the first (closes #20).

### The prose

`integration-bitcoind.yml` says regtest is a required check (closes #24);
the README and `ARCHITECTURE.md` stop calling btclib-wallet a library
above this one (closes #26).

## v2026.10.31

### The repository opens with btclib-wallet's bip32 and descriptors

btclib-wallet's `bip32` and `descriptors` at b8b5c9b, with their tests,
renamed to `bip32_descriptors`, around base58-bech32's repository files;
the integration workflow pins bitcoind 32.1 (issue btclib-org/.github#1811).

### The prose describes this package

The review bot's prompt, AUTHORS.md and a pypi-install comment describe
this package, not base58-bech32; comments naming btclib-wallet's modules
say they are btclib-wallet's (issue btclib-org/.github#1811).

### The README shows the OpenSSF badges

The Best Practices and Baseline badges of bestpractices.dev project
16116, which RELEASING.md also reads at release.
