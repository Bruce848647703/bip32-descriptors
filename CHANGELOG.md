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

## v2026.11.11

### ecc 2026.11.8, btclib 2026.11.10 and base58-bech32

ecc's schemes come from its top level, `bms` from btclib's, and the
Base58Check codec from base58-bech32, a new dependency (closes #108)
(closes #139) (closes #140) (closes #156).

### crack_prv_key

`crack_prv_key_var` is renamed `crack_prv_key`, with no alias
(closes #63).

### A hand-built key expression refuses what parse refuses

A `KeyExpression` built by hand refuses a key, a hardening, a `musig()`
or a path that `parse` would not build (closes #171) (closes #178)
(closes #179) (closes #181) (closes #182) (closes #183).

### A hand-built sh(), wsh() or tr() refuses what parse refuses there

Built by hand, they refuse a field, a function, a key or a size that
`parse` refuses there (closes #46) (closes #158) (closes #174)
(closes #175) (closes #194).

### A hand-built fragment refuses a field or a key parse refuses

`wpkh()`, `multi()`, `rawpkh()` and the other fragments refuse when
built a field of the wrong type and a key `parse` refuses there
(closes #103) (closes #150) (closes #159) (closes #161) (closes #200).

### A hand-built miniscript refuses what parse refuses

A `Miniscript` built by hand refuses a field of the wrong type, a key
that is no `KeyExpression` and a script that is not sane (closes #85)
(closes #119) (closes #141) (closes #153) (closes #170).

### A hand-built miniscript keeps one context

A node refuses a subexpression of another context, a `tr()` leaf one
that is not tapscript, and neither quotes an unknown fragment or context
(closes #111) (closes #120) (closes #130).

### satisfy() refuses a sh() or wsh() over the size limit

A hand-built `sh()` or `wsh()` whose script is over the size limit has
no spend (closes #47).

### unused() and preimage()

`parse` reads `unused(KEY)` at the top level (closes #134) and a hash
fragment's `preimage(HEX)` (closes #11).

### private_string writes the WIFs back

`private_string` writes back what `parse` files in `prv_keys`,
`preimages` and `wifs` (closes #137) (closes #148), and finds a WIF
under either hex spelling of its key (closes #147).

### An odd-y WIF's x-only key is its even-y key

An x-only key read from an odd-y WIF is held as its even-y key
(closes #177) (closes #192).

### A miniscript is typed once it is read, as Core does

An ill-typed fragment is refused once the expression is read, so a later
fault is named first (closes #16).

### Text not ending in ) is miniscript in wsh() and in a tr() leaf

Whatever function name it starts with, such text is read as miniscript
and gets Core's fallback (closes #15) (closes #19).

### c:pk_k and c:pk_h read as pk() and pkh()

`wsh(c:pk_k(K))` and `wsh(c:pk_h(K))` read as `pk()` and `pkh()`, and a
`tr()` leaf `c:pk_k(K)` as the key (issue #174) (issue #194).

### A multipath key's paths share one symbol, as Core writes them

Each path of a multipath key is written in the hardening symbol Core
keeps for the key (closes #72).

### multi() and multi_a() refuse in Core's order

A `multi()` refuses its threshold before its keys, and more than 20 keys
before its threshold; a `multi_a()` its threshold before its keys
(closes #17) (closes #102) (closes #107).

### Refusals name Core's fault

For a bracket after a multisig key, an expression no function takes and
a miniscript of the wrong type, refusals name Core's fault (closes #14)
(closes #53) (closes #118) (closes #128).

### Refusals name a key by its position

A refused key is named by its position, a short unknown function is
quoted, and an unknown context is not (closes #18) (closes #133).

### Mutation testing

The mutation profiles' last survivors are killed or named (closes #41),
and the bip32 session has 80 minutes (issue #50).

### Core's and BIP394's vectors

Core's miniscript and descriptor vectors are pinned to their tip and
cited at the v32.1 pin (closes #22) (closes #62) (issue #51); BIP394's
`rawtr()` vectors are tested (closes #12).

### Tests

Tests only: `raw()`'s refusal of whitespace, two hardened children of
one xprv as Core derives them (closes #8) (closes #98), and
`compare_descriptors.py` reads only a row's descriptor (closes #97).

### CI

Every call into btclib-org/.github moves to v2026.11.11,
`release.yml`'s among them, and `claude-implement.yml` calls one, off
until the organization enables it (issue btclib-org/.github#1999).

### Coverage and the docs

The coverage floor measures `.github/scripts` (closes #89)
(closes #126), and the docs read the ecc and btclib inventories
`uv.lock` pins (closes #160).

### CONTRIBUTING.md and the README

Both follow btclib-org/.github: the shared part, absolute links, the
badges last (issue btclib-org/.github#2088)
(issue btclib-org/.github#1851) (issue btclib-org/.github#1856).

### The standard's citation

The tree names the organization's standard as its section 11 asks, and
the shared files cite it as btclib-org/.github does
(issue btclib-org/.github#2137).

### The prose

`CONTRIBUTING.md` says a signature takes `check_validity` keyword-only
(closes #114); the prose says only what holds in the mutation profiles
and the base58 cache (closes #23) (closes #42).

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
