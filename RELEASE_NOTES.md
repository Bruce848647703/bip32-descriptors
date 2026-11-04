# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.11.4

Where `parse` does not read what `infer_descriptor` infers back to the
same script, `infer_descriptor` answers the `addr()` of the output, or
its `raw()` where the output has no address, such as a bare `multi()` or
a `pk()`. v2026.11.2 answered a descriptor that `parse` refuses: for
example, one holding a key that is no point, a `wsh()` of a miniscript
that cannot be satisfied, or a bare `multi()` of more than three keys.
Code that compares the answer with Core's `decodescript` or
`scantxoutset` has to expect these.

For a p2tr output, `infer_descriptor` writes out a repeated subtree only
where the tree then holds at most 1024 leaves. Past that, each repeat is
the `rawnode()` of its hash, where v2026.11.2 wrote every one out. Code
that expects the repeats written out meets `rawnode()` instead.

No workflow tests this release on x86_64 macOS: `os-macos.yml` and
`pypi-install.yml` run macOS on arm64 alone.

## v2026.11.2

`parse` reads `rawnode()`, `rawleaf()` and `rawpkh()`, and `raw()` inside
`sh()` and `wsh()`, which let a descriptor say what it knows of an output
it knows in part. Their classes are `RawNode`, `RawLeaf` and
`RawPkhDescriptor`.

This breaks the API. `DescriptorLeaf` gains `RawLeaf`, and
`DescriptorTree` gains `RawNode`, so code that walks the `tree` of a
`TrDescriptor` meets them. For a `tr()` whose tree holds a `rawnode()`,
`expansion()` gives the internal key, the merkle root and the known leaf
scripts, with `taproot_tree` None: such an expansion describes an input,
and an output's Updater has to refuse it.

`infer_descriptor` answers a `tr()` holding a `rawleaf()` or a
`rawnode()` where it cannot write every leaf as a descriptor, or knows
only part of the tree, where v2026.10.31 answered `rawtr()`.

`infer_descriptor` reads a script nested past the interpreter's recursion
limit, where v2026.10.31 raised `RecursionError`: a `tr()` leaf infers as
its miniscript, and a `wsh()` script past the ops limit as `addr()`.

`raw()` refuses an empty HEX and a HEX with whitespace, where
v2026.10.31 read `raw( 51)` as `raw(51)`.

Some refusals of `parse` change their message, so code matching the old
text has to change. Where Bitcoin Core's miniscript parser fails on a
wrapper, a number, a hash, an unbalanced bracket or trailing text,
`parse` gives Core's fallback: `A function is needed within P2WSH` in
`wsh()`, and `tr() leaf is not a valid descriptor function` in a `tr()`
leaf. For `sha256(zz)`, v2026.10.31 said
`invalid sha256() hash: hex expected`. A `tr()` tree is read leaf by
leaf, so a fault inside a leaf gets that leaf's refusal, such as
`not a key expression`, where v2026.10.31 could say `unbalanced braces`.

Where one fragment spells a key twice with two explicit origins,
`Descriptor.provider` gives the later one, where v2026.10.31 put the
later origin in front of the earlier one. `expansion()` keeps the first.

## v2026.10.31

The first release of `bip32-descriptors`: BIP32 keys, output script
descriptors and miniscript, imported as `bip32_descriptors`. There is no
earlier version of it to upgrade from.

The code is btclib-wallet's `bip32` and `descriptors` packages as of
btclib-wallet b8b5c9b. Every module keeps its name and its `__all__`
under the new prefix: `btclib_wallet.bip32` and
`btclib_wallet.descriptors` become `bip32_descriptors.bip32` and
`bip32_descriptors.descriptors`.

btclib-wallet still ships both packages. btclib-org/btclib-wallet#634
tracks removing them there, with no alias of the old names, and making
btclib-wallet depend on this package. Code that imports them from
`btclib_wallet` then imports them from `bip32_descriptors`.

Code coming from btclib-wallet v2026.10.29 meets these differences too.

In `wsh()` and in a `tr()` leaf, `parse` cuts a key, timelock or hash
fragment as Bitcoin Core's `Expr` does, counting `{` as a bracket
(btclib-org/btclib-wallet#607). Where a `{` stands in or after such a
fragment, the `BTClibValueError` for a key fragment is the key's own
refusal, such as `not a key expression` or `invalid key expression`,
where v2026.10.29 said `unbalanced brackets in <fragment>()` or
`invalid key expression`. For `older()` and `after()` it is
`A function is needed within P2WSH` in `wsh()` and
`tr() leaf is not a valid descriptor function` in a `tr()` leaf, and for
a hash fragment `invalid <fragment>() hash: hex expected`, where each was
`unbalanced brackets in <fragment>()`.

`account_descriptors` is in btclib-wallet's `bip44`, and
`update_psbt_input`, `update_psbt_output`, `miniscript_sizer`,
`satisfaction_sizer` and `miniscript_solver` are in its `psbt`; none of
them is in this package (btclib-org/btclib-wallet#620). There,
`update_psbt_input` and `update_psbt_output` are functions that take the
descriptor first, not methods of a descriptor.

The release attaches the wheel,
`bip32_descriptors-2026.10.31-py3-none-any.whl`, the sdist,
`bip32_descriptors-2026.10.31.tar.gz`,
`bip32_descriptors-2026.10.31.cdx.json` and `v2026.10.31.intoto.jsonl`;
*Supported versions* in [SECURITY.md](./SECURITY.md) has the
`gh attestation verify` command.
