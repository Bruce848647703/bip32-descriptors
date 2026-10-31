# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

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
