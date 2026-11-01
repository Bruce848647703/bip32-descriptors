# Architecture

The package is two subpackages, layered bottom-up, on top of
[btclib](https://github.com/btclib-org/btclib) and
[ecc](https://github.com/btclib-org/ecc).

`bip32` is the base and imports nothing else of the package. Within it,
`der_path` is the derivation path codec; `bip32` holds the extended key,
its serialization and its derivation, and `key_origin` the fingerprint
and path of a key's origin, each importing `der_path`.

`descriptors` builds on `bip32`. `key_expression` is BIP380's key
expression: a key, its origin and its derivation steps. `miniscript` is
BIP379's language over those keys, and imports `key_expression`.
`descriptors` is BIP380's script expressions and BIP388's wallet
policies, and imports both. A descriptor expanded at an index answers
with what it knows -- scripts, keys, key origins, the taproot tree --
and writes nothing into a transaction or a psbt: that is btclib-wallet's
psbt updater.

`__init__` imports no module of the package: it loads one when it is
first asked for.

`tests/imports_test.py` holds this rule. Its `_ALLOWED_UNITS` table is the
list of what each subpackage may import of the other, read against the
import statements of every file in `src/bip32_descriptors/`.
