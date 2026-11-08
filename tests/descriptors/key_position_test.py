# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Which key or which text a refusal of `parse` names.

Issue btclib-org/bip32-descriptors#18. Core is the release
`integration-bitcoind.yml` pins. Its ``ParsePubkey`` numbers each key
expression it reads, ``key_exp_index``: from 0, in the order it reads them,
a ``musig()`` after its participants (`src/script/descriptor.cpp`). Core
quotes the key it refuses, and `parse` names that number instead. Where an
expression is no descriptor function, Core quotes it, and `parse` quotes
it with what its brackets enclose written "...". What Core names for each
descriptor here is what getdescriptorinfo answered on an offline node.
"""

import pytest
from btclib.b58 import wif_from_prv_key
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData
from btclib.network import NETWORKS
from ecc.exceptions import EccValueError

from bip32_descriptors.bip32 import rootxprv_from_seed, xpub_from_xprv
from bip32_descriptors.descriptors import (
    multipath_descriptors,
    parse,
    wallet_policy_descriptor,
)
from tests.secret_free import assert_secret_free

K = PrvKeyData(1).pub.sec.hex()
K2 = PrvKeyData(2).pub.sec.hex()
X, X2 = K[2:], K2[2:]
XPUB = xpub_from_xprv(rootxprv_from_seed("1f2e3d4c" * 8))
# private keys of the test networks, from fixed random values
PRV_KEY = 0x1F2E3D4C5B6A79881F2E3D4C5B6A79881F2E3D4C5B6A79881F2E3D4C5B6A7988
WIF = wif_from_prv_key(PRV_KEY, "testnet")
TPRV = rootxprv_from_seed("4c3d2e1f" * 8, NETWORKS["testnet"].bip32_prv)


@pytest.mark.parametrize(
    "descriptor,message",
    [
        # the issue's own cases. Core: "Multi: key 'zz' is not valid", or
        # with the prefix of the function the key is in
        (f"wsh(multi(1,{K},zz))", "key 1: invalid key expression"),
        (f"sh(sortedmulti(2,{K},{K2},zz))", "key 2: invalid key expression"),
        (f"tr({X},{{pk({X2}),pk(zz)}})", "key 2: invalid key expression"),
        (f"wsh(and_v(v:pk({K}),pk(zz)))", "key 1: invalid key expression"),
        # a participant is the key, and the musig() is counted after it
        (f"tr({X},pk(musig({K},zz)))", "key 2: musig(): invalid key expression"),
        (
            f"tr({X},pk(musig({K},{K2})/0h))",
            "key 3: musig() derivation requires every participant to be extended",
        ),
        (f"tr(musig({K},{K2}),pk(zz))", "key 3: invalid key expression"),
        # sh() reads the expression before the "," and then the whole
        # argument, which it counts from the start again
        (f"sh(pk({K}),pk(zz))", "key 0: not a key expression"),
    ],
)
def test_a_key_is_named_by_its_position(descriptor: str, message: str) -> None:
    """Name the key refused by its position, as Core's ``key_exp_index``."""
    with pytest.raises(BTClibValueError) as e:
        parse(descriptor)
    assert str(e.value) == message


def test_a_key_read_again_on_its_first_path_is_counted_once() -> None:
    """A musig() with a step is read again on its first path."""
    with pytest.raises(BTClibValueError) as e:
        multipath_descriptors(f"tr(musig({XPUB}/<0;1>,{XPUB}),pk(zz))")
    assert str(e.value) == "key 3: invalid key expression"


def test_a_point_off_the_curve_keeps_its_class() -> None:
    """Core: "wpkh(): Pubkey '<key>' is invalid"."""
    with pytest.raises(EccValueError) as e:
        parse(f"wpkh(02{'ff' * 32})")
    assert str(e.value) == "key 0: not a public key"


@pytest.mark.parametrize(
    "descriptor,message",
    [
        (f"wsh(multi(1,{K},{WIF}))", "key 1: not a mainnet key: WIF prefix"),
        (f"wsh(multi(1,{K},{WIF[:-1]}x))", "key 1: invalid key expression"),
        (f"wsh(multi(1,{K},{TPRV}/0h/x))", "key 1: invalid derivation index"),
        (
            f"tr({X},pk(musig({K},{TPRV})))",
            "key 2: not a mainnet key: version 0x043587cf",
        ),
    ],
)
def test_a_private_key_is_named_and_not_quoted(descriptor: str, message: str) -> None:
    """The message for a private key carries no byte of it."""
    with pytest.raises(BTClibValueError) as e:
        parse(descriptor)
    assert str(e.value) == message
    assert_secret_free(e.value, [WIF, TPRV, f"{PRV_KEY:064x}"])


@pytest.mark.parametrize(
    "descriptor,message",
    [
        # where Core quotes the key too, as in 'wpkh(<key>)x'
        (f"wpkh({K})x", "'wpkh(...)x' is not a valid descriptor function"),
        (f"wpkx({K})", "'wpkx(...)' is not a valid descriptor function"),
        ("foo", "'foo' is not a valid descriptor function"),
        ("", "'' is not a valid descriptor function"),
        (f"tr({X},pk({X2})x)", "'pk(...)x' is not a valid descriptor function"),
        (f"tr({X},wpkx({X2}))", "'wpkx(...)' is not a valid descriptor function"),
        # longer than a name may be quoted
        (
            "seventeen_letters(1)",
            "top-level expression is not a valid descriptor function",
        ),
        (f"wpkh({K}){WIF}", "top-level expression is not a valid descriptor function"),
        (WIF, "top-level expression is not a valid descriptor function"),
        (f"tr({X},pk({X2}){WIF})", "tr() leaf is not a valid descriptor function"),
    ],
)
def test_an_expression_no_function_takes_is_quoted_short(
    descriptor: str, message: str
) -> None:
    """Quote the name and the text after it, what the brackets hold left out."""
    with pytest.raises(BTClibValueError) as e:
        parse(descriptor)
    assert str(e.value) == message
    assert_secret_free(e.value, [WIF])


def test_a_wallet_policy_key_is_named_by_its_place_and_not_its_number() -> None:
    """``@1`` comes first in the descriptor built, so it is key 0."""
    tpub = xpub_from_xprv(TPRV)
    key_info = [
        parse(f"pkh({XPUB})").key_expressions[0],
        parse(f"pkh({tpub})", "testnet").key_expressions[0],
    ]
    with pytest.raises(BTClibValueError) as e:
        wallet_policy_descriptor("wsh(multi(1,@1/**,@0/**))", key_info)
    assert str(e.value) == "key 0: not a mainnet key: version 0x043587cf"
    assert_secret_free(e.value, [TPRV])
