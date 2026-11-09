# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The helpers `infer_descriptor` reads a script with, on unusual shapes.

Issue btclib-org/bip32-descriptors#41. Each case here is one where a
helper answers otherwise when one of its operators is changed. The
mutation profile `.github/mutation/descriptors.toml` names the operators
of these helpers that no input can tell apart.
"""

import pytest
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors import Provider
from bip32_descriptors.descriptors.descriptors import (
    _inferred_leaf,
    _Known,
    _multi_a,
    _multisig,
    _ops,
    _solved,
)

# the generator's x coordinate, and both its coordinates: the body of
# its uncompressed SEC key, without the prefix byte
X = PrvKeyData(1).pub.sec[1:]
XY = X + bytes.fromhex(
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)


@pytest.mark.parametrize(
    "script, stop",
    [
        # OP_PUSHDATA1, OP_PUSHDATA2 and OP_PUSHDATA4, each pushing one
        # byte: the length that follows the op code is one, two and four
        # bytes long
        ("4c01aa", 3),
        ("4d0100aa", 4),
        ("4e01000000aa", 6),
    ],
)
def test_a_pushdata_op_code_carries_its_data(script: str, stop: int) -> None:
    """`_ops` skips the length bytes, whose width the op code gives."""
    assert _ops(bytes.fromhex(script)) == [(int(script[:2], 16), b"\xaa", stop)]


def test_a_key_size_comes_from_the_first_byte() -> None:
    """`_solved` sizes a key as Core's `CPubKey::GetLen` does.

    A 65-byte key with the hybrid prefix 07 is a pay-to-pubkey; a 33-byte
    push whose first byte is 04 is no key, a 04 key being 65 bytes.
    """
    hybrid = b"\x07" + XY
    assert _solved(b"\x41" + hybrid + b"\xac") == ("pubkey", [hybrid])
    assert _solved(b"\x21\x04" + X + b"\xac") == ("nonstandard", [])


def test_a_bare_multisig_holds_keys_of_their_own_size() -> None:
    """`_multisig` refuses a push shorter than its first byte says.

    The two bytes 0200 start like a compressed key, which is 33 bytes.
    """
    assert _multisig(bytes.fromhex("51020200" + "51ae")) is None


def test_a_multi_a_threshold_may_be_a_push() -> None:
    """A threshold over 16 is pushed as data, there being no OP_17."""
    keys = b"\x20" + X + b"\xac" + (b"\x20" + X + b"\xba") * 16
    assert _multi_a(keys + bytes.fromhex("0111" + "9c")) == (17, [X] * 17)


def test_an_x_only_key_has_no_uncompressed_twin() -> None:
    """`_Known` files an x-only hash for compressed keys alone."""
    known = _Known.of(Provider({b"\x04" + XY: None}, (), {}))
    assert known.by_x_only_hash == {}


@pytest.mark.parametrize("script", [b"", b"\x20"])
def test_a_leaf_shorter_than_a_key_is_no_pk(script: bytes) -> None:
    """`_inferred_leaf` reads a ``pk()`` leaf only where it is 34 bytes."""
    assert _inferred_leaf(script, _Known.of(Provider({}, (), {}))) is None
