# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a descriptor call answers where the caller leaves an argument out.

Issue btclib-org/bip32-descriptors#41. Each case here has another answer
where one default of `descriptors.py` or `miniscript.py`, or the refusal
beside one, is changed.
"""

import re

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors import SpendContext, parse
from bip32_descriptors.descriptors.descriptors import wallet_policy_descriptor
from bip32_descriptors.descriptors.miniscript import parse as parse_miniscript

XPUB = (
    "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkr"
    "gZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
)
KEY_INFO = (parse(f"pk({XPUB})").key_expressions[0],)


def test_expand_defaults_to_index_zero() -> None:
    """A ranged descriptor expands at index 0 where no index is given."""
    descriptor = parse(f"wpkh({XPUB}/0/*)")
    assert descriptor.expand() == descriptor.expand(0)
    assert descriptor.expand(0) != descriptor.expand(1)


def test_a_wallet_policy_defaults_to_the_receive_branch() -> None:
    """`/**` resolves to `/0/*` where no `multipath_index` is given."""
    expected = parse(f"pkh({XPUB}/0/*)")
    assert wallet_policy_descriptor("pkh(@0/**)", KEY_INFO) == expected
    assert wallet_policy_descriptor("pkh(@0/**)", KEY_INFO, 1) != expected


def test_a_placeholder_out_of_range_is_named_with_its_suffix() -> None:
    """The refusal quotes the placeholder as the template writes it."""
    message = "key placeholder out of range: @1/**"
    with pytest.raises(BTClibValueError, match=f"^{re.escape(message)}$"):
        wallet_policy_descriptor("pkh(@1/**)", KEY_INFO)


def test_a_spend_defaults_to_sequence_zero() -> None:
    """With no context, the input's sequence is 0, which meets older(65536).

    BIP68 reads the low 16 bits of both, and those of 65536 are 0. A
    sequence of -1 sets the disable bit, and would meet no ``older()``.
    """
    key = PrvKeyData(1).pub.sec
    node = parse_miniscript(f"and_v(v:pk({key.hex()}),older(65536))")
    signature = b"\xaa" * 72
    assert SpendContext().sequence == 0
    assert node.satisfy({key: signature}) == [signature]
