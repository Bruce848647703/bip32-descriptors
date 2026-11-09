# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The exact type of fragments where one term of BIP379's rules decides it.

Issue btclib-org/bip32-descriptors#41. Each expression here has other
properties where one operator of a composition rule in `miniscript.py`
is changed, or where thresh() counts or reads its stack arguments wrong.
The mutation profile `.github/mutation/descriptors.toml` names the
operators of those rules that no expression can tell apart.
"""

import pytest
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors.miniscript import parse

K = PrvKeyData(1).pub.sec.hex()
K2 = PrvKeyData(2).pub.sec.hex()


@pytest.mark.parametrize(
    "expression, properties",
    [
        # and_b's "f" term: 1 and a:1 are both "f"
        ("and_b(1,a:1)", "Bfkmux"),
        # or_c's "m" term keeps "m" alone of what both branches share
        (f"t:or_c(pk({K}),v:pk({K2}))", "Bfkmsux"),
        # or_d's "m" term: or_i(1,1) is not "m"
        ("or_d(0,or_i(1,1))", "Bkux"),
        # or_i is "o" where both branches are "z": 0 is, dv:0 is not
        ("or_i(0,dv:0)", "Bdkmsx"),
        # andor's "z", "u" and "d" terms: 0 is all three
        ("andor(0,0,0)", "Bdekmsuxz"),
        # andor's "o" term: X is "o", Y and Z are "z"
        ("andor(or_i(0,0),0,0)", "Bdkoux"),
        # andor's "m" term: Z, or_i(1,1), is not "m"
        ("andor(0,0,or_i(1,1))", "Bkux"),
        # thresh() counts an "o" subexpression as one stack argument
        ("thresh(1,or_i(0,0))", "Bdkou"),
    ],
)
def test_one_term_of_the_rules_decides_the_type(
    expression: str, properties: str
) -> None:
    """Assert the whole property set, so that a letter gained fails too."""
    assert parse(expression).properties == frozenset(properties)
