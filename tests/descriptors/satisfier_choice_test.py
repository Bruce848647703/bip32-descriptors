# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Which witness `Miniscript.satisfy` builds where it has a choice.

Issue btclib-org/bip32-descriptors#41. Each case here has another witness,
or none, where one operator of the satisfier in `miniscript.py` is
changed. The mutation profile `.github/mutation/descriptors.toml` names
the operators of the satisfier that no input can tell apart.

The signatures are placeholders of the lengths a signer hands back:
`satisfy` puts what it is given on the stack and checks none of it.
"""

from btclib.alias import Octets
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors.miniscript import parse

K = [PrvKeyData(i).pub.sec for i in range(1, 4)]
XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjq"
    "JoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)


def test_the_smaller_of_two_signed_witnesses() -> None:
    """Of two non-malleable witnesses with a signature, the fewer bytes win."""
    node = parse(f"or_i(pk({K[0].hex()}),pk({K[1].hex()}))")
    signatures: dict[Octets, Octets] = {K[0]: b"\xaa" * 72, K[1]: b"\xbb" * 71}
    assert node.satisfy(signatures) == [b"\xbb" * 71, b""]


OR_D = f"or_d(thresh(1,pk({K[0].hex()}),s:pk({K[1].hex()})),pk({K[2].hex()}))"


def test_a_witness_size_counts_each_length_prefix() -> None:
    """Each element costs its length prefix of one byte.

    Dissatisfying the thresh() and signing with the third key is three
    elements in 74 bytes; satisfying the thresh() with the first key is two
    elements in 75. A prefix of two bytes would make both 77, and the tie
    goes to the thresh().
    """
    signatures: dict[Octets, Octets] = {K[0]: b"\xaa" * 73, K[2]: b"\xcc" * 71}
    assert parse(OR_D).satisfy(signatures) == [b"\xcc" * 71, b"", b""]


def test_a_tie_between_witnesses_of_unequal_elements() -> None:
    """Two witnesses of 74 bytes, the one with fewer elements taken.

    Satisfying the thresh() with a 72-byte signature is two elements in 74
    bytes, as is the third key's 71-byte signature with the thresh()
    dissatisfied, three elements. The tie goes to the thresh(), the first
    branch of the or_d(). A prefix counted as zero bytes, or as minus one,
    would make the three elements the lighter witness.
    """
    signatures: dict[Octets, Octets] = {K[0]: b"\xaa" * 72, K[2]: b"\xcc" * 71}
    assert parse(OR_D).satisfy(signatures) == [b"", b"\xaa" * 72]


def test_satisfy_derives_a_ranged_key_at_index_zero() -> None:
    """The index `satisfy` derives at, where none is given, is 0."""
    node = parse(f"pk({XPUB}/*)")
    sec = node.subs[0].keys[0].sec(0)
    assert node.satisfy({sec: b"\xaa" * 71}) == [b"\xaa" * 71]
