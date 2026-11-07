# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Read a malformed multisig's keys before the structure that follows it.

Bitcoin Core's ``ParseScript`` (`src/script/descriptor.cpp`,
bitcoin/bitcoin@f0de87f040) falls through to miniscript when a multi()
or multi_a() expression does not end in a closing parenthesis. The key
reader can fail before that miniscript's trailing text is found.
"""

from collections.abc import Callable

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors import Descriptor, multipath_descriptors, parse
from tests.descriptors import P2SH_FAULT, P2WSH_FAULT, TOP_FAULT, TR_LEAF_FAULT

_KEY = PrvKeyData(1).pub.sec.hex()
_X_ONLY = _KEY[2:]


@pytest.mark.parametrize("read", [parse, multipath_descriptors])
@pytest.mark.parametrize(
    "descriptor",
    [
        f"wsh(multi(1,[dead]]{_KEY})junk))",
        f"sh(wsh(multi(1,[dead]]{_KEY})junk)))",
        f"tr({_X_ONLY},multi_a(1,[dead]]{_KEY})junk))",
        f"tr({_X_ONLY},{{multi_a(1,[dead]]{_KEY}))),pk({_X_ONLY})}})",
        f"wsh(multi(1,[dead]]{_KEY},{_KEY})",
        f"wsh(multi(-1,[dead]]{_KEY},{_KEY})",
        f"wsh(multi(9223372036854775807,[dead]]{_KEY},{_KEY})",
        f"wsh(multi(-9223372036854775808,[dead]]{_KEY},{_KEY})",
        f"sh(wsh(multi(1,[dead]]{_KEY},{_KEY}))",
        f"tr({_X_ONLY},multi_a(1,[dead]]{_KEY},{_X_ONLY})",
        f"wsh(multi(1,[dead]]{_KEY},{_KEY}}}))",
        f"tr({_X_ONLY},multi_a(1,[dead]]{_KEY},{_X_ONLY}}}))",
        f"wsh(and_v(v:pk({_KEY}),multi(1,[dead]]{_KEY},{_KEY})",
        f"tr({_X_ONLY},and_v(v:pk({_X_ONLY}),multi_a(1,[dead]]{_X_ONLY},{_X_ONLY})",
    ],
)
def test_a_multisig_key_is_read_before_its_trailing_structure(
    descriptor: str, read: Callable[[str], Descriptor | list[str]]
) -> None:
    """Core names the repeated origin end before it finds the structure."""
    with pytest.raises(
        BTClibValueError, match=r"^more than one '\]' in a single key expression$"
    ):
        read(descriptor)


@pytest.mark.parametrize(
    "descriptor,message",
    [
        (f"wsh(multi(x,[dead]]{_KEY},{_KEY})", P2WSH_FAULT),
        (f"wsh(multi(9223372036854775808,[dead]]{_KEY},{_KEY})", P2WSH_FAULT),
        (f"wsh(multi(-9223372036854775809,[dead]]{_KEY},{_KEY})", P2WSH_FAULT),
        pytest.param(
            f"wsh(multi({'9' * 5000},[dead]]{_KEY},{_KEY})",
            P2WSH_FAULT,
            id="threshold-of-5000-digits",
        ),
        (f"wsh(multi(1,,[dead]]{_KEY},{_KEY})", P2WSH_FAULT),
        (f"wsh(multi(1,{_KEY},{_KEY})", P2WSH_FAULT),
        (f"wsh(multi(1,{_KEY},[dead]]{_KEY})", P2WSH_FAULT),
        (f"wsh(multi(1,{_KEY}),{_KEY}))", "^trailing characters after the miniscript$"),
        (f"wsh(multi(1,){_KEY},{_KEY}))", P2WSH_FAULT),
        (
            f"wsh(and_v(v:pk({_KEY}),multi_a(1,[dead]{_KEY}){_KEY},{_KEY})))",
            P2WSH_FAULT,
        ),
        (
            (
                f"tr({_X_ONLY},and_v(v:pk({_X_ONLY}),"
                f"multi(1,[dead]{_X_ONLY}){_X_ONLY},{_X_ONLY})))"
            ),
            TR_LEAF_FAULT,
        ),
        (
            f"wsh(and_v(v:pk({_KEY}),multi_a(1,[dead]]{_KEY},{_KEY})",
            P2WSH_FAULT,
        ),
        (
            f"tr({_X_ONLY},and_v(v:pk({_X_ONLY}),multi(1,[dead]]{_X_ONLY},{_X_ONLY})",
            TR_LEAF_FAULT,
        ),
    ],
)
def test_a_multisig_structure_fault_is_not_a_key_fault(
    descriptor: str, message: str
) -> None:
    """Core refuses these as structure and names no key fault."""
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


def test_a_multisig_key_ends_at_a_comma_past_a_close() -> None:
    """Core: Invalid musig() expression.

    Core ends a key at the next comma, and at ")" only once no comma is
    left, so the first key read here is ``musig()``.
    """
    with pytest.raises(BTClibValueError, match=r"^musig\(\) takes at least one key$"):
        parse(f"tr({_X_ONLY},multi_a(1,musig(),)")


@pytest.mark.parametrize("read", [parse, multipath_descriptors])
@pytest.mark.parametrize(
    "descriptor",
    [
        f"wsh(multi(1,{_KEY})junk))",
        f"sh(wsh(multi(1,{_KEY})junk)))",
        f"tr({_X_ONLY},multi_a(1,{_KEY})junk))",
    ],
)
def test_a_valid_key_does_not_make_trailing_structure_valid(
    descriptor: str, read: Callable[[str], Descriptor | list[str]]
) -> None:
    """Reading the key cannot turn the trailing text into a descriptor."""
    with pytest.raises(BTClibValueError):
        read(descriptor)


@pytest.mark.parametrize(
    "descriptor,message",
    [
        (f"sh(multi(1,[dead]]{_KEY})junk))", P2SH_FAULT),
        (f"wsh(multi(1,[dead]]{_KEY}", TOP_FAULT),
        (f"tr({_X_ONLY},multi_a(1,[dead]]{_KEY}", TOP_FAULT),
    ],
)
def test_no_key_is_read_here(descriptor: str, message: str) -> None:
    """Core reads no key here.

    Inside sh() Core's miniscript is a tapscript one, which refuses multi()
    before its keys. An unclosed wsh() or tr() is no function, and Core's
    tapscript parser fails on its name.
    """
    with pytest.raises(BTClibValueError, match=message):
        parse(descriptor)


@pytest.mark.parametrize(
    "descriptor",
    [
        f"wsh(multi(1,{_KEY}))",
        f"sh(wsh(multi(1,{_KEY})))",
        f"tr({_X_ONLY},multi_a(1,{_KEY}))",
    ],
)
def test_a_closed_multisig_keeps_its_script(descriptor: str) -> None:
    """A well-formed expression still has its checksummed round trip."""
    parsed = parse(descriptor)
    assert parse(str(parsed)).script_pub_key() == parsed.script_pub_key()
