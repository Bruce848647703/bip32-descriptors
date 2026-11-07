# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Each path of a multipath key is written in the symbol Core keeps for the key.

Bitcoin Core reads a key into one ``m_apostrophe``, as `_parse_key` says,
and writes every path of its ``<a;b>`` step with it: ``ParseKeyPath`` at
bitcoin/bitcoin@f0de87f040 (the v32.1 tag), `src/script/descriptor.cpp`,
reads the items of the step in order. `CORE` holds what `getdescriptorinfo`
of that tag answers in ``multipath_expansion``. `MIXES` is every mix of the
two symbols across the origin, the items of the step, the steps beside it
and the wildcard, and `tests/integration/multipath_hardening_test.py` asks
the node for each.
"""

from __future__ import annotations

import itertools

import pytest

from bip32_descriptors.descriptors import add_checksum, multipath_descriptors, parse
from tests import vector_id

# the master key of BIP32's first test vector
XPRV = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6L"
    "nF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)
XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje"
    "8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)

# the origin, the step before the multipath one, the symbols of its two
# items, the step after it, and the wildcard
MIXES = list(
    itertools.product(
        ("", "[d34db33f/0h]", "[d34db33f/0']"),
        ("", "/2", "/2h", "/2'"),
        ("", "h", "'"),
        ("", "h", "'"),
        ("", "/3", "/3h", "/3'"),
        ("", "/*", "/*h", "/*'"),
    )
)


def mixed(key: str, mix: tuple[str, ...]) -> str:
    """Return the ``wpkh()`` of `key` with the parts of `mix`."""
    origin, before, first, second, after, wildcard = mix
    return f"wpkh({origin}{key}{before}/<0{first};1{second}>{after}{wildcard})"


def _expected(mix: tuple[str, ...]) -> list[str]:
    """Return Core's expansion of a mix, read from its parser's order.

    ``ParsePubkey`` reads the origin, then ``ParseDeriveType`` the
    wildcard, then ``ParseKeyPath`` the path left to right; each hardened
    step sets the symbol, and ``h`` is the default.
    """
    origin, before, first, second, after, wildcard = mix
    read = (origin, wildcard, before, first, second, after)
    symbols = [c for part in read for c in part if c in "h'"]
    symbol = symbols[-1] if symbols else "h"

    def written(part: str) -> str:
        return part.replace("'", symbol).replace("h", symbol)

    head = written(origin) + XPUB + written(before)
    tail = written(after) + written(wildcard)
    return [
        add_checksum(f"wpkh({head}/{index}{written(item)}{tail})")
        for index, item in enumerate((first, second))
    ]


def _expansion(descriptor: str) -> list[str]:
    """Return the checksummed `str` of each path `parse` reads."""
    return [add_checksum(str(parse(x))) for x in multipath_descriptors(descriptor)]


@pytest.mark.parametrize(
    "mix",
    [pytest.param(mix, id=vector_id(i, *mix)) for i, mix in enumerate(MIXES)],
)
def test_each_path_is_written_in_the_symbol_of_the_key(mix: tuple[str, ...]) -> None:
    """The symbol is the one the whole key chooses, not one path."""
    assert _expansion(mixed(XPRV, mix)) == _expected(mix)


# getdescriptorinfo's multipath_expansion, the first two the issue's lines
CORE = [
    (
        f"wpkh({XPRV}/<0h;1>/*')",
        [f"wpkh({XPUB}/0h/*h)#mxlmedup", f"wpkh({XPUB}/1/*h)#6s6evavu"],
    ),
    (
        f"wpkh({XPRV}/<0';1h>)",
        [f"wpkh({XPUB}/0h)#t7xv37qc", f"wpkh({XPUB}/1h)#3lp8maq8"],
    ),
    (
        f"wsh(multi(1,[d34db33f/0']{XPRV}/<0h;1>/*,{XPRV}/7'/<0;1h>/*'))",
        [
            f"wsh(multi(1,[d34db33f/0h]{XPUB}/0h/*,{XPUB}/7h/0/*h))#q0exa84v",
            f"wsh(multi(1,[d34db33f/0h]{XPUB}/1/*,{XPUB}/7h/1h/*h))#zat0w4fx",
        ],
    ),
    (
        f"tr(musig({XPRV}/<0h;1>/*',{XPRV}/9/<2;3>/*))",
        [
            f"tr(musig({XPUB}/0h/*h,{XPUB}/9/2/*))#xduvh05k",
            f"tr(musig({XPUB}/1/*h,{XPUB}/9/3/*))#40d90xs0",
        ],
    ),
    (
        f"tr({XPRV}/8h/<0;1>,{{pk({XPRV}/<0';1h>/*),pk([d34db33f/5h]{XPRV}/<4;5>/*')}})",
        [
            f"tr({XPUB}/8h/0,{{pk({XPUB}/0h/*),pk([d34db33f/5']{XPUB}/4/*')}})#ldjcgxqh",
            f"tr({XPUB}/8h/1,{{pk({XPUB}/1h/*),pk([d34db33f/5']{XPUB}/5/*')}})#tkgc066z",
        ],
    ),
    (
        f"sh(wsh(pk([d34db33f/1h/2']{XPRV}/<0;1'>)))",
        [
            f"sh(wsh(pk([d34db33f/1'/2']{XPUB}/0)))#l8384n0k",
            f"sh(wsh(pk([d34db33f/1'/2']{XPUB}/1')))#z56zyugp",
        ],
    ),
]


@pytest.mark.parametrize(
    "descriptor, core",
    [pytest.param(*case, id=vector_id(i, case[1][0])) for i, case in enumerate(CORE)],
)
def test_the_expansion_is_cores(descriptor: str, core: list[str]) -> None:
    """Each key of the descriptor, a ``musig()`` participant included."""
    assert _expansion(descriptor) == core


def test_only_the_symbols_of_a_key_with_a_step_are_rewritten() -> None:
    """The private key and the key without a step are left as written."""
    descriptor = f"wsh(multi(1,{XPRV}/<0h;1>/*',[d34db33f/1']{XPRV}/2h))"
    assert multipath_descriptors(descriptor) == [
        add_checksum(f"wsh(multi(1,{XPRV}/0h/*h,[d34db33f/1']{XPRV}/2h))"),
        add_checksum(f"wsh(multi(1,{XPRV}/1/*h,[d34db33f/1']{XPRV}/2h))"),
    ]
