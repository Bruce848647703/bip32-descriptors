# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A WIF goes back through `wifs`, and `private_string` writes it.

Issue btclib-org/bip32-descriptors#137. `parse` files each WIF under the
hex `str` writes for its public key, and `prv_keys` stays a mapping of
extended keys. Bitcoin Core's own private spellings are checked in
`tests/descriptors/preimage_test.py`.
"""

from __future__ import annotations

import pickle

import pytest
from btclib import b58
from btclib.exceptions import BTClibTypeError, BTClibValueError

from bip32_descriptors.descriptors import add_checksum, parse, private_string
from bip32_descriptors.descriptors.miniscript import TAPSCRIPT
from bip32_descriptors.descriptors.miniscript import parse as parse_miniscript
from tests.descriptors.descriptors_test import (
    KEY,
    MUSIG_A,
    MUSIG_A_WIF,
    MUSIG_B,
    UNCOMPRESSED,
    UNCOMPRESSED_WIF,
    WIF,
    XONLY,
)
from tests.secret_free import assert_secret_free

# the key of WIF, spelled for the test networks
_TESTNET_WIF = b58.wif_from_prv_key(b58.prv_key_data_from_wif(WIF).q, "testnet")

# the regtest WIFs of KEY, of its negation (the even key of XONLY), and of
# MUSIG_A, as the rows checked against Bitcoin Core write them
_W = "cVDJUtDjdaM25yNVVDLLX3hcHUfth4c7tY3rSc4hy9e8ibtCuj6G"
_NEG = "cNXjPRPAE4VqftyTR5jRpKcLvQHJJTjqSBERsQUFiDDj66UFdyDJ"
_MA = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87KcLPVfXz"
_EVEN = f"02{XONLY}"


@pytest.mark.parametrize(
    "text,filed",
    [
        (
            f"sh(multi(1,{WIF},{UNCOMPRESSED_WIF}))",
            {KEY: WIF, UNCOMPRESSED: UNCOMPRESSED_WIF},
        ),
        (f"tr({WIF})", {XONLY: WIF}),
        (f"tr({MUSIG_A[2:]},pk({WIF}))", {XONLY: WIF}),
        (f"tr(musig({MUSIG_A_WIF},{MUSIG_B}))", {MUSIG_A: MUSIG_A_WIF}),
        (f"wsh(and_v(v:pk({WIF}),older(1)))", {KEY: WIF}),
    ],
    ids=["sec", "tr", "tr-leaf", "musig", "miniscript"],
)
def test_parse_files_a_wif_under_the_hex_str_writes(
    text: str, filed: dict[str, str]
) -> None:
    """X-only where the position is, and 33 or 65 bytes elsewhere."""
    prv_keys: dict[str, str] = {}
    wifs: dict[str, str] = {}
    descriptor = parse(text, prv_keys=prv_keys, wifs=wifs)
    assert wifs == filed
    assert not prv_keys
    for hex_key in filed:
        assert hex_key in str(descriptor)
    assert private_string(descriptor, prv_keys, None, wifs) == text


def test_the_regtest_wifs_are_of_their_keys() -> None:
    """The literals the Core rows below are written with."""
    assert _W == _TESTNET_WIF
    for wif, key in ((_W, KEY), (_NEG, _EVEN), (_MA, MUSIG_A)):
        assert b58.prv_key_data_from_wif(wif, "regtest").pub.sec.hex() == key


@pytest.mark.parametrize(
    "text,filed",
    [
        (f"tr({_NEG},pk({_W}))", {XONLY: _NEG, KEY: _W}),
        (f"tr({_W},pk({_NEG}))", {XONLY: _NEG, KEY: _W}),
        (f"tr({_W},pk({_W}))", {XONLY: _W}),
    ],
    ids=["even-first", "even-last", "odd-only"],
)
def test_an_x_only_key_keeps_its_even_wif(text: str, filed: dict[str, str]) -> None:
    """The one Core's GetKeyByXOnly finds; the odd one under its 33 bytes."""
    wifs: dict[str, str] = {}
    parse(text, "regtest", wifs=wifs)
    assert wifs == filed


@pytest.mark.parametrize("even_first", [True, False])
def test_the_even_wif_is_kept_across_networks(*, even_first: bool) -> None:
    """The x-only hex keeps the even WIF in either order; none is written back.

    Each descriptor reads the other network's WIF under one of its key's
    spellings, and `private_string` refuses it.
    """
    even = b58.wif_from_prv_key(b58.prv_key_data_from_wif(_NEG).q, "mainnet")
    reads = [(f"tr({even})", "mainnet"), (f"tr({_W})", "regtest")]
    wifs: dict[str, str] = {}
    descriptors = [
        parse(text, network, wifs=wifs)
        for text, network in (reads if even_first else reversed(reads))
    ]
    assert wifs == {XONLY: even, KEY: _W}
    for descriptor in descriptors:
        network = descriptor.network
        with pytest.raises(
            BTClibValueError, match=f"^invalid wifs entry: no {network} WIF of its key$"
        ) as e:
            private_string(descriptor, None, None, wifs)
        assert_secret_free(e.value, [even, _W])


@pytest.mark.parametrize(
    "entry", [MUSIG_A_WIF, "not a key", b"not a key"], ids=["other", "no-wif", "bytes"]
)
def test_an_entry_of_another_key_does_not_hold_back_an_odd_wif(entry: str) -> None:
    """Only the even key of the same x coordinate does."""
    wifs = {XONLY: entry}
    parse(f"tr({_W})", "regtest", wifs=wifs)
    assert wifs == {XONLY: _W}


@pytest.mark.parametrize(
    "text,core",
    [
        (
            f"tr({MUSIG_A[2:]},pk(musig({_MA},{_W})))",
            f"tr({_MA},pk(musig({_MA},{_W})))#9a2ay92p",
        ),
        (
            f"tr({_MA},pk(musig({MUSIG_A},{_W})))",
            f"tr({_MA},pk(musig({_MA},{_W})))#9a2ay92p",
        ),
        (f"tr({_NEG},pk({_W}))", f"tr({_NEG},pk({_NEG}))#fgy3an9k"),
        (f"tr({_W},pk({_NEG}))", f"tr({_NEG},pk({_NEG}))#fgy3an9k"),
        (
            f"tr({_W},pk(musig({_NEG},{_MA})))",
            f"tr({_NEG},pk(musig({_NEG},{_MA})))#l35qh4k5",
        ),
        (
            f"tr({_W},pk(musig({_EVEN},{_MA})))",
            f"tr({_W},pk(musig({_EVEN},{_MA})))#2p93kays",
        ),
        (
            f"tr({_NEG},pk(musig({KEY},{_MA})))",
            f"tr({_NEG},pk(musig({KEY},{_MA})))#j5adhuam",
        ),
        (
            f"tr({_W},pk(musig({KEY},{_MA})))",
            f"tr({_W},pk(musig({_W},{_MA})))#atgc5s98",
        ),
        (
            f"tr({XONLY},pk(musig({_W},{_MA})))",
            f"tr({_W},pk(musig({_W},{_MA})))#atgc5s98",
        ),
        (
            f"tr({_W},{{pk({_NEG}),pk(musig({KEY},{_MA}))}})",
            f"tr({_NEG},{{pk({_NEG}),pk(musig({_W},{_MA}))}})#2kdpay3g",
        ),
        (
            f"tr({_NEG},{{pk({_W}),pk(musig({KEY},{_MA}))}})",
            f"tr({_NEG},{{pk({_NEG}),pk(musig({_W},{_MA}))}})#2kdpay3g",
        ),
        (
            f"tr({_W},{{pk({_NEG}),pk(musig({_EVEN},{_MA}))}})",
            f"tr({_NEG},{{pk({_NEG}),pk(musig({_NEG},{_MA}))}})#sc9zxw6n",
        ),
    ],
    ids=[
        "x-only-hex",
        "participant-hex",
        "even-and-odd",
        "odd-and-even",
        "even-participant",
        "even-participant-hex",
        "odd-participant-hex",
        "odd-participant-of-x-only",
        "x-only-of-odd-participant",
        "odd-yields-then-participant",
        "even-first-then-participant",
        "odd-yields-then-even-participant",
    ],
)
def test_a_wif_is_found_under_either_spelling_of_its_key(text: str, core: str) -> None:
    """Bitcoin Core v32.1.0's listdescriptors, with its private flag.

    Each row was imported on regtest and listed back. Core looks a key up
    by the key itself, and an x-only key as its even key, then its odd one.
    """
    wifs: dict[str, str] = {}
    descriptor = parse(text, "regtest", wifs=wifs)
    assert add_checksum(private_string(descriptor, None, None, wifs)) == core


def test_a_wif_of_another_key_under_the_other_spelling_is_skipped() -> None:
    """Filed for the even key, it is no WIF of the odd one: hex is written."""
    descriptor = parse(f"wpkh({KEY})", "regtest")
    assert private_string(descriptor, None, None, {XONLY: _NEG}) == f"wpkh({KEY})"
    assert private_string(descriptor, None, None, {XONLY: _W}) == f"wpkh({_W})"


def test_private_string_refuses_what_is_no_wif_under_the_other_spelling() -> None:
    """A malformed entry is refused wherever it is looked up, unquoted."""
    descriptor = parse(f"wpkh({KEY})", "regtest")
    with pytest.raises(BTClibValueError, match="no regtest WIF of its key") as e:
        private_string(descriptor, None, None, {XONLY: "not a key"})
    assert_secret_free(e.value, ["not a key"])
    descriptor = parse(f"tr({XONLY})", "regtest")
    with pytest.raises(BTClibValueError, match="whitespace around it"):
        private_string(descriptor, None, None, {_EVEN: f" {_NEG}"})


def test_the_parsed_descriptor_holds_no_wif() -> None:
    """Not in its text, its repr, or its pickle: the mapping holds it."""
    descriptor = parse(f"wsh(multi(1,{WIF},{MUSIG_A_WIF}))", wifs={})
    for written in (str(descriptor), repr(descriptor)):
        assert WIF not in written
        assert MUSIG_A_WIF not in written
    pickled = pickle.dumps(descriptor)
    assert WIF.encode() not in pickled
    assert MUSIG_A_WIF.encode() not in pickled


def test_miniscript_parse_files_a_wif_too() -> None:
    """`miniscript.parse` takes the mapping `descriptors.parse` takes."""
    wifs: dict[str, str] = {}
    parse_miniscript(f"and_v(v:pk({WIF}),older(1))", TAPSCRIPT, None, None, wifs)
    assert wifs == {XONLY: WIF}


def test_a_mapping_keeps_what_a_refused_parse_filed() -> None:
    """As `prv_keys` does: the WIF is filed before the refusal."""
    wifs: dict[str, str] = {}
    with pytest.raises(BTClibValueError, match="only be used in wsh or tr"):
        parse(f"and_v(v:pk({WIF}),older(1))", wifs=wifs)
    assert wifs == {XONLY: WIF}


def test_a_hex_key_the_mapping_names_is_written_as_its_wif() -> None:
    """Core's `ToPrivateString` writes any key its provider holds a WIF of."""
    wifs: dict[str, str] = {}
    parse(f"pkh({WIF})", wifs=wifs)
    descriptor = parse(f"wpkh({KEY})")
    assert private_string(descriptor, None, None, wifs) == f"wpkh({WIF})"


def test_a_test_network_wif_is_written_on_each_test_network() -> None:
    """The test networks share one WIF prefix."""
    text = f"pkh({_TESTNET_WIF})"
    for network in ("testnet", "regtest", "signet"):
        wifs: dict[str, str] = {}
        descriptor = parse(text, network, wifs=wifs)
        assert private_string(descriptor, None, None, wifs) == text


@pytest.mark.parametrize(
    "network,entry,message",
    [
        ("mainnet", MUSIG_A_WIF, "no mainnet WIF of its key"),
        ("mainnet", _TESTNET_WIF, "no mainnet WIF of its key"),
        ("testnet", WIF, "no testnet WIF of its key"),
        ("mainnet", UNCOMPRESSED_WIF, "no mainnet WIF of its key"),
        ("mainnet", "not a key", "no mainnet WIF of its key"),
        ("mainnet", f" {WIF}", "whitespace around it"),
        ("mainnet", f"{WIF}\n", "whitespace around it"),
    ],
    ids=[
        "other-key",
        "testnet",
        "mainnet",
        "uncompressed",
        "no-wif",
        "lead",
        "newline",
    ],
)
def test_private_string_refuses_an_entry_that_is_no_wif_of_its_key(
    network: str, entry: str, message: str
) -> None:
    """The text written would not be this descriptor's: refused, unquoted."""
    descriptor = parse(f"wpkh({KEY})", network)
    with pytest.raises(BTClibValueError, match=f"^invalid wifs entry: {message}$") as e:
        private_string(descriptor, None, None, {KEY: entry})
    assert_secret_free(e.value, [entry.strip(), WIF])


def test_private_string_refuses_an_x_only_key_s_other_wif() -> None:
    """An x-only key is matched by its x coordinate alone."""
    descriptor = parse(f"tr({XONLY})")
    with pytest.raises(BTClibValueError, match="no mainnet WIF of its key") as e:
        private_string(descriptor, None, None, {XONLY: MUSIG_A_WIF})
    assert_secret_free(e.value, [MUSIG_A_WIF])


def test_private_string_refuses_a_wif_that_is_no_string() -> None:
    """A bytes entry is a type error, naming the type and nothing else."""
    descriptor = parse(f"wpkh({KEY})")
    entry = WIF.encode()
    with pytest.raises(BTClibTypeError, match="^invalid wifs entry type: bytes$") as e:
        private_string(descriptor, None, None, {KEY: entry})  # type: ignore[dict-item]
    assert_secret_free(e.value, [entry, WIF])


def test_private_string_refuses_a_wifs_that_is_no_mapping() -> None:
    """`wifs` is a mapping or None, as `parse` asks for it."""
    descriptor = parse(f"wpkh({KEY})")
    with pytest.raises(BTClibTypeError, match="invalid wifs type"):
        private_string(descriptor, None, None, "x")  # type: ignore[arg-type]
    assert private_string(descriptor, None, None, None) == str(descriptor)
