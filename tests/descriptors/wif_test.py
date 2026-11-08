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

from bip32_descriptors.descriptors import parse, private_string
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
