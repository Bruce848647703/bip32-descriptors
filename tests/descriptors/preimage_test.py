# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A hash fragment's private form, ``preimage(HEX)``, and `private_string`.

Issue btclib-org/bip32-descriptors#11. The syntax is the one the
`miniscript` module docstring names, and no BIP specifies it.
`tests/_data/preimage_descriptors.json` holds the vectors, and
`tests/_data/README.md` says where they come from.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any, cast

import pytest
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData

from bip32_descriptors.bip32.bip32 import rootxprv_from_seed, xpub_from_xprv
from bip32_descriptors.descriptors import (
    KeyExpression,
    WshDescriptor,
    add_checksum,
    at_index,
    parse,
    private_string,
)
from bip32_descriptors.descriptors.miniscript import P2WSH, TAPSCRIPT
from bip32_descriptors.descriptors.miniscript import parse as parse_miniscript
from tests import load, vector_id
from tests.descriptors.descriptors_test import CORE_VECTORS
from tests.secret_free import assert_secret_free

VECTORS: list[dict[str, Any]] = load("_data", "preimage_descriptors.json")
_IDS = [vector_id(i, v["fragment"], v["ranged"]) for i, v in enumerate(VECTORS)]

_FRAGMENTS = ("sha256", "hash256", "ripemd160", "hash160")
_PREIMAGE = "22" * 32
_KEY = PrvKeyData(1).pub.sec.hex()
# the WIF of Bitcoin Core's descriptor_tests
_WIF = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"
_XPRV = rootxprv_from_seed(b"\x01" * 32)
_XPUB = xpub_from_xprv(_XPRV)


@pytest.mark.parametrize("vector", VECTORS, ids=_IDS)
def test_the_private_form_is_the_public_descriptor(vector: dict[str, Any]) -> None:
    """Parsed, the two spellings are one descriptor, with one script."""
    preimages: dict[bytes, bytes] = {}
    private = parse(vector["private"], preimages=preimages)
    assert private == parse(vector["public"])
    assert preimages == {
        bytes.fromhex(vector["digest"]): bytes.fromhex(vector["preimage"])
    }
    count = len(vector["script_pub_keys"])
    scripts = [private.script_pub_key(i).script.hex() for i in range(count)]
    assert scripts == vector["script_pub_keys"]


@pytest.mark.parametrize("vector", VECTORS, ids=_IDS)
def test_str_writes_the_digest_and_never_the_preimage(vector: dict[str, Any]) -> None:
    """`str` is public: the node holds the digest alone."""
    text = str(parse(vector["private"], preimages={}))
    assert add_checksum(text) == vector["public"]
    assert vector["preimage"] not in text


@pytest.mark.parametrize("vector", VECTORS, ids=_IDS)
def test_the_private_string_round_trips(vector: dict[str, Any]) -> None:
    """Parsed and printed back with its mappings, the text is the same."""
    prv_keys: dict[str, str] = {}
    preimages: dict[bytes, bytes] = {}
    descriptor = parse(vector["private"], prv_keys=prv_keys, preimages=preimages)
    text = private_string(descriptor, prv_keys, preimages)
    assert add_checksum(text) == vector["private"]


@pytest.mark.parametrize("fragment", _FRAGMENTS)
def test_every_fragment_compiles_its_digest_form_script(fragment: str) -> None:
    """``OP_SIZE 32 OP_EQUALVERIFY``, then the script of the digest form."""
    preimages: dict[bytes, bytes] = {}
    node = parse_miniscript(f"{fragment}(preimage({_PREIMAGE}))", P2WSH, {}, preimages)
    (digest,) = preimages
    assert node.data == digest
    assert node.script().startswith(bytes.fromhex("82012088"))
    assert node == parse_miniscript(f"{fragment}({digest.hex()})")


@pytest.mark.parametrize(
    "vector", [v for v in VECTORS if v["ranged"]], ids=lambda v: v["fragment"]
)
def test_a_ranged_descriptor_repeats_the_digest_at_every_index(
    vector: dict[str, Any],
) -> None:
    """The key derives at each index; the digest is the same at all of them."""
    preimages: dict[bytes, bytes] = {}
    descriptor = parse(vector["private"], preimages=preimages)
    digest = bytes.fromhex(vector["digest"])
    inner = cast("WshDescriptor", descriptor).inner
    scripts = {inner.redeem_script(index) for index in (0, 1, 7, 2**31 - 1)}
    assert len(scripts) == 4
    assert all(digest in script for script in scripts)
    for index in (0, 1, 7):
        fixed = at_index(descriptor, index)
        assert vector["digest"] in str(fixed)
        assert f"preimage({vector['preimage']})" in private_string(
            fixed, None, preimages
        )


@pytest.mark.parametrize(
    "descriptor",
    [
        f"tr({_KEY[2:]},and_v(v:pk({_KEY[2:]}),sha256(preimage({_PREIMAGE}))))",
        f"sh(wsh(and_v(v:pk({_KEY}),ripemd160(preimage({_PREIMAGE})))))",
        f"wsh(or_d(pk({_XPRV}/0/*),and_v(v:pk({_KEY}),hash160(preimage({_PREIMAGE})))))",
    ],
)
def test_a_tr_leaf_and_a_nested_wsh_file_their_preimage(descriptor: str) -> None:
    """A ``tr()`` leaf and a ``wsh()``, nested in ``sh()`` or not, fill it."""
    prv_keys: dict[str, str] = {}
    preimages: dict[bytes, bytes] = {}
    parsed = parse(descriptor, prv_keys=prv_keys, preimages=preimages)
    assert list(preimages.values()) == [bytes.fromhex(_PREIMAGE)]
    assert _PREIMAGE not in str(parsed)
    assert private_string(parsed, prv_keys, preimages) == descriptor


@pytest.mark.parametrize(
    "argument,message",
    [
        (f"preimage({_PREIMAGE[:-2]} {_PREIMAGE[-2:]})", "hex expected"),
        (f"preimage({_PREIMAGE[:-1]})", "hex expected"),
        (f"preimage({_PREIMAGE[:-2]}zz)", "hex expected"),
        ("preimage()", "hex expected"),
        (f"preimage({_PREIMAGE[:-2]})", "32 bytes expected"),
        (f"preimage({_PREIMAGE}22)", "32 bytes expected"),
    ],
)
@pytest.mark.parametrize("fragment", _FRAGMENTS)
def test_a_malformed_preimage_is_refused_quoting_none_of_it(
    fragment: str, argument: str, message: str
) -> None:
    """Hex in whole bytes, no whitespace, and 32 of them; no echo."""
    descriptor = f"wsh(and_v(v:pk({_WIF}),{fragment}({argument})))"
    preimages: dict[bytes, bytes] = {}
    with pytest.raises(
        BTClibValueError, match=rf"^invalid {fragment}\(\) preimage: "
    ) as e:
        parse(descriptor, preimages=preimages)
    assert message in str(e.value)
    assert not preimages
    secret = argument[len("preimage(") : -1]
    assert_secret_free(e.value, [s for s in (secret, _WIF) if len(s) >= 12])


def test_a_preimage_of_another_digest_is_written_as_the_digest() -> None:
    """An entry that does not hash to the digest is no preimage of it."""
    preimages: dict[bytes, bytes] = {}
    descriptor = parse(
        f"wsh(and_v(v:pk({_KEY}),sha256(preimage({_PREIMAGE}))))", preimages=preimages
    )
    (digest,) = preimages
    wrong = bytes.fromhex("33" * 32)
    assert private_string(descriptor, None, {digest: wrong}) == str(descriptor)


@pytest.mark.parametrize(
    "first,second,function",
    [
        ("sha256", "hash256", lambda b: hashlib.sha256(b).digest()),
        (
            "hash160",
            "ripemd160",
            lambda b: hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest(),
        ),
    ],
    ids=["sha256-hash256", "hash160-ripemd160"],
)
def test_a_digest_another_fragment_filed_is_written_as_the_digest(
    first: str, second: str, function: Callable[[bytes], bytes]
) -> None:
    """One mapping keyed by digest serves fragments of different hashes.

    The second fragment holds the digest the first one's preimage hashes
    to, so the mapping names that digest with a preimage that is no
    preimage of the second: the second is written with its digest.
    """
    digest = function(bytes.fromhex(_PREIMAGE)).hex()
    text = (
        f"wsh(and_v(v:pk({_KEY}),and_v(v:{first}(preimage({_PREIMAGE})),"
        f"{second}({digest}))))"
    )
    prv_keys: dict[str, str] = {}
    preimages: dict[bytes, bytes] = {}
    descriptor = parse(text, prv_keys=prv_keys, preimages=preimages)
    assert list(preimages) == [bytes.fromhex(digest)]
    assert private_string(descriptor, prv_keys, preimages) == text


def test_private_string_refuses_a_malformed_preimage() -> None:
    """An entry that is no 32 bytes is refused, quoting none of it."""
    preimages: dict[bytes, bytes] = {}
    descriptor = parse(
        f"wsh(and_v(v:pk({_KEY}),sha256(preimage({_PREIMAGE}))))", preimages=preimages
    )
    (digest,) = preimages
    short = bytes.fromhex(_PREIMAGE)[1:]
    with pytest.raises(BTClibValueError, match="32 bytes expected") as e:
        private_string(descriptor, None, {digest: short})
    assert_secret_free(e.value, [short])
    with pytest.raises(BTClibTypeError, match="preimage") as type_error:
        private_string(descriptor, None, {digest: _PREIMAGE})  # type: ignore[dict-item]
    assert_secret_free(type_error.value, [_PREIMAGE])


def test_private_string_refuses_an_xprv_of_another_key() -> None:
    """A `prv_keys` entry that is no xprv of its xpub is refused, unquoted."""
    descriptor = parse(f"wpkh({_XPUB}/0/*)")
    other = rootxprv_from_seed(b"\x02" * 32)
    for entry in (other, "not a key", f"{_XPRV[:40]} {_XPRV[40:]}"):
        with pytest.raises(BTClibValueError, match="^invalid prv_keys entry") as e:
            private_string(descriptor, {_XPUB: entry})
        assert_secret_free(e.value, [entry, other, _XPRV])


@pytest.mark.parametrize(
    "entry", [f" {_XPRV}", f"{_XPRV} ", f"{_XPRV}\n"], ids=["lead", "trail", "newline"]
)
def test_private_string_refuses_an_xprv_padded_with_whitespace(entry: str) -> None:
    """The padded xprv is read by btclib as the key, and `parse` refuses it."""
    descriptor = parse(f"wpkh({_XPUB}/0/*)")
    with pytest.raises(BTClibValueError, match="^invalid prv_keys entry") as e:
        private_string(descriptor, {_XPUB: entry})
    assert_secret_free(e.value, [_XPRV])


def test_private_string_refuses_an_xprv_that_is_no_string() -> None:
    """A bytes entry is a type error, naming the type and nothing else."""
    descriptor = parse(f"wpkh({_XPUB}/0/*)")
    entry = _XPRV.encode()
    with pytest.raises(BTClibTypeError, match="^invalid prv_keys entry type") as e:
        private_string(descriptor, {_XPUB: entry})  # type: ignore[dict-item]
    assert_secret_free(e.value, [entry, _XPRV])


def test_a_mapping_keeps_what_a_refused_parse_filed() -> None:
    """As `prv_keys` does: the entries are filed before the refusal."""
    prv_keys: dict[str, str] = {}
    preimages: dict[bytes, bytes] = {}
    text = f"and_v(v:pk({_XPRV}),sha256(preimage({_PREIMAGE})))"
    with pytest.raises(BTClibValueError, match="only be used in wsh or tr"):
        parse(text, prv_keys=prv_keys, preimages=preimages)
    assert list(prv_keys.values()) == [_XPRV]
    assert list(preimages.values()) == [bytes.fromhex(_PREIMAGE)]


def test_private_string_writes_back_what_the_mappings_name_only() -> None:
    """A key or a digest neither mapping names is written as `str` writes it."""
    descriptor = parse(f"wsh(and_v(v:pk({_XPUB}/0/*),sha256({'44' * 32})))")
    assert private_string(descriptor) == str(descriptor)
    assert private_string(descriptor, {}, {}) == str(descriptor)


def test_a_wif_is_written_as_its_public_key() -> None:
    """`parse` files no WIF in `prv_keys`, so there is none to write back."""
    prv_keys: dict[str, str] = {}
    descriptor = parse(f"wpkh({_WIF})", prv_keys=prv_keys)
    assert not prv_keys
    assert private_string(descriptor, prv_keys) == str(descriptor)


def _has_wif(key: KeyExpression) -> bool:
    return bool(key.wif_prefix) or any(map(_has_wif, key.participants))


def _core_case(private: str) -> Any:
    keys = parse(private).key_expressions
    if any(map(_has_wif, keys)):
        return pytest.param(
            private,
            marks=pytest.mark.xfail(
                reason="no WIF in prv_keys: btclib-org/bip32-descriptors#137",
                strict=True,
            ),
        )
    return private


@pytest.mark.parametrize(
    "private",
    [_core_case(private) for private, _, _ in CORE_VECTORS],
    ids=[vector_id(i, private) for i, (private, _, _) in enumerate(CORE_VECTORS)],
)
def test_core_s_private_spelling_is_written_back(private: str) -> None:
    """Bitcoin Core's descriptor_test checks `ToPrivateString` the same way."""
    prv_keys: dict[str, str] = {}
    descriptor = parse(private, prv_keys=prv_keys)
    assert private_string(descriptor, prv_keys) == private


def test_private_string_refuses_a_wrong_type() -> None:
    """`preimages` is a mapping or None, and the descriptor a Descriptor.

    `parse` and `miniscript.parse` are driven on `preimages` in
    `tests/serialization_boundary_test.py`, and `prv_keys` here in
    `tests/prv_keys_contract_test.py`.
    """
    descriptor = parse(f"wpkh({_KEY})")
    with pytest.raises(BTClibTypeError, match="invalid preimages type"):
        private_string(descriptor, None, "x")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid descriptor type"):
        private_string(str(descriptor))  # type: ignore[arg-type]


def test_a_tapscript_hash_fragment_takes_a_preimage_too() -> None:
    """The context changes the keys, not the hash fragments."""
    preimages: dict[bytes, bytes] = {}
    node = parse_miniscript(
        f"and_v(v:pk({_KEY[2:]}),hash256(preimage({_PREIMAGE})))",
        TAPSCRIPT,
        {},
        preimages,
    )
    assert node.subs[1].data in preimages
