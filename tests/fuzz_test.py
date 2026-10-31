# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every parser, on input nobody wrote down.

The rest of the suite is fixed vectors: exactly what conformance needs,
and blind to the malformed bytes that never make it into a
specification's test section. This file is the converse. It does not
assert that a parser accepts the right things -- the vectors do that --
but that it *fails the way the library says it fails*, whatever it is
handed.

Issues btclib-org/btclib#133, btclib-org/btclib#135 and
btclib-org/btclib#138 were all one bug: a parser answering hostile input
with IndexError, or OverflowError, or a silent short read, where the
caller was catching BTClibValueError to reject it. btclib's own
`fuzz_test.py` drives btclib's parsers, and this one this package's.
"""

import contextlib
import importlib
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from bip32_descriptors import descriptors
from bip32_descriptors.bip32.bip32 import BIP32KeyData, rootxprv_from_seed
from bip32_descriptors.bip32.der_path import indexes_from_der_path
from bip32_descriptors.bip32.key_origin import BIP32KeyOrigin
from bip32_descriptors.descriptors import miniscript
from tests import module_names, public_classes_with
from tests.exception_family_test import RUNTIME_ERRORS, TYPE_ERRORS, VALUE_ERRORS

# What a parser is allowed to raise. Anything else -- an IndexError off a
# short slice, an OverflowError off an unchecked size, a KeyError, a
# UnicodeDecodeError -- leaves the contract btclib's exceptions module
# documents, and reaches a caller who wrote `except BTClibValueError` to
# reject bad input and has no reason to expect anything else. Each of the
# three with ecc's class of its kind beside it, which is what a
# parse that library performs refuses with (issue btclib-org/btclib#2282)
CONTRACT = (*VALUE_ERRORS, *TYPE_ERRORS, *RUNTIME_ERRORS)

# Bounded because these are parsers, not benchmarks: what a length field
# does with the bytes behind it is decided in the first few of them, and
# an input long enough to be interesting to a parser is one this
# strategy cannot stumble on anyway. The mutation test below is what
# reaches past the outermost check
MAX_INPUT = 512

BINARY_PARSERS: dict[str, Callable[[bytes], Any]] = {
    "BIP32KeyData.parse": BIP32KeyData.parse,
    "BIP32KeyOrigin.parse": BIP32KeyOrigin.parse,
}


# The same contract, for what a user pastes rather than what a peer
# sends: an extended key, a derivation path, a descriptor.
#
# The base58 wrapper is here rather than above, and is a parser of its
# own: `b58decode` decodes and then hands the bytes to `parse`, so what it
# adds is the decoding, a layer the binary entry point never sees
TEXT_PARSERS: dict[str, Callable[[str], Any]] = {
    "BIP32KeyData.b58decode": BIP32KeyData.b58decode,
    "descriptors.checksum": descriptors.checksum,
    "descriptors.parse": descriptors.parse,
    "miniscript.parse": miniscript.parse,
    "der_path.indexes_from_der_path": indexes_from_der_path,
}


# A class-level decoder is one of these: `parse` for octets, and
# `b64decode` and `b58decode` for the two text encodings a class reads on
# its own, as `serialization_boundary_test.py` walks them
_CLASS_DECODER_METHODS = ("parse", "b64decode", "b58decode")

# And the module-function side: the names a bare function decodes
# under. A decoder named otherwise rests on the dicts, by hand, not on
# this walk
_MODULE_DECODER_NAMES = (
    "parse",
    "decode",
    "checksum",
    "indexes_from_der_path",
)


def _classes_driven_here() -> set[str]:
    """Every class the two dicts above drive, through which decoder.

    A bound classmethod carries in `__self__` the class it was read off
    rather than the one that defines the method, which is what the entry
    names: a class inheriting a private base's `parse` would answer
    `__qualname__` with that base, which the walk below never returns. The
    method name is part of the key, since a class offering two of them
    would otherwise collide.
    """
    driven = set()
    for entry_point in (*BINARY_PARSERS.values(), *TEXT_PARSERS.values()):
        cls = getattr(entry_point, "__self__", None)
        if isinstance(cls, type) and entry_point.__name__ in _CLASS_DECODER_METHODS:
            driven.add(f"{cls.__module__}.{cls.__qualname__}.{entry_point.__name__}")
    return driven


def _functions_driven_here() -> set[str]:
    """Every module function the two dicts above drive, module included."""
    return {
        f"{entry_point.__module__}.{entry_point.__name__}"
        for entry_point in (*BINARY_PARSERS.values(), *TEXT_PARSERS.values())
        if getattr(entry_point, "__self__", None) is None
    }


def test_every_class_that_decodes_is_driven_here() -> None:
    """The inventory is a promise only if omission is what fails.

    A class added to the package and given no line above is held to
    nothing here: the tests keep passing on the entry points they were
    given, and the new decoder answers hostile input however it likes.
    The walk is `tests/__init__.py`'s, `parse_contract_test.py` and
    `serialization_boundary_test.py` holding these same classes to their
    own contracts through it.
    """
    found = {
        f"{name}.{method}"
        for method in _CLASS_DECODER_METHODS
        for name in public_classes_with(method)
    }
    # a walk returning nothing is a defect in the walk and not in the
    # inventory, and the equality alone answers it with a mismatch of
    # every name: this is what says which of the two a red run is
    assert found
    assert found == _classes_driven_here()


def test_every_module_function_that_decodes_is_driven_here() -> None:
    """And the same promise where the entry point is a module function.

    The walk above finds classes, so a module-level decoder needs its
    own names, `_MODULE_DECODER_NAMES`.
    What is asserted is containment and not equality: the dicts already
    drive entry points named otherwise, and their coverage rests on the
    dicts above, by hand, not on this walk.
    """
    found = set()
    for module_name in module_names():
        module = importlib.import_module(module_name)
        for name in _MODULE_DECODER_NAMES:
            function = getattr(module, name, None)
            if not callable(function) or isinstance(function, type):
                continue
            if getattr(function, "__module__", "") != module_name:
                continue
            found.add(f"{module_name}.{name}")

    # the containment below is what an empty walk passes, the class walk
    # above having an equality to fail instead
    assert found
    assert found - _functions_driven_here() == set()


def _assert_contract(parse: Callable[[Any], Any], data: Any) -> None:
    """Call parse, and let anything outside the contract propagate.

    Rejecting the input is the expected answer to almost all of what
    these strategies generate, so there is nothing to assert about it.
    What the test is for is the third outcome, neither a value nor a
    refusal: hypothesis reports the exception, and the input it shrank
    to reach it.
    """
    with contextlib.suppress(*CONTRACT):
        parse(data)


@pytest.mark.parametrize(
    "parse", BINARY_PARSERS.values(), ids=list(BINARY_PARSERS.keys())
)
@given(data=st.binary(max_size=MAX_INPUT))
def test_binary_parser_honors_the_exception_contract(
    parse: Callable[[bytes], Any], data: bytes
) -> None:
    """Fuzz every binary parser: refusals stay within the contract."""
    _assert_contract(parse, data)


@pytest.mark.parametrize("parse", TEXT_PARSERS.values(), ids=list(TEXT_PARSERS.keys()))
@given(data=st.text(max_size=MAX_INPUT))
def test_text_parser_honors_the_exception_contract(
    parse: Callable[[str], Any], data: str
) -> None:
    """Fuzz every text parser: refusals stay within the contract."""
    _assert_contract(parse, data)


# A number of more than 4300 digits is past `MAX_INPUT` and past what
# `int()` takes, so the strategy above cannot stumble on it. Each text
# parser is handed one in every place a number is read.
_KEY = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"  # pragma: allowlist secret
_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjq"  # pragma: allowlist secret
    "JoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"  # pragma: allowlist secret
)
_MINISCRIPT_TEXTS = (
    "older({n})",
    f"thresh({{n}},pk({_KEY}),s:pk({_KEY}))",
    f"multi({{n}},{_KEY})",
)
LONG_NUMBER_TEXTS = [(miniscript.parse, text) for text in _MINISCRIPT_TEXTS] + [
    (descriptors.parse, f"wsh(and_v(v:pk({_KEY}),{_MINISCRIPT_TEXTS[0]}))"),
    (descriptors.parse, f"wsh({_MINISCRIPT_TEXTS[1]})"),
    (descriptors.parse, f"wsh({_MINISCRIPT_TEXTS[2]})"),
    (descriptors.parse, f"wpkh({_XPUB}/{{n}})"),
]


@pytest.mark.parametrize("parse, template", LONG_NUMBER_TEXTS)
def test_text_parser_refuses_a_number_over_4300_digits(
    parse: Callable[[str], Any], template: str
) -> None:
    """A number `int()` cannot read leaves as the contract says."""
    for digits in ("9" * 5000, "0" * 5000 + "1"):
        _assert_contract(parse, template.format(n=digits))


# a root extended private key, serialized: 78 octets of fixed-width fields
XKEY_BIN = BIP32KeyData.b58decode(rootxprv_from_seed("00" * 32)).serialize()


def _mutations(sample: bytes) -> st.SearchStrategy[bytes]:
    """Return the near-misses of a valid serialization.

    Uniform random bytes are rejected by the first field of a parser and
    so exercise the outermost check and nothing beneath it. What reaches
    the code underneath is a serialization valid right up to the point
    where it is not: the truncation, the flipped length prefix, the
    trailing junk that must not be taken for a second record.
    """
    truncated = st.integers(min_value=0, max_value=len(sample)).map(
        lambda i: sample[:i]
    )
    flipped = st.builds(
        lambda i, byte: sample[:i] + bytes([byte]) + sample[i + 1 :],
        st.integers(min_value=0, max_value=len(sample) - 1),
        st.integers(min_value=0, max_value=0xFF),
    )
    extended = st.binary(max_size=32).map(lambda tail: sample + tail)
    return st.one_of(truncated, flipped, extended)


MUTATED_PARSERS: dict[str, tuple[Callable[[bytes], Any], bytes]] = {
    "BIP32KeyData.parse": (BIP32KeyData.parse, XKEY_BIN),
}


@pytest.mark.parametrize(
    "parse, sample",
    MUTATED_PARSERS.values(),
    ids=list(MUTATED_PARSERS.keys()),
)
@given(data=st.data())
def test_mutated_serialization_honors_the_exception_contract(
    parse: Callable[[bytes], Any], sample: bytes, data: st.DataObject
) -> None:
    """Fuzz near-miss serializations: refusals stay within the contract."""
    _assert_contract(parse, data.draw(_mutations(sample)))
