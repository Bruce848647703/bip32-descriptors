# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every `bool` parameter of the package, classified and held to its class.

btclib's census of the same name, over this package: a kind written down
and read back -- json, a configuration file, a coordinator's message --
arrives as whatever it was written as, and `"false"` is true
(issue btclib-org/btclib#868).

## The line, and the shape that makes it decidable

A **truth** only decides whether the call refuses: `verify_checksum=False`
says do not check, and the answer is the same one. So a value read for its
truth runs a check or skips one and changes no answer, which is why
nothing is refused there.

A **kind** decides what a non-refusing call computes, returns or writes.
`"no"` is true, so a kind read for its truth quietly computes the other
answer -- the other key, the other signature, the other script -- and that
is what the refusal is for.

## The polarity a truth has to have

`"no"` is true, and so is every other wrong value, so the misreading is
never "the flag was off": it is always the one the flag's `True` stands
for. That is what makes a truth safe rather than the fact that it changes
no answer: the wrong value falls on the side that refuses more.

So a truth's `True` has to be its conservative value, and a flag whose
`True` is the permissive one is a kind however little it computes:
`compressed` of the two extended-key parses is one, in `_KINDS` with its
reason beside it (issue btclib-org/btclib#884).

The two tests below are that line, one each:

- a kind refuses `"no"`, `0`, `1` and (where the annotation does not
  declare it) `None`, with a `BTClibTypeError` -- or ecc's
  `EccTypeError`, where the flag is handed on to that package
  (issue btclib-org/btclib#2282)
- a truth **accepts** them, on a fixture the flag's `True` accepts: a
  truth that starts refusing fails here, and the entry has to move rather
  than the test being edited

## The walk, and the one name it subtracts

`_bool_parameters` reads every public function of the package and every
`bool`-annotated parameter of one, so a flag added anywhere is either in a
table here or the run is red -- there is no third table, and that is the
state to keep.

`check_validity` is subtracted by name: it is a convention rather than a
parameter, held by btclib's own `check_validity_test.py` to one rule over
every class.

"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from bip32_descriptors.bip32.bip32 import (
    derive,
    derive_from_account,
    derive_from_account_,
    derive_from_account_range,
    derive_from_account_range_,
    prv_keyinfo_from_xprv,
    pub_keyinfo_from_xpub,
    rootxprv_from_seed,
    xpub_from_xprv,
)
from bip32_descriptors.bip32.der_path import (
    hardenings_from_der_path,
    indexes_from_der_path,
    int_from_index_str,
)
from tests.exception_family_test import TYPE_ERRORS

_LIBRARY = Path(__file__).parents[1] / "src" / "bip32_descriptors"

# `check_validity` is the one name the walk subtracts, and this is the
# reason it may: it is a convention over many signatures rather than a
# parameter of one
_OWNED_BY_ITS_OWN_FILE = "check_validity"

# a value of no bool type: a truthy string, and the two integers `bool`
# inherits from. Every one of them is a call mypy refuses
_WRONG_TYPES: tuple[Any, ...] = ("no", 0, 1)

_ROOT_XPRV = rootxprv_from_seed("00" * 32)
_ACCOUNT_XPRV = derive(_ROOT_XPRV, "m/44h/0h/0h")


_XPUB = xpub_from_xprv(_ROOT_XPRV)


@dataclass(frozen=True)
class _Case:
    """One `bool` parameter, and a call of its function that works."""

    dotted: str
    flag: str
    function: Any
    # every argument but the flag, by keyword
    args: dict[str, Any] = field(default_factory=dict)
    # the flag value the working call is made with: `True` unless the
    # fixture is one only `False` accepts
    valid: bool = True
    # `bool | None` declares None, so it is not a wrong value there. Read
    # off the annotation, not an exemption from anything
    optional: bool = False
    # the classification, which is prose because it is a judgement: for a
    # truth what the flag turns on and what it therefore cannot change,
    # and for a kind only where the kind is the polarity rather than the
    # answer -- the flags carrying one below are those
    reason: str = ""


_KINDS = (
    # the two extended-key parses. Their `compressed` computes nothing --
    # a BIP32 key is compressed, so the flag is a check on a key that has
    # already answered the question -- and it is the polarity that makes
    # each a kind
    _Case(
        "bip32_descriptors.bip32.bip32.prv_keyinfo_from_xprv",
        "compressed",
        prv_keyinfo_from_xprv,
        {"xprv": _ROOT_XPRV},
        optional=True,
        reason="`True` is the value an extended key already has, so a"
        " non-bool passes the check a False was written down to fail and"
        " an uncompressed key is reported as this compressed one",
    ),
    _Case(
        "bip32_descriptors.bip32.bip32.pub_keyinfo_from_xpub",
        "compressed",
        pub_keyinfo_from_xpub,
        {"xpub": _XPUB},
        optional=True,
        reason="`prv_keyinfo_from_xprv`'s above, on the public half",
    ),
)

_TRUTHS = (
    _Case(
        "bip32_descriptors.bip32.der_path.int_from_index_str",
        "bip380_enforced",
        int_from_index_str,
        {"s": "0"},
        reason="whether BIP380's spelling rules are enforced; an index both"
        " accept is the same integer",
    ),
    _Case(
        "bip32_descriptors.bip32.der_path.indexes_from_der_path",
        "bip380_enforced",
        indexes_from_der_path,
        {"der_path": "0/1"},
        reason="whether BIP380's spelling rules are enforced",
    ),
    _Case(
        "bip32_descriptors.bip32.der_path.hardenings_from_der_path",
        "bip380_enforced",
        hardenings_from_der_path,
        {"der_path": "0/1"},
        reason="whether BIP380's spelling rules are enforced",
    ),
    _Case(
        "bip32_descriptors.bip32.bip32.derive_from_account",
        "branches_0_1_only",
        derive_from_account,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_index": 0},
        reason="whether a branch other than 0 and 1 is refused; the key"
        " derived at a branch both accept is the same key",
    ),
    _Case(
        "bip32_descriptors.bip32.bip32.derive_from_account_",
        "branches_0_1_only",
        derive_from_account_,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_index": 0},
        reason="the flag of `derive_from_account` above, in the spelling"
        " that answers the key rather than its Base58Check text",
    ),
    _Case(
        "bip32_descriptors.bip32.bip32.derive_from_account_range",
        "branches_0_1_only",
        derive_from_account_range,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_indexes": [0]},
        reason="the flag of `derive_from_account` above, over many"
        " addresses of one branch rather than over one",
    ),
    _Case(
        "bip32_descriptors.bip32.bip32.derive_from_account_range_",
        "branches_0_1_only",
        derive_from_account_range_,
        {"mxkey": _ACCOUNT_XPRV, "branch": 0, "address_indexes": [0]},
        reason="the flag of `derive_from_account_range` above, in the"
        " spelling that answers the keys rather than their text",
    ),
)

_KIND_IDS = tuple(f"{case.dotted}({case.flag})" for case in _KINDS)
_TRUTH_IDS = tuple(f"{case.dotted}({case.flag})" for case in _TRUTHS)


def _flags_of(function: ast.FunctionDef) -> set[str]:
    """Return the `bool`-annotated parameters of one public function."""
    if function.name.startswith("_") and not function.name.startswith("__"):
        return set()
    arguments = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    return {
        argument.arg
        for argument in arguments
        if argument.annotation is not None
        and ast.unparse(argument.annotation) in {"bool", "bool | None"}
        and argument.arg != _OWNED_BY_ITS_OWN_FILE
    }


def _bool_parameters() -> set[tuple[str, str]]:
    """Return every (function, `bool` parameter) pair of the public API.

    Keyed on the annotation, `bool` and `bool | None`: what a flag is
    called says nothing, and `include_witness` is spelled both ways.

    A method counts and a private function does not, as in
    `curve_parameter_test.py`. A method of a private class does not count
    either. A function nested in another is a closure rather than API --
    `Miniscript.to_script`'s `up` takes a `verify` that no caller can
    pass.
    """
    found: set[tuple[str, str]] = set()

    def walk(node: ast.Module | ast.ClassDef, module: str, prefix: str) -> None:
        for child in node.body:
            if isinstance(child, ast.ClassDef):
                if not child.name.startswith("_"):
                    walk(child, module, f"{prefix}{child.name}.")
            elif isinstance(child, ast.FunctionDef):
                dotted = f"{module}.{prefix}{child.name}"
                found.update((dotted, flag) for flag in _flags_of(child))

    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        walk(ast.parse(path.read_text(encoding="utf-8")), module, "")
    return found


@pytest.mark.parametrize("case", [*_KINDS, *_TRUTHS], ids=[*_KIND_IDS, *_TRUTH_IDS])
def test_the_call_works(case: _Case) -> None:
    """The fixture is valid, which is what makes a refusal below a finding.

    Without this a case whose arguments had gone stale would pass every
    test in the file by refusing everything it is handed.
    """
    case.function(**case.args, **{case.flag: case.valid})


@pytest.mark.parametrize("case", _KINDS, ids=_KIND_IDS)
def test_a_kind_refuses_a_non_bool(case: _Case) -> None:
    """A kind decides what is computed, so it is not read for its truth.

    `"no"` is the value that makes the point -- it is true, so the flag
    would be on -- and `0` and `1` are the two `bool` inherits from, which
    is what makes `isinstance(value, int)` no check at all here.
    """
    wrong = _WRONG_TYPES if case.optional else (*_WRONG_TYPES, None)
    for value in wrong:
        with pytest.raises(TYPE_ERRORS, match=f"invalid {case.flag} type"):
            case.function(**case.args, **{case.flag: value})


@pytest.mark.parametrize("case", _TRUTHS, ids=_TRUTH_IDS)
def test_a_truth_is_read_for_its_truth(case: _Case) -> None:
    """The other half of the line, and the ratchet under this file.

    A truth turns a check on or off and changes no answer, so a value of
    another type is read for whether it is true and refused by nothing.
    An entry that starts refusing fails here rather than passing quietly:
    the fix is to move it to `_KINDS`, which is a decision about the
    parameter and not about this test.
    """
    for value in _WRONG_TYPES:
        case.function(**case.args, **{case.flag: value})


def test_every_bool_parameter_is_classified() -> None:
    """No third table: a flag is a kind or a truth, and the walk says so.

    A parameter added anywhere under `src/bip32_descriptors/` fails here until
    somebody decides which of the two it is -- which is the decision this file
    exists to keep from being made by default.
    """
    classified = {(case.dotted, case.flag) for case in (*_KINDS, *_TRUTHS)}
    found = _bool_parameters()
    assert classified == found, (
        f"unclassified: {sorted(found - classified)};"
        f" gone from the tree: {sorted(classified - found)}"
    )


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes it must find, and the ones it must not.

    A walk that found nothing would pass the test above.
    """
    found = _bool_parameters()
    # a defaulted flag, and an optional annotation
    assert (
        "bip32_descriptors.bip32.der_path.int_from_index_str",
        "bip380_enforced",
    ) in (found)
    assert (
        "bip32_descriptors.bip32.bip32.prv_keyinfo_from_xprv",
        "compressed",
    ) in found

    # the convention with a file of its own
    assert not [pair for pair in found if pair[1] == "check_validity"]
    # a closure, and a parameter of another type
    assert ("bip32_descriptors.descriptors.miniscript.up", "verify") not in found
    assert ("bip32_descriptors.bip32.bip32.derive", "der_path") not in found
