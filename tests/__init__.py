# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Non-regression tests for bip32_descriptors, and the vectors they read.

The vector files are the BIPs', Bitcoin Core's and a few other projects',
which tests/_data/README.md pins.
Read them here and hand them to `pytest.mark.parametrize`, so that a
vector is a test rather than one turn of a loop inside a single test
function: xdist can then spread them over the cores, a failure names the
vector instead of the loop that was running it, and the vectors after the
first failure still run.

Here rather than in a `tests/vectors.py`: every Python file under
`tests/` is a test file except `__init__.py` and `conftest.py`, so the
loaders live in the package `__init__`, and shared test code lives in the
package `__init__` at every level.

This package is imported by every test module, before that module's own
body runs, so whatever this file executes at import time executes inside
every module's own measured reach. A literal is safe to share here at
module scope. Anything that calls into btclib's own arithmetic, or imports
a module of it that a test may want to reach first, is shared as a
function instead, and imports what it needs when a caller invokes it.
"""

import importlib
import json
import pkgutil
import re
import sys
import types
from collections.abc import Callable
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

import bip32_descriptors

_TESTS_DIR = Path(__file__).parent


def chained_text(e: BaseException | None) -> str:
    """Return the `str` and `repr` of an exception and its chain."""
    text = ""
    while e is not None:
        text += f"{e!s} {e!r} "
        e = e.__cause__ or e.__context__
    return text


# what `str.strip()` takes and `string.whitespace` does not: U+001C is
# ASCII and the rest are not. A value padded with one of them is not the
# value it wraps (issue btclib-org/btclib-wallet#102)
NOT_STRIPPED = (
    "\N{NO-BREAK SPACE}",
    "\N{IDEOGRAPHIC SPACE}",
    "\N{LINE SEPARATOR}",
    "\N{NEXT LINE}",
    "\N{INFORMATION SEPARATOR FOUR}",
)


def module_names() -> list[str]:
    """Return every module of the installed package, the root included.

    Here rather than at each site that walks the package: what the walk
    covers is settled here for all of them, and a copy that disagreed
    would be red nowhere, each site asserting against whatever its own
    walk found.
    """
    return [
        "bip32_descriptors",
        *(
            module.name
            for module in pkgutil.walk_packages(
                bip32_descriptors.__path__, "bip32_descriptors."
            )
        ),
    ]


def public_classes_with(method_name: str) -> set[str]:
    """Return each public class offering that method, with its module.

    Found rather than listed, which is what makes an inventory a promise:
    a class added to the library has to appear in the test that holds the
    method to its contract, or be named an exclusion there. A class this
    walk cannot reach is one no caller can import either.

    The module is part of the name because two classes can share one. A
    private class is skipped, the contract being about what a
    caller can reach.

    Here rather than in the one test that first needed it: the files that
    call it hold the same classes to contracts of their own, and none of
    them owns the walk.
    """
    found = set()
    for module_name in module_names():
        module = importlib.import_module(module_name)
        for obj in vars(module).values():
            if not isinstance(obj, type):
                continue
            module_of = getattr(obj, "__module__", "")
            if module_of.split(".")[0] != "bip32_descriptors":
                continue
            if obj.__qualname__.startswith("_"):
                continue
            if callable(getattr(obj, method_name, None)):
                found.add(f"{obj.__module__}.{obj.__qualname__}")
    return found


def load(*relative_path: str, encoding: str = "ascii") -> Any:
    """Read a vendored JSON vector file, named relative to `tests/`.

    Naming a vector file by its path from the test suite root, rather
    than from the test module that reads it, is what lets two packages
    share one file without the `dirname(dirname(__file__))` walk that
    breaks the moment a test module moves.
    """
    with _TESTS_DIR.joinpath(*relative_path).open(encoding=encoding) as file_:
        return json.load(file_)


# what makes an id unreadable in a report and unusable in a -k expression:
# anything that is not a letter, a digit or a dash. Bitcoin Core comments
# hold spaces, quotes, parentheses and slashes; a descriptor holds a '#'
_NOT_IN_AN_ID = re.compile(r"[^0-9A-Za-z]+")


def vector_id(index: int, *description: object) -> str:
    """Name the vector at `index`: where it is, then what it is about.

    The position alone is what parametrize generates on its own, and it
    says where in the file to look but not what the case was testing;
    the description alone -- the comment of a Bitcoin Core vector, a
    script, an address -- reads well but is neither unique nor always
    there. Both, so that the red line of a report both identifies the
    vector in the file and says what it is, and `-k` can select it.

    Truncated, because a description is occasionally a whole script: an
    id is a name, and the vector file remains the place to read the
    case in full.
    """
    text = "-".join(str(d) for d in description if d)
    text = _NOT_IN_AN_ID.sub("-", text).strip("-")
    return f"{index}-{text[:60]}" if text else str(index)


def replace_unchecked(instance: Any, **changes: Any) -> Any:
    """Return `instance` with the given fields changed, validation skipped.

    `dataclasses.replace` always re-validates through `__init__` -- right
    for a modified copy meant to stay valid, wrong for a fixture built to
    fail its own `assert_valid` on purpose. A frozen dataclass of this
    project that takes `check_validity` takes it keyword-only
    (`CONTRIBUTING.md`'s "The public surface"), so this is the one helper
    any of them can use in place of the direct field mutation a frozen
    instance now refuses.
    """
    current = {
        field.name: getattr(instance, field.name) for field in fields(instance)
    } | changes
    return type(instance)(**current, check_validity=False)


# What a test asking libsecp256k1 for the right answer is marked with.
#
# The suite validates the Python arithmetic *against* the bindings, so a
# few tests hold both implementations and compare them. Those cannot run
# where only one exists, and marking them is what lets the rest of the
# suite run without the bindings installed.
#
# A marker and not a `skipif`, with `conftest.py` turning it into a skip
# where the bindings are absent. One name then does both jobs: `pytest -m
# "not bindings"` names the same set a run without the bindings runs, and
# the registration in pyproject.toml has something to be strict about.
needs_bindings = pytest.mark.bindings


# --------------------------------------------------------------------------
# The libsecp256k1 dispatch switched off, shared by the tests that ask the
# Python arm of a function a question. The dispatch they switch off is the
# one `ecc.curves.set_libsecp256k1_serving` sets, and this package
# reaches the bindings only through ecc.
# --------------------------------------------------------------------------


def _refuse_bindings(monkeypatch: pytest.MonkeyPatch, mod: types.ModuleType) -> None:
    """Replace every btclib_secp256k1 callable `mod` holds with one that raises.

    A callable is one of the bindings when its own `__module__` is in
    btclib_secp256k1, whatever name `mod` holds it under, so no name of
    `mod` is spelled here. A module `mod` holds is skipped: a caller
    reaching through one, as `ecc.curves.sec_point` reaches through
    `keys`, is refused by walking that module itself.
    """

    def refuse(what: str) -> Callable[..., Any]:
        def asked(*_args: object, **_kwargs: object) -> Any:
            # a green suite is one where this never runs, the dispatch
            # switched off beside every call of this ruling the call out
            raise AssertionError(  # pragma: no cover -- the dispatch switched off keeps this uncalled
                f"the Python arm reached libsecp256k1: {what}"
            )

        return asked

    for attr, value in list(vars(mod).items()):
        if isinstance(value, types.ModuleType) or not callable(value):
            continue
        origin = getattr(value, "__module__", None) or ""
        if origin.split(".")[0] == "btclib_secp256k1":
            monkeypatch.setattr(mod, attr, refuse(f"{mod.__name__}.{attr}"))


# the packages `no_bindings_anywhere` walks
WALKED_PACKAGES = frozenset({"btclib", "ecc", "bip32_descriptors", "btclib_secp256k1"})


def no_bindings_anywhere(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put every already-bound btclib_secp256k1 callable out of reach.

    `curves.set_libsecp256k1_serving` sets what every dispatch reads on
    every call, so switching it off is the whole dispatch;
    `tests/conftest.py` puts it back after every test. The switch is what
    keeps every binding uncalled; the refusals are what show it did. A
    module can hold a binding of its own -- `ecc.curves.sec_point`
    imports the bindings' `PubkeyTweakChain` -- and `from ... import x as
    y` copies the object rather than looking it up again, so a patch on
    the module the bindings live in does not reach a name already copied
    out of it.

    So this walks every module already loaded under a package of
    `WALKED_PACKAGES` and refuses every bindings callable there, whichever
    module holds the name; `ecc` is where a btclib that delegates
    its curve arithmetic to it holds the dispatch. The dispatch is
    switched off alongside it, since a caller with the flag still on and
    every name unreachable is not the configuration a missing install
    produces. An arm this does not cover fails by calling through instead
    of passing by measuring the bindings against themselves.
    """
    from ecc.curves import set_libsecp256k1_serving  # noqa: PLC0415

    for mod_name, mod in list(sys.modules.items()):
        if mod_name.split(".")[0] in WALKED_PACKAGES:
            _refuse_bindings(monkeypatch, mod)

    set_libsecp256k1_serving(serving=False)
