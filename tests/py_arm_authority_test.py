# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

r"""What says the Python arm is right, other than the bindings.

The suite validates the Python arithmetic *against* libsecp256k1, the
bindings being the reference implementation. A caller that runs the
Python arm so that libsecp256k1 is not checked with libsecp256k1 needs
the other property (issue btclib-org/btclib#198): per arm, which vectors
of somebody else's making reach it (issue btclib-org/btclib#993). btclib's
own `py_arm_authority_test.py` is that inventory for btclib's arms, and
this is the inventory for this package's.

The arms are counted from the source -- a function containing a call to
`is_libsecp256k1_serving` is an arm -- so one added without an entry
fails.
The entries were measured, not reasoned:

    ECC_NO_LIBSECP256K1=1 \
        uv run --locked pytest <one module> \
        -m "not bindings" --cov=bip32_descriptors --cov-report=json \
        --cov-fail-under=0

reading back which lines of each arm ran. A module is named here when its
run reached the arm's body, the `def` line excluded -- that line runs at
import and would report every arm of every imported module as reached.
The variable is ecc's, which `tests/conftest.py`'s `NO_LIBSECP256K1`
names, and a run whose dispatch still serves with it set is refused there
rather than measured.
`-m "not bindings"` because the variable switches the dispatch off with
the bindings still installed, so what needs them is deselected rather
than skipped.

**Nothing here re-runs the measurement.** The tests below check the
table's shape -- its keys against the parser, its cited modules against
the vector table, its entries against that same table -- and none reruns
the coverage that produced `_AUTHORITY`'s values.

**The attribution is per module, and a module may also hold tests this
package wrote.** So an entry says "a module built on third-party vectors
reaches this arm", which is weaker than "this vector reaches this arm"
and is what the measurement supports.
"""

from __future__ import annotations

import ast
from pathlib import Path

_LIBRARY = Path(__file__).parents[1] / "src" / "bip32_descriptors"
_TESTS = Path(__file__).parent

# the vendored vectors each module below is built on, by the name they
# carry in `tests/_data` or a `_data` beside the module. What makes a
# source third-party is who wrote it: a BIP, Bitcoin Core, an RFC
_THIRD_PARTY_VECTORS: dict[str, tuple[str, ...]] = {
    "bip32/bip32_test.py": ("bip32_test_vectors.json", "bip32_invalid_keys.json"),
}

# arm -> the modules of `_THIRD_PARTY_VECTORS` whose run reaches it
_AUTHORITY: dict[str, tuple[str, ...]] = {}


def _py_arms(library: Path) -> set[str]:
    """Return every function under `library` that holds a dispatch.

    A function whose source calls `is_libsecp256k1_serving` has two arms, and
    the one this file is about is the arm that call declines. The match is
    textual, over the function's own source, so a comment writing the call
    spelling invents an arm and a nested function is attributed to its
    enclosing function as well: neither can hide a real arm. The key is
    `module.funcname`, so two same-named methods of two classes in one
    module would collide into one entry.
    """
    found: set[str] = set()
    for path in sorted(library.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        module = ".".join(path.relative_to(library).with_suffix("").parts)
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            segment = ast.get_source_segment(source, node) or ""
            if "is_libsecp256k1_serving(" in segment:
                found.add(f"{module}.{node.name}")
    return found


def test_every_py_arm_is_in_the_inventory() -> None:
    """An arm added without an entry fails here, which is the point."""
    # an empty inventory matches an empty scan, so the scan has to have
    # read the package before its answer counts
    assert (_LIBRARY / "bip32" / "bip32.py").is_file(), f"no package at {_LIBRARY}"
    listed = set(_AUTHORITY)
    found = _py_arms(_LIBRARY)
    assert listed == found, (
        f"not in the inventory: {sorted(found - listed)};"
        f" gone from the package: {sorted(listed - found)}"
    )


def test_the_arm_scan_finds_a_planted_dispatch(tmp_path: Path) -> None:
    """A scan that found nothing would pass the test above."""
    (tmp_path / "unit").mkdir()
    (tmp_path / "unit" / "mod.py").write_text(
        "def arm():\n    return is_libsecp256k1_serving()\n\n"
        "def plain():\n    return None\n",
        encoding="utf-8",
    )
    assert _py_arms(tmp_path) == {"unit.mod.arm"}


def test_every_arm_has_an_authority() -> None:
    """No arm of this package is reached by nothing third-party."""
    assert all(_AUTHORITY.values())


def test_every_named_module_is_in_the_tree_and_reads_its_vectors() -> None:
    """A module named here exists, and the vectors it is named for do too."""
    for module, vectors in _THIRD_PARTY_VECTORS.items():
        path = _TESTS / module
        assert path.is_file(), f"{module} is named in the inventory and is not here"
        source = path.read_text(encoding="utf-8")
        for vector in vectors:
            assert vector in source, f"{module} no longer names {vector}"


def test_every_authority_names_a_module_of_the_table() -> None:
    """No entry may cite a module whose vectors are not written down."""
    uncovered = [
        (arm, module)
        for arm, sources in _AUTHORITY.items()
        for module in sources
        if module not in _THIRD_PARTY_VECTORS
    ]
    assert not uncovered, (
        f"cited, and no line of _THIRD_PARTY_VECTORS covers: {uncovered}"
    )
