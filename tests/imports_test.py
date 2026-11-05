# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the import graph of the `bip32_descriptors` package.

Every module must be importable *first*, with no other module of this
package or of `btclib` in sys.modules yet. Nothing else in the suite
establishes that: a test module reaches its subject through whatever the
modules imported before it have already pulled in, so a cycle that only
bites the caller who happens to arrive from the other side stays
invisible.

And every module must reach the units of this package by this package's
name. The units were cut out of `btclib`, whose older releases still
publish them at their old paths, so a `btclib.bip32` left behind would
import, run and pass against a copy nobody maintains here.

What a module may import is the standard library, this package and the
distributions `dependencies` in pyproject.toml names, with the bindings
of the `secp256k1` extra behind a guard: each file's import statements
are read statically. And `bip32` imports nothing of the package, while
`descriptors` imports `bip32` alone.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

import bip32_descriptors
from tests import module_names


def _is_ours(name: str) -> bool:
    """Answer whether a dotted name is this package's, btclib's or ecc's.

    `btclib_secp256k1`, the bindings, is none of the three: reimporting a
    cffi extension module is another matter entirely, so the boundary is
    the three package names and their submodules, not a bare `startswith`.
    """
    return any(
        name == root or name.startswith(f"{root}.")
        for root in ("btclib", "ecc", "bip32_descriptors")
    )


def loaded_modules() -> list[str]:
    """Return the modules of this package, of btclib and of ecc."""
    return [name for name in sys.modules if _is_ours(name)]


@pytest.fixture
def unimported() -> Iterator[None]:
    """Hide every module of this package and of btclib, then put it back.

    A subprocess per module would be the obvious way to get a virgin
    interpreter, and it costs an interpreter start-up per module for
    nothing: the import machinery decides what to execute by consulting
    sys.modules and nothing else.

    What the modules imported inside the fixture must not do is outlive
    it. They are fresh objects, so a class reimported here is not the
    class the rest of the suite already holds a reference to, and an
    isinstance check across the two would fail.
    """
    saved = {name: sys.modules[name] for name in loaded_modules()}
    for name in saved:
        del sys.modules[name]
    try:
        yield
    finally:
        for name in loaded_modules():
            del sys.modules[name]
        sys.modules.update(saved)


@pytest.mark.parametrize("module_name", module_names())
def test_import_first(module_name: str, unimported: None) -> None:
    """Import each module first, with nothing of either package loaded."""
    assert importlib.import_module(module_name).__name__ == module_name


def test_the_tests_package_imports_no_submodule() -> None:
    """Importing the `tests` package alone reaches no submodule of either.

    `tests/__init__.py` is imported by every test module before that
    module's own body runs -- before any fixture, `unimported` included,
    so this probe is a subprocess rather than that fixture. The coverage
    floor reads what the import itself reaches, so a helper built at the
    module scope of `tests/__init__.py` by calling into btclib would be
    measured as reached by every module that asks it nothing.
    """
    probe = (
        "import sys, tests; "
        "print(sorted(m for m in sys.modules "
        "if m.split('.')[0] in ('btclib', 'bip32_descriptors')))"
    )
    loaded = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        check=True,
        capture_output=True,
        encoding="utf-8",
        cwd=Path(__file__).resolve().parents[1],
    ).stdout
    assert ast.literal_eval(loaded) == ["bip32_descriptors"]


# the top-level units of this package, which btclib carried under its own
# name until its side of btclib-org/btclib#2129 removed them
_UNITS = tuple(sorted(bip32_descriptors.__all__))


def _stale_units_imported_by(path: Path) -> set[str]:
    """Return every `btclib.<unit>` one source file's own imports name.

    `from btclib import bip32`, `from btclib.bip32 import BIP32Key` and
    `import btclib.bip32.bip32` name the same unit three ways, and each is
    read: the `from` module with each of its aliases covers the first two,
    and an `import` is a complete dotted name on its own.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return {
        name
        for name in names
        if any(name == f"btclib.{u}" or name.startswith(f"btclib.{u}.") for u in _UNITS)
    }


def test_the_stale_unit_scan_finds_a_planted_import(tmp_path: Path) -> None:
    """`_stale_units_imported_by` reports each spelling of a stale import.

    The real tree has no such import -- that is what the test below
    measures -- so this is the only green run that crosses the branch
    reporting one, and a scan that stopped seeing a spelling would leave
    the test below green over a tree that has it.
    """
    planted = tmp_path / "planted.py"
    planted.write_text(
        "from btclib import b58, bip32\n"
        "from btclib.descriptors.miniscript import parse\n"
        "import btclib.bip32.der_path\n"
        "from btclib.script import taproot\n"
        "from bip32_descriptors import descriptors\n",
        encoding="utf-8",
    )
    assert _stale_units_imported_by(planted) == {
        "btclib.bip32",
        "btclib.bip32.der_path",
        "btclib.descriptors.miniscript",
        "btclib.descriptors.miniscript.parse",
    }


@pytest.mark.parametrize("root", ["src", "tests"])
def test_no_module_imports_a_unit_by_btclibs_name(root: str) -> None:
    """Every import of a unit of this package names this package.

    Static rather than a probe of `sys.modules`: an older btclib still
    carries the units, so a stale import resolves and runs there, and
    nothing at run time says which of the two copies answered. The sources
    are the checkout's, which is what the suite runs: the package is
    installed editable.
    """
    base = Path(__file__).resolve().parents[1] / root
    stale = {
        str(path.relative_to(base)): found
        for path in sorted(base.rglob("*.py"))
        if (found := _stale_units_imported_by(path))
    }
    assert not stale


# what each unit may import of the package besides itself, as
# ARCHITECTURE.md describes
_ALLOWED_UNITS = {
    "bip32": frozenset(),
    "descriptors": frozenset({"bip32"}),
}


def _units_imported_by(path: Path, package: str) -> set[str]:
    """Return every unit of `bip32_descriptors` one source file's imports reach.

    A unit is the first name below `bip32_descriptors`: a top-level module or a
    subpackage. `package` is the dotted package the file sits in, which a
    relative import is resolved against. `from bip32_descriptors import bip32`
    and `from . import bip32` in the root name the unit as an alias, so the
    aliases are read where the module is the root itself, and `import
    bip32_descriptors` alone is reported as the root. Imports inside a function
    are found too, `ast.walk` visiting every node.
    """
    units: set[str] = set()
    for module, aliases in _imports_of(path, package):
        parts = module.split(".")
        if parts[0] != "bip32_descriptors":
            continue
        if len(parts) > 1:
            units.add(parts[1])
        elif aliases:
            units.update(aliases)
        else:
            units.add("bip32_descriptors")
    return units


def _imports_of(path: Path, package: str) -> Iterator[tuple[str, list[str]]]:
    """Yield each module one source file imports, and the names it takes.

    An `import` takes none, and `_units_imported_by` says what `package`
    is.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, []
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                parts = package.split(".")
                base = ".".join(parts[: len(parts) - node.level + 1])
                module = f"{base}.{module}" if module else base
            yield module, [alias.name for alias in node.names]


def _package_of(path: Path, src: Path) -> str:
    """Return the dotted package a source file under `src` sits in."""
    return ".".join(path.relative_to(src).parent.parts)


def _layer_violations(src: Path) -> dict[str, set[str]]:
    """Return, per file of a constrained unit, the units it may not import."""
    violations: dict[str, set[str]] = {}
    for path in sorted((src / "bip32_descriptors").rglob("*.py")):
        unit = path.relative_to(src).parts[1].removesuffix(".py")
        if unit not in _ALLOWED_UNITS:
            continue
        found = _units_imported_by(path, _package_of(path, src))
        if forbidden := found - _ALLOWED_UNITS[unit] - {unit}:
            violations[path.relative_to(src).as_posix()] = forbidden
    return violations


def _plant(src: Path, relative: str, line: str) -> None:
    """Write a module with one import line under a fake `src`."""
    path = src / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(line + "\n", encoding="utf-8")


@pytest.mark.parametrize(
    "relative, line, forbidden",
    [
        (
            "bip32_descriptors/bip32/bip32.py",
            "from bip32_descriptors.descriptors import parse",
            {"descriptors"},
        ),
        (
            "bip32_descriptors/bip32/bip32.py",
            "def f():\n    import bip32_descriptors.descriptors.miniscript",
            {"descriptors"},
        ),
        (
            "bip32_descriptors/bip32/bip32.py",
            "from .. import descriptors",
            {"descriptors"},
        ),
        (
            "bip32_descriptors/bip32/der_path.py",
            "from ..descriptors.descriptors import Descriptor",
            {"descriptors"},
        ),
        (
            "bip32_descriptors/descriptors/descriptors.py",
            "import bip32_descriptors",
            {"bip32_descriptors"},
        ),
        (
            "bip32_descriptors/descriptors/miniscript.py",
            "from bip32_descriptors import psbt",
            {"psbt"},
        ),
    ],
)
def test_the_layer_scan_finds_a_planted_import(
    tmp_path: Path, relative: str, line: str, forbidden: set[str]
) -> None:
    """`_layer_violations` reports each spelling of an upward import.

    The real tree has none, so only this test exercises a report.
    """
    _plant(tmp_path, relative, line)
    assert _layer_violations(tmp_path) == {relative: forbidden}


@pytest.mark.parametrize(
    "relative, line",
    [
        ("bip32_descriptors/bip32/bip32.py", "from .der_path import DerPath"),
        ("bip32_descriptors/bip32/bip32.py", "from btclib.script import x"),
        ("bip32_descriptors/descriptors/descriptors.py", "from ..bip32 import derive"),
        (
            "bip32_descriptors/descriptors/miniscript.py",
            "from .key_expression import x",
        ),
        ("bip32_descriptors/__init__.py", "from bip32_descriptors import descriptors"),
    ],
)
def test_the_layer_scan_admits_the_allowed_imports(
    tmp_path: Path, relative: str, line: str
) -> None:
    """`_layer_violations` leaves a unit's own and allowed imports alone."""
    _plant(tmp_path, relative, line)
    assert _layer_violations(tmp_path) == {}


def test_each_unit_imports_only_the_units_below_it() -> None:
    """Keep `bip32` and `descriptors` to `_ALLOWED_UNITS`."""
    assert _layer_violations(Path(bip32_descriptors.__path__[0]).parent) == {}


# the distributions `dependencies` names, by their import names, and the
# bindings of the `secp256k1` extra, which `bip32.bip32` imports in a `try`
_DECLARED = frozenset(
    {"btclib", "ecc", "typing_extensions", "btclib_secp256k1", "bip32_descriptors"}
)


def _top_level_imports(source: str) -> set[str]:
    """Return the first component of every name one module's imports name.

    Relative imports name this package, so they are recorded as it.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(
                "bip32_descriptors" if node.level else (node.module or "").split(".")[0]
            )
    return names


def _undeclared(names: set[str]) -> list[str]:
    """Return the names neither the standard library nor `_DECLARED` holds."""
    return sorted(names - sys.stdlib_module_names - _DECLARED)


def test_the_dependency_scan_finds_a_planted_import() -> None:
    """The scan names each form, and the check refuses what is undeclared."""
    source = (
        "import hashlib\nimport btclib.utils\nfrom btclib_wallet import psbt\n"
        "from . import bip32\nfrom bip39_slip39 import bip39\n"
    )
    names = _top_level_imports(source)
    assert names == {
        "hashlib",
        "btclib",
        "btclib_wallet",
        "bip32_descriptors",
        "bip39_slip39",
    }
    assert _undeclared(names) == ["bip39_slip39", "btclib_wallet"]


def test_no_module_imports_an_undeclared_distribution() -> None:
    """Every file of the package, read rather than imported.

    An import inside a function or behind `TYPE_CHECKING` is one no
    interpreter runs at import, and it would still fail the day it ran.
    """
    root = Path(bip32_descriptors.__path__[0])
    found = {
        path.relative_to(root).as_posix(): _undeclared(
            _top_level_imports(path.read_text(encoding="utf-8"))
        )
        for path in sorted(root.rglob("*.py"))
    }
    assert "descriptors/miniscript.py" in found
    assert not {file: names for file, names in found.items() if names}


def test_btclib_imports_nothing_of_this_package() -> None:
    """No module of the installed `btclib` imports `bip32_descriptors`.

    The units were cut out of `btclib`, which must not depend on the
    package that now holds them.
    """
    spec = importlib.util.find_spec("btclib")
    assert spec is not None
    assert spec.submodule_search_locations is not None
    (base,) = (Path(location) for location in spec.submodule_search_locations)
    found = {
        str(path.relative_to(base)): units
        for path in sorted(base.rglob("*.py"))
        if (
            units := _units_imported_by(
                path, ".".join(("btclib", *path.relative_to(base).parent.parts))
            )
        )
    }
    assert not found
