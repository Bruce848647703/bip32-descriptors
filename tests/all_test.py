# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for what the package exports.

Every module and package of bip32_descriptors declares an `__all__`, at every
depth: a name is public here because a list says so, not because it
happens to lack a leading underscore. A list per module is a list per
module to keep true, and the policy tests below are what keeps it, rather
than a reviewer noticing.

`bip32_descriptors.__all__` is the root of that tree, and one of those tests
walks it from the root, into every module-valued export, down to a node
that has none.

These tests are written against the names rather than the counts, so that a
deliberate addition is one line here and an accidental one is a failure.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator
from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules
from types import ModuleType

import pytest

import bip32_descriptors
from tests import module_names

# what a module defines without a leading underscore and deliberately does
# not export, with the reason beside the list in each module's docstring.
# A name added here is a decision; a name that has to be added here to make
# the suite pass is one that was about to become public by accident
UNEXPORTED = {
    "bip32_descriptors": ["name"],
    "bip32_descriptors.descriptors.descriptors": [
        "CHECKSUM_CHARSET",
        "GENERATOR",
        "INPUT_CHARSET",
    ],
}


# every direct child module of every package, on the side of the decision
# its parent made about it: `groups` is what the parent publishes, and
# `unpublished` is what it deliberately does not -- a module holding names
# the parent re-exports flat, or an implementation nothing outside the
# package calls.
#
# The two together are asserted to be the package's whole directory, which
# is the half a table of the published edges alone cannot check: a child
# module added and left out of its parent's `__all__` changes neither the
# list nor the edges. Both sides are recorded, so a module added to a
# package fails the suite until somebody says which of the two it is.
#
# bip32_descriptors itself is not here: its children are the top-level modules,
# and test_the_root_publishes_every_top_level_module asserts the same
# partition against the directory with nothing on the unpublished side
CHILD_MODULES = {
    "bip32_descriptors.bip32": {
        "groups": [],
        "unpublished": ["bip32", "der_path", "key_origin"],
    },
    "bip32_descriptors.descriptors": {
        "groups": ["miniscript"],
        "unpublished": ["descriptors", "key_expression"],
    },
}


def public_name(dotted: str) -> bool:
    """Whether every component of a dotted module name is public."""
    return not any(part.startswith("_") for part in dotted.split("."))


def library_modules() -> list[ModuleType]:
    """Return every module and package of the library, private ones out.

    Found rather than listed: one added to bip32_descriptors is one these
    tests ask about, and the walk is the whole tree rather than the top
    level, the packages having submodules a caller reaches by name --
    `bip32_descriptors.descriptors.miniscript`.

    Anything under a private name is out: a module whose name opens with
    an underscore is not part of the surface, so what is public *in* it is
    not reachable by any spelling a caller is offered.

    The walk is `tests/__init__.py`'s, which is where the sites asking a
    question of every module take it from; what is this file's own is the
    filter and the import.
    """
    return [import_module(name) for name in module_names() if public_name(name)]


def module_scope(body: Iterable[ast.stmt]) -> Iterator[ast.stmt]:
    """Yield the statements a module executes in its own namespace.

    Every statement of the body, and then inside each compound one, which
    runs at module scope too: an import in a module-level `try`, `if`,
    `with`, `for`, `while` or `match` binds a global exactly as a
    top-level one does, and `try: from dependency import PublicType` is
    how an optional import is written. A function or a class opens a scope
    of its own, so an import in either binds nothing here, and neither is
    descended into.
    """
    for node in body:
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        nested: list[ast.stmt] = []
        for field in ("body", "orelse", "finalbody"):
            statements = getattr(node, field, None)
            if isinstance(statements, list):
                nested += statements
        for clause in (*getattr(node, "handlers", ()), *getattr(node, "cases", ())):
            nested += clause.body
        yield from module_scope(nested)


def imported_names_in(source: str) -> set[str]:
    """Return the names the import statements of one module source bind."""
    return {
        alias.asname or alias.name.split(".")[0]
        for node in module_scope(ast.parse(source).body)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }


def imported_names(module: ModuleType) -> set[str]:
    """Return the names a module's own import statements bind.

    Read off the source rather than the module object, there being nothing
    in a module's namespace to say how a name got there.
    """
    return imported_names_in(Path(str(module.__file__)).read_text(encoding="utf-8"))


def defined_public_names(module: ModuleType) -> set[str]:
    """Return the public names a module defines itself.

    Everything in its namespace, minus the underscored, minus what it
    imported, minus the modules: a submodule becomes an attribute of its
    package as soon as anything imports it, so `bip32_descriptors.bip32` is in
    `vars(bip32_descriptors)` by the time any test runs.
    """
    imported = imported_names(module)
    return {
        name
        for name, value in vars(module).items()
        if not name.startswith("_")
        and name not in imported
        and not isinstance(value, ModuleType)
    }


def test_every_exported_name_exists() -> None:
    """An `__all__` entry that names nothing is a broken `import *`.

    Every module and package of the library, found rather than listed: one
    added to bip32_descriptors is one this checks, where a list here would
    be one more thing to keep true, and a module missing `__all__` is what
    this catches that a fixed list cannot. The whole tree is walked, which
    imports every module of the library; tests/imports_test.py does that
    deliberately and one module at a time, for the cycle a bulk import
    hides, and this one asks a question that needs them all loaded.

    An empty list is a legitimate answer, and the assertion says when: a
    module with nothing public of its own -- a package `__init__` that only
    re-exports, or a module that is all private helpers -- declares `[]`
    rather than nothing, so that the declaration is there to read.
    """
    modules = library_modules()
    # the root, the two packages and their modules: a walk that found only
    # the root would satisfy the loop below
    assert len(modules) > 3, f"only {len(modules)} modules found"
    for module in modules:
        names = getattr(module, "__all__", None)
        assert names is not None, f"{module.__name__} declares no __all__"
        assert names or not defined_public_names(module), (
            f"{module.__name__} declares an empty __all__ and defines"
            f" {sorted(defined_public_names(module))}"
        )
        for name in names:
            assert hasattr(module, name), f"{module.__name__}.{name} is not there"


def test_no_module_exports_a_name_it_imported() -> None:
    """A module exports what it defines, which is what packages do not.

    A package's `__all__` is re-export by design --
    `bip32_descriptors.descriptors` names `Descriptor`, defined a module
    away -- and for a module the same thing is a leak: `Octets` reached
    through `bip32_descriptors.bip32.bip32` is that module's import
    section, where `btclib.alias.Octets` is the name a caller wants. A
    module with a reason to re-export something is a conversation to have
    with this test, not around it.

    No module of this package re-exports, so there is no table of
    exceptions to keep.
    """
    for module in library_modules():
        if hasattr(module, "__path__"):  # a package re-exports for a living
            continue
        imported = imported_names(module)
        leaked = {name for name in module.__all__ if name in imported}
        assert not leaked, f"{module.__name__} re-exports {sorted(leaked)}"


def test_the_export_tree_is_walkable_to_its_leaves() -> None:
    """Every module reachable through `__all__` declares one of its own.

    A module named in a parent's list and declaring nothing is a node a
    walker arrives at and cannot descend from -- which is what this asks
    about, transitively from `bip32_descriptors` down, following exports
    rather than the file tree.

    A module-valued export is also checked to be a submodule of the module
    exporting it: `bip32_descriptors.descriptors.miniscript` is
    `bip32_descriptors.descriptors`'s to publish, and a module from
    somewhere else in the tree would make the path a caller reads off the
    walk name something the import does not.
    """
    seen = {bip32_descriptors.__name__}
    frontier: list[ModuleType] = [bip32_descriptors]
    while frontier:
        module = frontier.pop()
        names = getattr(module, "__all__", None)
        assert names is not None, f"{module.__name__} declares no __all__"
        for name in names:
            value = getattr(module, name)
            if not isinstance(value, ModuleType):
                continue
            assert value.__name__ == f"{module.__name__}.{name}", (
                f"{module.__name__} exports {name}, which is {value.__name__}"
            )
            # the set is the frontier's filter rather than a check on the
            # way out: one module reachable from two parents would be
            # walked twice, and nothing here is -- which is what the
            # `no branch` says, the tree being one and the filter being
            # what would keep a future re-export from doubling the walk
            if value.__name__ not in seen:  # pragma: no branch -- the tree is one
                seen.add(value.__name__)
                frontier.append(value)
    # the root, the packages and the modules they publish: a walk that
    # stopped at the root would satisfy the loop above
    assert len(seen) > 3, f"the export tree walk reached {len(seen)} modules"


def test_every_child_module_is_a_group_or_deliberately_not() -> None:
    """Each package's children are partitioned, and the parts are recorded.

    Two directions, and the second is the one nothing else here can see.
    The published side is the exact module-valued exports, so a submodule
    imported into an `__init__` for one name and left in `__all__` by habit
    is a command group nobody decided on. The union of the two sides is the
    package's whole directory, so a child module added and left out of the
    list -- which changes neither the list nor the edges -- fails until
    somebody writes down which side it is on.

    The empty published side is as deliberate as the rest: `bip32` offers
    a flat surface and no group. Every package has to
    be in the table, so a new one is a decision rather than a silent pair of
    empty lists.
    """
    packages = [module for module in library_modules() if hasattr(module, "__path__")]
    assert len(packages) == len(CHILD_MODULES) + 1, (
        "bip32_descriptors itself plus every package CHILD_MODULES records"
    )
    for package in packages:
        if package.__name__ == "bip32_descriptors":  # the directory is its assertion
            continue
        assert package.__name__ in CHILD_MODULES, f"{package.__name__} is not recorded"
        recorded = CHILD_MODULES[package.__name__]
        edges = sorted(
            name
            for name in package.__all__
            if isinstance(getattr(package, name), ModuleType)
        )
        assert edges == recorded["groups"], f"{package.__name__} publishes {edges}"
        children = sorted(
            child
            for _, child, _ in iter_modules(package.__path__)
            if public_name(child)
        )
        assert sorted([*recorded["groups"], *recorded["unpublished"]]) == children, (
            f"{package.__name__}'s children are {children}"
        )


def test_the_root_publishes_every_top_level_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`bip32_descriptors.__all__` is the root: no top-level module is missing.

    The list is written out rather than discovered -- a declaration is a
    list somebody edited -- and this is the other half of that: a module
    added to `src/bip32_descriptors/` and not published here would be a name
    `getattr(bip32_descriptors, ...)` cannot answer, where a discovered list
    would have published it without anybody deciding to.
    """
    top_level = sorted(
        name
        for _, name, _ in iter_modules(bip32_descriptors.__path__)
        if public_name(name)
    )
    assert sorted(bip32_descriptors.__all__) == top_level
    # and each answers on a package that has not bound it yet, which is
    # what the module __getattr__ is for. The suite has imported both
    # subpackages by now, so the binding the import left is removed first;
    # monkeypatch puts it back
    for name in top_level:
        monkeypatch.delattr(bip32_descriptors, name)
        assert getattr(bip32_descriptors, name).__name__ == f"bip32_descriptors.{name}"


def test_the_root_answers_only_for_what_it_publishes() -> None:
    """A name outside the list raises, as an attribute of anything does.

    What the list decides is what this package imports *for* a caller: a
    submodule is an attribute of its package once anything imports it,
    whatever the list says.
    """
    with pytest.raises(AttributeError, match="has no attribute 'bip33'"):
        _ = bip32_descriptors.bip33
    # dir() answers the published tree, not only what has been imported
    assert set(bip32_descriptors.__all__) <= set(dir(bip32_descriptors))


def test_the_import_scan_reaches_a_nested_import() -> None:
    """A module-level `try` binds a global, and a function body does not.

    The check above is only as good as this scan: an optional dependency
    imported in a `try` and named in `__all__` is exactly the re-export it
    refuses, and reading `tree.body` alone would have let it through.
    """
    source = (
        "try:\n"
        "    from dependency import PublicType\n"
        "except ImportError:\n"
        "    from fallback import PublicType\n"
        "if TYPE_CHECKING:\n"
        "    from typing import Never\n"
        "for _name in ():\n"
        "    import late\n"
        "def f():\n"
        "    import local\n"
        "class C:\n"
        "    import attribute\n"
    )
    assert imported_names_in(source) == {"PublicType", "Never", "late"}


def test_nothing_becomes_public_by_accident() -> None:
    """Every public name is exported or recorded as kept out.

    This is the check the underscore convention cannot make: a helper that
    grows into a name callers depend on does so silently, where a package
    takes an edit to a list. `UNEXPORTED` is that edit for modules, and
    `sorted` is what the failure reads as -- the names not accounted for,
    against the ones that are.
    """
    for module in library_modules():
        kept_out = sorted(defined_public_names(module) - set(module.__all__))
        assert kept_out == UNEXPORTED.get(module.__name__, []), (
            f"{module.__name__} defines public names that are neither"
            f" exported nor recorded in UNEXPORTED: {kept_out}"
        )
