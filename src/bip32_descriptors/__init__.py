# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The bip32_descriptors package: what it publishes, and the version metadata.

BIP32 hierarchical deterministic keys, key origins and derivation paths,
and output script descriptors with miniscript, built on the protocol
package `btclib` and the curve package `ecc`. The dependency points one
way: this package imports them, and nothing in either imports this one.

`__all__` here is the root of the package's public tree: the packages a
caller reaches from this name. Each of them declares its own `__all__`,
so a walk that starts here has a declared surface at every node -- which
is why the list is not `pkgutil.iter_modules`: discovery would answer
the file tree, and a module added to the directory would publish itself
rather than being published.

`name` is not in it, nor are the metadata dunders. `name` is the
distribution's name and not a member of the tree, `__version__` bound by
a star import would overwrite the importing module's own, and each is
still an attribute here: `bip32_descriptors.__version__` is how a caller
reads the version and `bip32_descriptors.name` how it reads the name.

Nothing is imported eagerly. A package is imported when it is first asked
for, through the `__getattr__` at the bottom of this file, so `import
bip32_descriptors` is the metadata lookup below and nothing else, and the
import graph keeps its shape: importing every module here would put the
whole package in `sys.modules` before any single module of it could be
imported first, which is the situation tests/imports_test.py exists to
make impossible.

What that costs is worth stating: mypy reads a module-level `__getattr__`
as a promise that any attribute may exist, so `bip32_descriptors.bip23` is
`Any` to it and a misspelling on this package is a runtime
`AttributeError` rather than a reported error. The spellings a caller
actually writes -- `from bip32_descriptors import bip32`, `import
bip32_descriptors.bip32`, `from bip32_descriptors.bip32 import derive`
-- resolve against the real modules and stay checked.
"""

from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from types import ModuleType

name = "bip32-descriptors"
try:
    __version__ = version("bip32-descriptors")
except PackageNotFoundError:
    # a source tree with no metadata beside it: git clone and import, or
    # read the docs, which builds without installing this package. Any
    # number here would be a guess, and reading pyproject.toml back is not
    # the way to stop guessing: the file is not in the wheel. Importing has
    # to keep working, so the version says it does not know
    __version__ = "unknown"

__all__ = [
    "bip32",
    "descriptors",
]


def __getattr__(published: str) -> ModuleType:
    """Import a published package the first time it is asked for.

    PEP 562: this runs only for a name the package does not already have,
    so it answers `bip32_descriptors.bip32` once and the import machinery's
    own attribute answers it from then on -- and it never runs for
    `import bip32_descriptors.bip32` or `from bip32_descriptors import
    bip32`, which import the subpackage themselves. What it makes work is
    `getattr(bip32_descriptors, "bip32")` on a fresh interpreter, which is
    how a walker reading `__all__` descends, and `from bip32_descriptors
    import *`, which asks for each name in the list.

    Anything not in `__all__` raises `AttributeError`, with the
    interpreter's own wording, so a typo reads as it does anywhere else.
    """
    if published in __all__:
        return import_module(f"{__name__}.{published}")
    raise AttributeError(f"module {__name__!r} has no attribute {published!r}")


def __dir__() -> list[str]:
    """Answer with the published tree beside what the package already has.

    `dir(bip32_descriptors)` consults this rather than the namespace, so
    without it a package not yet imported is missing from the completion a
    caller gets at an interactive prompt -- the same names `__getattr__`
    above will answer for.
    """
    return sorted({*__all__, *globals()})
