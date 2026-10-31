# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The classes a refusal of this package may leave as, and their test.

btclib's own, and ecc's wherever an argument reaches that package,
the curve arithmetic and the schemes on it being ecc's (issue
btclib-org/btclib#2282). ecc's classes are each beside the same
built-in as btclib's of its kind and none of them a `BTClibException`, so
a test holding a function to the contract names one of the tuples below
rather than btclib's class alone. A bare built-in is in none of them,
which is what the test below asserts.

ecc's classes are imported from `ecc.exceptions`; `btclib.exceptions`
binds none of them.

Shared test code belongs in `tests/__init__.py`; these tuples are here
rather than there because this module is what tests them.
"""

from __future__ import annotations

import pytest
from btclib.exceptions import (
    BTClibException,
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
)
from ecc.exceptions import (
    EccException,
    EccRuntimeError,
    EccTypeError,
    EccValueError,
)

# the package btclib delegates its curve arithmetic to, as it is imported
ECC_PACKAGE = "ecc"
VALUE_ERRORS = (BTClibValueError, EccValueError)
TYPE_ERRORS = (BTClibTypeError, EccTypeError)
RUNTIME_ERRORS = (BTClibRuntimeError, EccRuntimeError)
# the base of each family, for a test whose contract is the base
EXCEPTIONS = (BTClibException, EccException)


@pytest.mark.parametrize(
    "family, own, built_in",
    [
        pytest.param(VALUE_ERRORS, BTClibValueError, ValueError, id="value"),
        pytest.param(TYPE_ERRORS, BTClibTypeError, TypeError, id="type"),
        pytest.param(RUNTIME_ERRORS, BTClibRuntimeError, RuntimeError, id="runtime"),
        pytest.param(EXCEPTIONS, BTClibException, Exception, id="base"),
    ],
)
def test_a_family_holds_the_libraries_classes_and_no_bare_built_in(
    family: tuple[type[Exception], ...],
    own: type[Exception],
    built_in: type[Exception],
) -> None:
    """The class of btclib is in it, of its kind, and a bare one is not.

    The last is the half that makes the tuple a contract: a test naming
    the family still fails on the built-in leaking from underneath.
    """
    assert own in family
    assert all(issubclass(member, built_in) for member in family)
    assert not issubclass(built_in, family)
