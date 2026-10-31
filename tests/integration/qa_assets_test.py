# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

r"""Bitcoin Core's descriptor fuzz corpus, replayed here.

`bitcoin-core/qa-assets` holds, per Core fuzz target, the inputs that
target's fuzzers found interesting. The `descriptor_parse` target reads
a descriptor, and the same input goes to this package's parser. The
parser may refuse it with an exception of the families
`tests/exception_family_test.py` holds; any other exception is a defect.
btclib-wallet replays the psbt directories in its own copy of this module.

Skipped unless `BTCLIB_QA_ASSETS` names a checkout:

    BTCLIB_QA_ASSETS=/path/to/qa-assets uv run pytest \
        tests/integration/qa_assets_test.py -n 0

`qa-assets.yml` runs it weekly against the default branch, sparse-checking
out the one directory.

`descriptor_parse` hands `parse` the input as text, one character per
octet, as Core's `std::string` holds it. Core parses each input twice,
with a checksum required and without; `parse` verifies a checksum where
there is one and requires none, which is the second, the first adding
only the refusal of an input without one. Core's target skips what
`IsTooExpensive` names, to spend its fuzzing time elsewhere; this replay
reads every input, and `qa-assets.yml`'s `timeout-minutes` bounds it.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bip32_descriptors.descriptors import descriptors
from tests.exception_family_test import EXCEPTIONS

pytestmark = pytest.mark.integration

_VARIABLE = "BTCLIB_QA_ASSETS"
_DIRECTORY = "descriptor_parse"


def test_corpus_is_refused_in_the_libraries_own_exceptions() -> None:
    """Every input is parsed, or refused in one of the families."""
    checkout = os.environ.get(_VARIABLE)
    if not checkout:
        # the prefix is what integration-bitcoind.yml exempts from its
        # check that the tests ran
        pytest.skip(f"set {_VARIABLE} to a bitcoin-core qa-assets checkout")
    inputs = sorted((Path(checkout) / "fuzz_corpora" / _DIRECTORY).iterdir())
    # a renamed or emptied directory would otherwise pass by replaying nothing
    assert inputs, f"{_DIRECTORY} holds no input"

    defects = []
    for path in inputs:
        data = path.read_bytes()
        try:
            descriptors.parse(data.decode("latin-1"))
        except EXCEPTIONS:
            pass
        except Exception as exc:  # noqa: BLE001 -- any other is the finding
            defects.append(f"{path.name} ({len(data)} octets): {exc!r}")
    assert not defects, "\n".join(
        ["descriptor_parse.cpp: Parse on the input as a string, on mainnet", *defects]
    )
