# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core's scripts for ``tr(musig(...)/<0;1>/*,sortedmulti_a(...))``.

Issue btclib-org/bip32-descriptors#198. The key path is the MuSig2
aggregate of the account xpubs, derived after aggregation as BIP328 says,
and the leaf is a ``sortedmulti_a`` over the same xpubs, each derived on
its own. `tests/_data/core_musig_sortedmulti_a.json` holds the receive
and change scriptPubKeys Bitcoin Core gives, and `tests/_data/README.md`
says how they were recorded.
"""

from __future__ import annotations

from typing import Any

import pytest

from bip32_descriptors.descriptors import multipath_descriptors, parse
from tests import load, vector_id

VECTORS: list[dict[str, Any]] = load("_data", "core_musig_sortedmulti_a.json")


@pytest.mark.parametrize(
    "vector",
    VECTORS,
    ids=[
        vector_id(i, f"{v['descriptor'].count('[') // 2}keys", f"k{v['threshold']}")
        for i, v in enumerate(VECTORS)
    ],
)
def test_core_scripts(vector: dict[str, Any]) -> None:
    """Each branch gives Core's scriptPubKey at each index Core recorded."""
    receive, change = multipath_descriptors(vector["descriptor"])
    for descriptor, scripts in (
        (receive, vector["receive"]),
        (change, vector["change"]),
    ):
        parsed = parse(descriptor)
        derived = [parsed.script_pub_key(i).script.hex() for i in range(len(scripts))]
        assert derived == scripts
