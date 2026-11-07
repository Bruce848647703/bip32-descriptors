# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core expands each mix of the unit test of this name as `parse` does.

`tests/descriptors/multipath_hardening_test.py` says what the mixes are
and holds `multipath_descriptors` to what Core's parser reads; this one
asks the node, with the master key of BIP32's first test vector spelled
for regtest.

Skipped unless `BTCLIB_INTEGRATION=1` and a `bitcoind` is available; the
conftest beside this says which switch was off.
"""

from __future__ import annotations

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

from bip32_descriptors.descriptors import add_checksum, multipath_descriptors, parse
from tests import vector_id
from tests.descriptors.multipath_hardening_test import MIXES, mixed

pytestmark = pytest.mark.integration

TPRV = (
    "tprv8ZgxMBicQKsPeDgjzdC36fs6bMjGApWDNLR9erAXMs5skhMv36j9MV5ecvfavji5khqjWaWS"
    "FhN3YcCUUdiKH6isR4Pwy3U5y5egddBr16m"
)


@pytest.mark.parametrize(
    "mix",
    [pytest.param(mix, id=vector_id(i, *mix)) for i, mix in enumerate(MIXES)],
)
def test_core_expands_the_mix_as_parse_writes_it(
    node: BitcoinCoreRpcClient, mix: tuple[str, ...]
) -> None:
    """`getdescriptorinfo`'s ``multipath_expansion`` of the mix."""
    descriptor = mixed(TPRV, mix)
    core = node.call("getdescriptorinfo", [descriptor])["multipath_expansion"]
    assert [
        add_checksum(str(parse(x, "regtest")))
        for x in multipath_descriptors(descriptor, "regtest")
    ] == core
