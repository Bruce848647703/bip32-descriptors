# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the descriptor package: the grammar, the keys, miniscript.

One test module per source module, with one gap on purpose:
`key_expression` has none of its own. BIP380's KEY expressions are read
through `parse` and written back through `str`, which is where
`descriptors_test` already exercises every spelling of one -- the origin,
the wildcards, the two hardening symbols, the WIF and the xprv -- and a
second module would be those same cases reached by a private function.
"""

# what Bitcoin Core, at the release integration-bitcoind.yml pins, names
# where its miniscript parser fails without naming a key, inside wsh() and
# in a tr() leaf. Core quotes the leaf: `parse` quotes it with what its
# brackets enclose written "...", and names it where that is too long
P2WSH_FAULT = "^A function is needed within P2WSH$"
TR_LEAF_FAULT = r"^('[^']{0,16}'|tr\(\) leaf) is not a valid descriptor function$"
# and inside sh() and at the top level, where Core reads as a tapscript
# miniscript an expression no descriptor function takes. At the top level
# the expression is quoted as a leaf is
P2SH_FAULT = "^A function is needed within P2SH$"
TOP_FAULT = "^('[^']{0,16}'|top-level expression) is not a valid descriptor function$"
# what Core names there for a miniscript its parser reads
MINISCRIPT_OUTSIDE = r"^Miniscript expressions can only be used in wsh or tr\.$"
