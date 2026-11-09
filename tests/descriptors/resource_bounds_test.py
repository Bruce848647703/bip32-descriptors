# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The sizes and bounds `miniscript.py` computes, on the inputs that pin them.

Issue btclib-org/bip32-descriptors#41. Each case here has another answer
where one operator of the script-size, witness-size, stack or key-count
computations is changed. The mutation profile
`.github/mutation/descriptors.toml` names the operators of those
computations that no input can tell apart.
"""

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors.miniscript import TAPSCRIPT, from_script, parse

K = [PrvKeyData(i).pub.sec.hex() for i in range(1, 6)]


def test_the_largest_tapscript_from_script_reads() -> None:
    """A tapscript is refused for its length one byte past 329482.

    At 329482 bytes it is read, and refused for what it holds.
    """
    with pytest.raises(BTClibValueError, match="closes no fragment"):
        from_script(b"\xff" * 329482, TAPSCRIPT)
    with pytest.raises(BTClibValueError, match="script too large"):
        from_script(b"\xff" * 329483, TAPSCRIPT)


def test_the_script_size_of_a_multi_a_with_one_key() -> None:
    """`script_size` is the length of the script `script` writes."""
    node = parse(f"multi_a(1,{K[0]})", TAPSCRIPT)
    assert node.script_size == len(node.script()) == 36


def test_the_witness_of_a_multisig() -> None:
    """A multi() dissatisfaction and a multi_a() satisfaction, in bytes.

    multi(2,...) is dissatisfied by three empty pushes, the dummy element
    and one per signature it asks for, before multi(3,...) is satisfied by
    its dummy
    and three 73-byte signature pushes. multi_a(1,...) of three keys is
    satisfied by one 66-byte signature push and two empty pushes.
    """
    node = parse(f"or_d(multi(2,{K[0]},{K[1]}),multi(3,{K[2]},{K[3]},{K[4]}))")
    assert node.max_witness_size == 3 + 1 + 3 * 73
    node = parse(f"multi_a(1,{K[0]},{K[1]},{K[2]})", TAPSCRIPT)
    assert node.max_witness_size == 66 + 2


def test_a_dissatisfied_thresh_costs_its_dissatisfactions() -> None:
    """The stack a thresh() dissatisfaction leaves is not its satisfaction's.

    The or_i() is dissatisfied by two elements and satisfied by up to
    three, so dissatisfying the thresh() and satisfying pk() needs three
    elements, as satisfying the thresh() does.
    """
    expression = f"thresh(1,or_i(pk({K[0]}),and_v(v:pk({K[1]}),pk({K[2]}))))"
    node = parse(f"or_d({expression},pk({K[3]}))")
    assert node.max_stack_items == 3
    assert node.max_exec_stack_items == 3


def test_the_stack_peaks_above_the_witness() -> None:
    """`max_exec_stack_items` counts what the script pushes on the witness.

    A multi_a() of three keys takes three witness elements, and its first
    key is pushed on top of them.
    """
    node = parse(f"multi_a(1,{K[0]},{K[1]},{K[2]})", TAPSCRIPT)
    assert node.max_stack_items == 3
    assert node.max_exec_stack_items == 4


def test_a_multi_a_takes_its_most_keys() -> None:
    """`multi_a()` holds as many keys as BIP387 allows, and no more."""
    x_only = K[0][2:]
    node = parse(f"multi_a(1,{','.join([x_only] * 999)})", TAPSCRIPT)
    assert len(node.keys) == 999
    with pytest.raises(BTClibValueError, match="invalid number of keys"):
        parse(f"multi_a(1,{','.join([x_only] * 1000)})", TAPSCRIPT)
