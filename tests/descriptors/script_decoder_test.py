# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `from_script` answers on the scripts that pin its decoder.

Issue btclib-org/bip32-descriptors#41. Each case here has another answer
where one operator of the script decoder in `miniscript.py` is changed.
The mutation profile `.github/mutation/descriptors.toml` names the
operators of the decoder that no input can tell apart.

A refusal is compared whole: these mutants refuse the same scripts, but
for another reason, or with another exception.
"""

import re

import pytest
from btclib.exceptions import BTClibValueError
from btclib.key import PrvKeyData

from bip32_descriptors.descriptors.miniscript import from_script, parse

K = [PrvKeyData(i).pub.sec.hex() for i in range(1, 3)]


@pytest.mark.parametrize(
    "script, message",
    [
        # one byte pushed by OP_PUSHDATA1, OP_PUSHDATA2 and OP_PUSHDATA4:
        # the length after the op code is one, two and four bytes long
        ("4c01aa", "non-minimal push of 1 bytes: op code 0x4c"),
        ("4d0100aa", "non-minimal push of 1 bytes: op code 0x4d"),
        ("4e01000000aa", "non-minimal push of 1 bytes: op code 0x4e"),
    ],
)
def test_a_pushdata_op_code_is_read_with_its_data(script: str, message: str) -> None:
    """The refusal counts the bytes pushed, after the length bytes."""
    with pytest.raises(BTClibValueError, match=f"^{re.escape(message)}$"):
        from_script(script)


def test_an_op_code_below_op_endif_closes_no_fragment() -> None:
    """OP_NOP sorts below OP_ENDIF and is no OP_ENDIF."""
    message = "not a miniscript: op code 0x61 closes no fragment"
    with pytest.raises(BTClibValueError, match=f"^{re.escape(message)}$"):
        from_script("61")


def test_a_hash160_comparison_without_op_dup_is_no_pk_h() -> None:
    """Four of the five op codes the decoder reads a pk_h() as are no pk_h().

    The script is OP_HASH160, the hash and OP_EQUALVERIFY, which the
    decoder splits into OP_EQUAL and OP_VERIFY. It looks for OP_DUP only
    where five op codes are left, and refuses the script as one that
    closes no fragment.
    """
    message = "not a miniscript: op code 0x87 closes no fragment"
    with pytest.raises(BTClibValueError, match=f"^{re.escape(message)}$"):
        from_script("a914" + "00" * 20 + "88")


def test_a_thresh_read_after_another_expression() -> None:
    """A thresh() takes its own branches from what is built, and no more.

    In ``and_v(X,Y)`` the script is read from its end, so Y is built
    before the thresh() in X is.
    """
    node = parse(f"and_v(v:thresh(1,pk({K[0]})),pk({K[1]}))")
    assert from_script(node.script()) == node


def test_the_innermost_ill_typed_fragment_is_named() -> None:
    """The fragment refused is the one built without a type, not its parent.

    ``c:1`` is built after ``pk()``, the script being read from its end.
    """
    with pytest.raises(BTClibValueError, match="^ill-typed miniscript: c: over"):
        from_script(f"51ad21{K[1]}ac")
