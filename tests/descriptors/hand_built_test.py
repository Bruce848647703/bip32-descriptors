# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Which of `parse`'s refusals a descriptor built by hand meets too.

A field of the wrong type, in every `Descriptor` fragment and in a
`MultiA`, leaves as a `BTClibTypeError`, and so does a `Miniscript`
node's fragment, threshold or digest of the wrong type, its keys given
as no tuple, or a key that is no `KeyExpression`. `TrDescriptor`,
`MiniscriptDescriptor`, `UnusedDescriptor`, `ShDescriptor`,
`WshDescriptor` and `MultiA` also refuse a value `parse` refuses, as a
`BTClibValueError`, and every fragment holding a key that `parse` reads
outside ``tr()`` and ``rawtr()``, and a P2WSH `Miniscript` node, refuses
a ``musig()`` one and an x-only one. Issues
btclib-org/bip32-descriptors#46, btclib-org/bip32-descriptors#85,
btclib-org/bip32-descriptors#103, btclib-org/bip32-descriptors#119,
btclib-org/bip32-descriptors#134, btclib-org/bip32-descriptors#141,
btclib-org/bip32-descriptors#150, btclib-org/bip32-descriptors#158,
btclib-org/bip32-descriptors#159, btclib-org/bip32-descriptors#161 and
btclib-org/bip32-descriptors#170.

`KeyExpression` refuses a `pub_key` that `parse` refuses, an x-only key
with no `pub_key`, a `pub_key` beside another key or a derivation, and a
hardening symbol BIP380 does not allow. Issues
btclib-org/bip32-descriptors#171 and btclib-org/bip32-descriptors#178.

It also refuses a ``musig()`` with an `xkey`, an `origin`, or a
participant that is a ``musig()``, x-only, uncompressed or no
`KeyExpression`. A path or a wildcard on a ``musig()`` is refused where
it hardens, or where a participant is not extended or is ranged. A
wildcard is refused unless it is None, 0 or 2**31. Issue
btclib-org/bip32-descriptors#179.

A ``musig()`` whose `hardening` is not h is refused too. Issue
btclib-org/bip32-descriptors#181.

`WshDescriptor` refuses an argument holding an uncompressed key, and
`ShDescriptor` a ``wsh()`` one. Both refuse an argument holding a
``musig()`` or an x-only key, and one whose script size or number of
``multi()`` keys `parse` refuses there. Issues
btclib-org/bip32-descriptors#175 and btclib-org/bip32-descriptors#233.

`ShDescriptor` refuses the argument of a ``wsh()`` argument as
`WshDescriptor` refuses it, a value of the wrong type included, and by
its function before its keys, as `parse` does. Issue
btclib-org/bip32-descriptors#242.

`WpkhDescriptor` and a P2WSH `Miniscript` node refuse an uncompressed
key, `MultiDescriptor` no keys, more than 20 keys and a k outside 1 to
n, and `RawPkhDescriptor` an empty hash and one of other than 20 bytes,
each with `parse`'s message. Issue btclib-org/bip32-descriptors#200.

`TrDescriptor` and `RawTrDescriptor` refuse an uncompressed key with
`parse`'s message. A `MultiA` and a tapscript `Miniscript` node refuse
one too, without the key's position in the ``tr()`` that `parse`
names. Issue btclib-org/bip32-descriptors#221.

`TrDescriptor` and `MiniscriptDescriptor` refuse a node holding a number
of keys its fragment does not take, with the node's own message, before
its text is written: a multisig of the other context for its context,
any other node for its number of keys. Where the descriptor also holds
an uncompressed key and the node's text can be written, the node is left
to the descriptor's text and sanity checks; where it passes them,
``tr()`` and ``wsh()`` refuse that key by its position, and a bare
`MiniscriptDescriptor` builds it. Issue btclib-org/bip32-descriptors#235.

A `MultiDescriptor` of more than three keys builds, and as a top-level
descriptor writes a text `parse` refuses: its docstring says why. Issue
btclib-org/bip32-descriptors#226.

`TrDescriptor` and `MiniscriptDescriptor` refuse an unpickled node
holding a key that is no `KeyExpression`, before they count its keys.
Issue btclib-org/bip32-descriptors#246. `TrDescriptor` refuses an
unpickled `MultiA` leaf whose keys are not a tuple of `KeyExpression`,
before it reads a key. Issue btclib-org/bip32-descriptors#249.

A `MiniscriptDescriptor` builds, and as a top-level descriptor writes a
text `parse` refuses: its docstring says why. Issue
btclib-org/bip32-descriptors#253.

`ShDescriptor` and `WshDescriptor` refuse an unpickled argument holding
a key that is no `KeyExpression`, after its function and before its
other keys, their number and its script size. Issue
btclib-org/bip32-descriptors#257.
"""

from __future__ import annotations

import pickle
import re
from collections.abc import Callable
from dataclasses import fields, replace
from typing import Any, cast

import pytest
from btclib import b58
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData
from btclib.script.limits import MAX_SCRIPT_SIZE
from ecc.exceptions import EccValueError
from typing_extensions import override

from bip32_descriptors.bip32 import derive, rootxprv_from_seed, xpub_from_xprv
from bip32_descriptors.descriptors import (
    Provider,
    add_checksum,
    at_index,
    infer_descriptor,
    miniscript,
    normalized,
    parse,
)
from bip32_descriptors.descriptors import descriptors as descriptors_module
from bip32_descriptors.descriptors.descriptors import (
    AddrDescriptor,
    ComboDescriptor,
    Descriptor,
    MiniscriptDescriptor,
    MultiA,
    MultiDescriptor,
    PkDescriptor,
    PkhDescriptor,
    RawDescriptor,
    RawLeaf,
    RawPkhDescriptor,
    RawTrDescriptor,
    ShDescriptor,
    TrDescriptor,
    UnusedDescriptor,
    WpkhDescriptor,
    WshDescriptor,
)
from bip32_descriptors.descriptors.key_expression import KeyExpression
from tests.descriptors import MINISCRIPT_OUTSIDE
from tests.secret_free import assert_secret_free

_X = PrvKeyData(1).pub.sec.hex()[2:]
_X2 = PrvKeyData(2).pub.sec.hex()[2:]
(_KEY,) = parse(f"tr({_X})").key_expressions
(_KEY2,) = parse(f"tr({_X2})").key_expressions
_C = PrvKeyData(3).pub.sec.hex()
_RANDOM_HEX = "7e3d796f1b20eb42c57e4f6a0c6ecaf1879529ae1ad154cebf0ed79035de2901"


def _nested(levels: int, *, right: bool) -> object:
    """Return a tree of `levels` branches, nested on one side."""
    tree: object = RawLeaf(b"\x51")
    for _ in range(levels):
        tree = (RawLeaf(b"\x51"), tree) if right else (tree, RawLeaf(b"\x51"))
    return tree


def test_a_raw_descriptor_is_built_from_bytes() -> None:
    """The control: the bytes `parse` gives, written back as hex."""
    assert str(RawDescriptor(b"\x51")) == "raw(51)"


@pytest.mark.parametrize("script", ["51", 0x51, bytearray(b"\x51")])
def test_a_raw_descriptor_script_of_another_type_is_refused(script: Any) -> None:
    """Hex text is not the script: `parse` is what reads hex."""
    err_msg = f"^invalid script type: {type(script).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        RawDescriptor(script)


@pytest.mark.parametrize("internal_key", [_X, 5, None, MultiA(1, (_KEY,))])
def test_a_tr_internal_key_of_another_type_is_refused(internal_key: Any) -> None:
    """The internal key is a KEY expression, never its text."""
    err_msg = f"^invalid internal key type: {type(internal_key).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        TrDescriptor(internal_key)


@pytest.mark.parametrize(
    "tree",
    [5, f"pk({_X})", [_KEY, _KEY2], (_KEY, (_KEY2, "pk")), ((5, _KEY), _KEY2)],
    ids=["int", "text", "list", "right-leaf", "left-leaf"],
)
def test_a_tr_tree_node_of_another_type_is_refused(tree: Any) -> None:
    """Every node of the tree, at any depth, a branch being a tuple."""
    with pytest.raises(BTClibTypeError, match="^invalid script tree node type: "):
        TrDescriptor(_KEY, tree)


@pytest.mark.parametrize("branch", [(), (_KEY,), (_KEY, _KEY2, _KEY)])
def test_a_tr_branch_of_other_than_two_subtrees_is_refused(branch: Any) -> None:
    """A third subtree is not dropped, and a lone one is not a branch."""
    err_msg = f"^a script tree branch takes two subtrees, {len(branch)} given$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        TrDescriptor(_KEY, (_KEY2, branch))


@pytest.mark.parametrize("right", [False, True])
def test_a_tr_tree_too_deep_is_refused_when_built(right: bool) -> None:
    """At 129 levels, and far past Python's recursion limit too.

    The deepest tree `parse` reads is built, and its text parses back.
    """
    deepest = TrDescriptor(_KEY, _nested(128, right=right))  # type: ignore[arg-type]
    assert parse(str(deepest)) == deepest
    for levels in (129, 5000):
        tree = _nested(levels, right=right)
        with pytest.raises(BTClibValueError, match="^script tree deeper than 128$"):
            TrDescriptor(_KEY, tree)  # type: ignore[arg-type]


def test_a_tr_miniscript_leaf_of_another_context_is_refused() -> None:
    """A leaf of the p2wsh context would commit to a 33-byte key.

    BIP342 reads that key as an unknown public key type, which any
    non-empty signature satisfies. Issue btclib-org/bip32-descriptors#111.
    """
    expression = f"and_v(v:pk({_C}),older(1))"
    leaf = miniscript.parse(expression, miniscript.TAPSCRIPT)
    assert parse(str(TrDescriptor(_KEY, leaf))) == TrDescriptor(_KEY, leaf)
    p2wsh = miniscript.parse(expression, miniscript.P2WSH)
    for tree in (p2wsh, (leaf, p2wsh), (p2wsh, _KEY2)):
        with pytest.raises(BTClibValueError, match="^not a tapscript node: and_v in "):
            TrDescriptor(_KEY, tree)


def _with_context(node: miniscript.Miniscript, context: object) -> None:
    """Give the node a context, as unpickling a stream holding it would.

    Unpickling skips `Miniscript`'s own checks, which refuse a node of an
    unknown context, or of a subexpression of another, when it is built.
    """
    object.__setattr__(node, "context", context)


def _unpickled(node: miniscript.Miniscript) -> miniscript.Miniscript:
    """Return a copy of the node, its subexpressions copied too."""
    copied: miniscript.Miniscript = pickle.loads(pickle.dumps(node))  # noqa: S301
    return copied


def test_a_tr_miniscript_leaf_holding_a_node_of_another_context_is_refused() -> None:
    """Each node writes its keys in its own context, whatever the root's."""
    expression = f"and_v(v:pk({_C}),older(1))"
    leaf = _unpickled(miniscript.parse(expression, miniscript.TAPSCRIPT))
    _with_context(leaf.subs[0], miniscript.P2WSH)
    with pytest.raises(BTClibValueError, match="^not a tapscript node: v: in P2WSH$"):
        TrDescriptor(_KEY, leaf)


# a fixed random value in each shape an unpickled node's context can
# take, and the spelling of it a refusal could print
_UNKNOWN_CONTEXTS = [
    (770907403214864877517, "770907403214864877517"),
    (bytes.fromhex(_RANDOM_HEX), bytes.fromhex(_RANDOM_HEX)),
    (_RANDOM_HEX, _RANDOM_HEX),
]


@pytest.mark.parametrize("context,spelling", _UNKNOWN_CONTEXTS)
def test_a_tr_leaf_of_an_unknown_context_is_refused(
    context: Any, spelling: str | bytes
) -> None:
    """A context the library does not define is not echoed, being any value."""
    leaf = _unpickled(miniscript.parse("1", miniscript.TAPSCRIPT))
    _with_context(leaf, context)
    err_msg = "^not a tapscript node: 1 in another context$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        TrDescriptor(_KEY, leaf)
    assert_secret_free(e.value, [spelling])


def test_a_wsh_miniscript_of_another_context_is_refused() -> None:
    """A tapscript node would write 32-byte keys into a P2WSH script.

    Issue btclib-org/bip32-descriptors#119.
    """
    expression = f"and_v(v:pk({_C}),older(1))"
    p2wsh = miniscript.parse(expression, miniscript.P2WSH)
    assert parse(f"wsh({expression})") == WshDescriptor(MiniscriptDescriptor(p2wsh))
    node = miniscript.parse(expression, miniscript.TAPSCRIPT)
    with pytest.raises(
        BTClibValueError, match="^not a P2WSH node: and_v in tapscript$"
    ):
        WshDescriptor(MiniscriptDescriptor(node))
    node = _unpickled(p2wsh)
    _with_context(node.subs[0], miniscript.TAPSCRIPT)
    with pytest.raises(BTClibValueError, match="^not a P2WSH node: v: in tapscript$"):
        MiniscriptDescriptor(node)


@pytest.mark.parametrize("context,spelling", _UNKNOWN_CONTEXTS)
def test_a_wsh_miniscript_of_an_unknown_context_is_refused(
    context: Any, spelling: str | bytes
) -> None:
    """A context the library does not define is not echoed, being any value."""
    node = _unpickled(miniscript.parse("1", miniscript.P2WSH))
    _with_context(node, context)
    if isinstance(context, str):
        error: type[Exception] = BTClibValueError
        err_msg = "^not a P2WSH node: 1 in another context$"
    else:
        error = BTClibTypeError
        err_msg = f"^invalid context type: {type(context).__name__}$"
    with pytest.raises(error, match=err_msg) as e:
        MiniscriptDescriptor(node)
    assert_secret_free(e.value, [spelling])


def test_a_node_of_another_context_and_an_unknown_fragment_is_not_echoed() -> None:
    """Its fragment is any value, so the refusal says "a node".

    In a ``tr()`` leaf and in a ``wsh()``. Issue
    btclib-org/bip32-descriptors#153.
    """
    leaf = _unpickled(miniscript.parse(f"pk({_X})", miniscript.TAPSCRIPT))
    object.__setattr__(leaf, "fragment", _RANDOM_HEX)
    _with_context(leaf, miniscript.P2WSH)
    with pytest.raises(
        BTClibValueError, match="^not a tapscript node: a node in P2WSH$"
    ) as e:
        TrDescriptor(_KEY, leaf)
    assert_secret_free(e.value, [_RANDOM_HEX])
    node = _unpickled(miniscript.parse(f"pk({_C})", miniscript.P2WSH))
    object.__setattr__(node, "fragment", _RANDOM_HEX)
    _with_context(node, miniscript.TAPSCRIPT)
    with pytest.raises(
        BTClibValueError, match="^not a P2WSH node: a node in tapscript$"
    ) as e:
        MiniscriptDescriptor(node)
    assert_secret_free(e.value, [_RANDOM_HEX])


def test_a_wsh_miniscript_holding_what_is_no_node_is_refused() -> None:
    """As a ``tr()`` leaf holding one is, naming the type alone."""
    node = _unpickled(miniscript.parse(f"pk({_C})", miniscript.P2WSH))
    object.__setattr__(node, "subs", (_RANDOM_HEX,))
    with pytest.raises(
        BTClibTypeError, match="^invalid miniscript node type: str$"
    ) as e:
        MiniscriptDescriptor(node)
    assert_secret_free(e.value, [_RANDOM_HEX])


@pytest.mark.parametrize("key", ["abc", 5, None], ids=["str", "int", "None"])
@pytest.mark.parametrize(
    "context",
    [miniscript.P2WSH, miniscript.TAPSCRIPT],
    ids=["p2wsh", "tapscript"],
)
def test_a_miniscript_holding_a_key_of_another_type_is_refused(
    key: object, context: str
) -> None:
    """Each key is a KeyExpression, in any context.

    Issue btclib-org/bip32-descriptors#170.
    """
    err_msg = f"^invalid key type: {type(key).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        miniscript.Miniscript(
            "pk_k",
            context,
            keys=(key,),  # type: ignore[arg-type]
        )
    (valid_key,) = parse(f"pk({_C})").key_expressions
    fragment = "multi" if context == miniscript.P2WSH else "multi_a"
    with pytest.raises(BTClibTypeError, match=err_msg):
        miniscript.Miniscript(
            fragment,
            context,
            keys=(valid_key, key),  # type: ignore[arg-type]
            threshold=1,
        )


@pytest.mark.parametrize("key", ["abc", 5, None], ids=["str", "int", "None"])
def test_an_unpickled_node_holding_a_key_of_another_type_is_refused(
    key: object,
) -> None:
    """In a ``tr()`` leaf and in a ``wsh()``, naming the type alone.

    An unpickled node skips `Miniscript`'s own check of its keys. Issue
    btclib-org/bip32-descriptors#246.
    """
    err_msg = f"^invalid key type: {type(key).__name__}$"
    leaf = _unpickled(miniscript.parse(f"pk({_X})", miniscript.TAPSCRIPT))
    object.__setattr__(leaf.subs[0], "keys", (key,))
    with pytest.raises(BTClibTypeError, match=err_msg):
        TrDescriptor(_KEY, leaf)
    node = _unpickled(miniscript.parse(f"pk({_C})", miniscript.P2WSH))
    object.__setattr__(node.subs[0], "keys", (key,))
    with pytest.raises(BTClibTypeError, match=err_msg):
        WshDescriptor(MiniscriptDescriptor(node))


@pytest.mark.parametrize(
    "forged,kind",
    [
        (MultiA(1, (_KEY2,)), "MultiA"),
        (_KEY2, "KeyExpression"),
        ((_KEY2, _KEY2), "tuple"),
    ],
    ids=["MultiA", "KeyExpression", "tuple"],
)
def test_a_tr_leaf_holding_a_tree_node_as_a_subexpression_is_refused(
    forged: object, kind: str
) -> None:
    """A tree node of another type is no miniscript node inside a leaf."""
    leaf = _unpickled(miniscript.parse(f"pk({_X})", miniscript.TAPSCRIPT))
    object.__setattr__(leaf, "subs", (forged,))
    with pytest.raises(
        BTClibTypeError, match=f"^invalid miniscript node type: {kind}$"
    ) as e:
        TrDescriptor(_KEY, leaf)
    assert_secret_free(e.value, [str(forged)])


# tapscript miniscripts whose text `parse` reads as a leaf of another type
_READ_AS_LEAF = [
    (f"pk({_X2})", KeyExpression),
    (f"c:pk_k({_X2})", KeyExpression),
    (f"multi_a(1,{_X},{_X2})", MultiA),
]


@pytest.mark.parametrize(
    "expression,cls", _READ_AS_LEAF, ids=[e.partition("(")[0] for e, _ in _READ_AS_LEAF]
)
def test_a_tr_miniscript_leaf_parse_reads_as_a_function_is_refused_when_built(
    expression: str, cls: type
) -> None:
    """Built directly, in a branch or by `replace`, naming the function.

    Inside ``tr()`` its text parses back as that leaf, and so does the
    expression. Issue btclib-org/bip32-descriptors#194.
    """
    leaf = miniscript.parse(expression, miniscript.TAPSCRIPT)
    read = cast("TrDescriptor", parse(f"tr({_X},{leaf})"))
    assert type(read.tree) is cls
    assert parse(f"tr({_X},{expression})") == read
    name = re.escape(str(leaf).partition("(")[0])
    err_msg = rf"^parse reads {name}\(\) as a descriptor function, not a miniscript$"
    for tree in (leaf, (_KEY2, leaf), (leaf, _KEY2)):
        with pytest.raises(BTClibValueError, match=err_msg):
            TrDescriptor(_KEY, tree)
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(TrDescriptor(_KEY), tree=leaf)


@pytest.mark.parametrize(
    "expression", [f"pkh({_X2})", f"c:pk_h({_X2})", f"rawpkh({'00' * 20})"]
)
def test_a_tr_miniscript_leaf_parse_reads_as_a_miniscript_is_built(
    expression: str,
) -> None:
    """The control: inside ``tr()`` these are miniscript fragments."""
    leaf = miniscript.parse(expression, miniscript.TAPSCRIPT)
    descriptor = TrDescriptor(_KEY, leaf)
    assert parse(str(descriptor)) == descriptor


@pytest.mark.parametrize(
    "template",
    [f"tr({_X},LEAF)", f"tr({_X},{{pk({_X}),LEAF}})"],
    ids=["leaf", "branch"],
)
def test_parse_reads_a_tr_leaf_written_as_pk_as_a_pk_leaf(template: str) -> None:
    """``c:pk_k()``, which its text parses back to, as no miniscript would."""
    parsed = parse(template.replace("LEAF", f"c:pk_k({_X2})"))
    assert parsed == parse(template.replace("LEAF", f"pk({_X2})"))
    assert parse(str(parsed)) == parsed


@pytest.mark.parametrize(
    "wif,network",
    [
        (b58.wif_from_prv_key(2, "mainnet", compressed=True), "regtest"),
        (b58.wif_from_prv_key(2, "testnet", compressed=True), "mainnet"),
    ],
    ids=["mainnet-wif-on-regtest", "testnet-wif-on-mainnet"],
)
def test_a_tr_leaf_read_as_pk_keeps_its_wif_network_check(
    wif: str, network: str
) -> None:
    """A WIF of another network is refused, as inside ``pk()``."""
    err_msg = rf"^key 1: not a {network} key: WIF prefix$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(f"tr({_X},pk({wif}))", network)
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(f"tr({_X},c:pk_k({wif}))", network)


class _Network(str):
    """A caller's str subclass, which `parse` must not hand on."""

    __slots__ = ()


@pytest.mark.parametrize(
    "text",
    [f"wsh(and_v(v:pk({_C}),pk({PrvKeyData(4).pub.sec.hex()})))", f"tr({_X},pk({_X}))"],
    ids=["wsh", "tr"],
)
def test_parse_hands_constructors_the_table_s_own_network_string(
    text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`parse` hands the constructors the network table's own string.

    It is that object itself, never the caller's str subclass, whatever
    btclib's normalization returns.
    """
    received: list[str] = []
    parse_text = descriptors_module._parse_text

    def spy(text: str, network: str, prv_keys: Any) -> Any:
        received.append(network)
        return parse_text(text, network, prv_keys)

    monkeypatch.setattr(descriptors_module, "_parse_text", spy)
    descriptor = parse(text, _Network(" MAINNET "))
    assert len(received) == 1
    assert received[0] is descriptors_module._NETWORK_NAMES["mainnet"]
    assert type(descriptor.network) is str
    assert descriptor.network == "mainnet"


def test_a_large_wsh_miniscript_of_an_unknown_context_is_refused() -> None:
    """Its context is refused before its size, which would name it."""
    keys = [
        parse(f"pk({PrvKeyData(i).pub.sec.hex()})").key_expressions
        for i in range(5, 126)
    ]
    node = miniscript.Miniscript(
        "c:", subs=(miniscript.Miniscript("pk_k", keys=keys[0]),)
    )
    for key in keys[1:]:
        check = miniscript.Miniscript(
            "c:", subs=(miniscript.Miniscript("pk_k", keys=key),)
        )
        verify = miniscript.Miniscript("v:", subs=(check,))
        node = miniscript.Miniscript("and_v", subs=(verify, node))
    with pytest.raises(BTClibValueError, match="^miniscript too large for P2WSH: "):
        MiniscriptDescriptor(node)
    node = _unpickled(node)
    _with_context(node, _RANDOM_HEX)
    with pytest.raises(BTClibValueError, match="^not a P2WSH node: and_v in another"):
        MiniscriptDescriptor(node)
    with pytest.raises(
        BTClibValueError, match="^miniscript too large for P2WSH: "
    ) as e:
        miniscript._assert_fits(node)
    assert_secret_free(e.value, [_RANDOM_HEX])


_XPRV = rootxprv_from_seed(_RANDOM_HEX)
_XPUB = xpub_from_xprv(_XPRV)
_C2 = PrvKeyData(4).pub.sec.hex()
# each with the fault `parse` names, its keys filled in per context
_INSANE = [
    ("and_v(v:pk({0}),pk({0}))", "it repeats a public key"),
    ("and_v(v:pk({0}),or_i(1,1))", "malleable witnesses exist"),
    ("older(1)", "witnesses without signature exist"),
    (
        "and_v(v:pk({0}),and_v(v:older(1),older(4194305)))",
        "it mixes timelocks expressed in blocks and in seconds",
    ),
    ("and_v(v:pk({0}),0)", "is not satisfiable"),
]


@pytest.mark.parametrize(
    "expression,fault", _INSANE, ids=[fault for _, fault in _INSANE]
)
def test_a_miniscript_parse_refuses_is_refused_when_built(
    expression: str, fault: str
) -> None:
    """In a tr() leaf and in a wsh(), with the refusal `parse` gives.

    Built, the descriptor would not parse back from its own text. Issue
    btclib-org/bip32-descriptors#85.
    """
    tapscript = expression.format(_X2)
    p2wsh = expression.format(_C2)
    leaf = miniscript.parse(tapscript, miniscript.TAPSCRIPT)
    node = miniscript.parse(p2wsh)
    cases: list[tuple[str, Callable[[], object]]] = [
        (
            f"tr({_X},{{pk({_X2}),{tapscript}}})",
            lambda: TrDescriptor(_KEY, (_KEY2, leaf)),
        ),
        (f"wsh({p2wsh})", lambda: WshDescriptor(MiniscriptDescriptor(node))),
    ]
    for text, build in cases:
        with pytest.raises(BTClibValueError, match=f"{fault}$") as parsed:
            parse(text)
        with pytest.raises(BTClibValueError) as built:
            build()
        assert str(built.value) == str(parsed.value)


@pytest.mark.parametrize(
    "node,err_msg",
    [
        (
            miniscript.Miniscript("pk_k", keys=(parse(f"pk({_C})").key_expressions)),
            rf"^not a miniscript script: pk_k\({_C}\) is a K, not a B$",
        ),
        (
            miniscript.Miniscript(
                "and_b", subs=(miniscript.Miniscript("1"), miniscript.Miniscript("1"))
            ),
            "^ill-typed miniscript: and_b over ",
        ),
    ],
    ids=["not-a-B", "ill-typed"],
)
def test_a_miniscript_that_is_no_script_is_refused_when_built(
    node: miniscript.Miniscript, err_msg: str
) -> None:
    """What `miniscript.parse` refuses before any sanity is asked."""
    with pytest.raises(BTClibValueError, match=err_msg):
        MiniscriptDescriptor(node)


def test_a_sane_miniscript_built_by_hand_parses_back() -> None:
    """The control: the issue's leaf with two keys, and its p2wsh twin."""
    leaf = miniscript.parse(f"and_v(v:pk({_X2}),pk({_X}))", miniscript.TAPSCRIPT)
    tr = TrDescriptor(_KEY, leaf)
    assert parse(str(tr)) == tr
    wsh = WshDescriptor(
        MiniscriptDescriptor(miniscript.parse(f"and_v(v:pk({_C2}),pk({_C}))"))
    )
    assert parse(str(wsh)) == wsh


def test_a_top_level_miniscript_built_by_hand_does_not_parse_back() -> None:
    """`parse` takes a `MiniscriptDescriptor` only inside ``wsh()``.

    One built at the top level gives its script, and `infer_descriptor`
    answers the ``raw()`` of that script.
    """
    node = miniscript.parse(f"and_v(v:pk({_C}),older(1))", miniscript.P2WSH)
    descriptor = MiniscriptDescriptor(node)
    script = descriptor.script_pub_key().script
    assert script == node.script()
    text = str(descriptor)
    with pytest.raises(BTClibValueError, match=MINISCRIPT_OUTSIDE):
        parse(text)
    wsh = WshDescriptor(descriptor)
    assert parse(str(wsh)) == wsh
    raw = add_checksum(f"raw({script.hex()})")
    assert infer_descriptor(script, Provider()) == raw


@pytest.mark.parametrize(
    "template",
    ["tr({0},and_v(v:pk({1}/*),pk({1}/1)))", "wsh(and_v(v:pk({1}/*),pk({1}/1)))"],
    ids=["tr", "wsh"],
)
def test_at_index_refuses_an_index_where_a_key_repeats(template: str) -> None:
    """The keys differ at index 0, where `parse` compares them, not at 1.

    At index 1 both keys are ``/1``, and the script is malleable there.
    """
    descriptor = parse(template.format(_X, _XPUB))
    for index in (0, 2):
        assert parse(str(at_index(descriptor, index))) == at_index(descriptor, index)
    with pytest.raises(
        BTClibValueError, match="is not sane: it repeats a public key$"
    ) as e:
        at_index(descriptor, 1)
    assert_secret_free(e.value, [_XPRV, bytes.fromhex(_RANDOM_HEX)])


def test_normalized_refuses_what_repeats_a_key_once_derived() -> None:
    """Two spellings of one key, one of them behind a hardened step.

    Without `prv_keys` the hardened one is compared by its expression, so
    `parse` reads the descriptor; normalized, both are the same xpub.
    """
    child = xpub_from_xprv(derive(_XPRV, "m/1h"))
    descriptor = parse(f"wsh(and_v(v:pk({_XPUB}/1h/0),pk({child}/0)))")
    prv_keys = {_XPUB: _XPRV}
    with pytest.raises(
        BTClibValueError, match="is not sane: it repeats a public key$"
    ) as e:
        normalized(descriptor, prv_keys)
    assert_secret_free(e.value, [_XPRV, bytes.fromhex(_RANDOM_HEX)])


def test_a_refusal_when_built_names_no_private_key() -> None:
    """A leaf read from an xprv holds its xpub, which is what is named."""
    prv_keys: dict[str, str] = {}
    expression = f"and_v(v:pk({_XPRV}/1),pk({_XPRV}/1))"
    leaf = miniscript.parse(expression, miniscript.TAPSCRIPT, prv_keys)
    with pytest.raises(BTClibValueError, match=rf"pk\({_XPUB}/1\)\) is not sane") as e:
        TrDescriptor(_KEY, leaf)
    assert_secret_free(e.value, [_XPRV, bytes.fromhex(_RANDOM_HEX)])


@pytest.mark.parametrize("sort", [False, True])
def test_a_multi_a_built_by_hand_parses_back(sort: bool) -> None:
    """The control: a leaf built by hand is the leaf `parse` reads."""
    descriptor = TrDescriptor(_KEY, MultiA(2, (_KEY, _KEY2), sort=sort))
    assert parse(str(descriptor)) == descriptor


@pytest.mark.parametrize("threshold", ["1", 1.0, True, None])
def test_a_multi_a_threshold_of_another_type_is_refused(threshold: Any) -> None:
    """A bool is no number of signatures, though Python makes it an int."""
    err_msg = f"^invalid threshold type: {type(threshold).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        MultiA(threshold, (_KEY,))


@pytest.mark.parametrize(
    "keys,what",
    [([_KEY], "keys"), (_KEY, "keys"), ((_KEY, _X2), "key"), ((None,), "key")],
)
def test_multi_a_keys_of_another_type_are_refused(keys: Any, what: str) -> None:
    """A tuple of KEY expressions, as `parse` builds it."""
    with pytest.raises(BTClibTypeError, match=f"^invalid {what} type: "):
        MultiA(1, keys)


@pytest.mark.parametrize("sort", [1, "sortedmulti_a", None])
def test_a_multi_a_sort_of_another_type_is_refused(sort: Any) -> None:
    """The flag says which of two scripts is built, so it is a bool."""
    err_msg = f"^invalid sort type: {type(sort).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        MultiA(1, (_KEY,), sort=sort)


@pytest.mark.parametrize("sort", [False, True])
@pytest.mark.parametrize(
    "threshold,keys",
    [(0, (_KEY,)), (-1, (_KEY,)), (3, (_KEY, _KEY2)), (1, ())],
    ids=["zero", "negative", "above-key-count", "no-key"],
)
def test_a_multi_a_threshold_out_of_range_is_refused(
    threshold: int, keys: tuple[Any, ...], sort: bool
) -> None:
    """From 1 to the number of keys, named as `parse` names the function."""
    name = "sortedmulti_a" if sort else "multi_a"
    err_msg = f"^invalid k in k-of-n {name}: {threshold}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        MultiA(threshold, keys, sort=sort)


# a hand-built `Miniscript` node for each field the tests below try,
# carrying a valid value of it for `replace` to overtype
_OLDER = miniscript.Miniscript("older", miniscript.P2WSH, threshold=1)
_PK_K = miniscript.Miniscript("pk_k", miniscript.TAPSCRIPT, keys=(_KEY,))
_SHA256 = miniscript.Miniscript("sha256", miniscript.P2WSH, data=bytes(32))


@pytest.mark.parametrize("fragment", [[], 5, None])
def test_a_miniscript_fragment_of_another_type_is_refused(fragment: Any) -> None:
    """The fragment is the name BIP379 gives it, never another type."""
    err_msg = f"^invalid fragment type: {type(fragment).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        replace(_OLDER, fragment=fragment)


@pytest.mark.parametrize("threshold", ["1", 1.0, True, None])
def test_a_miniscript_threshold_of_another_type_is_refused(threshold: Any) -> None:
    """A bool is no number, though Python makes it an int."""
    err_msg = f"^invalid threshold type: {type(threshold).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        replace(_OLDER, threshold=threshold)


@pytest.mark.parametrize("keys", [5, [_KEY], None])
def test_miniscript_keys_of_another_type_are_refused(keys: Any) -> None:
    """The keys are a tuple, as `parse` builds them."""
    err_msg = f"^invalid keys type: {type(keys).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        replace(_PK_K, keys=keys)


@pytest.mark.parametrize("data", ["ab" * 32, 5, bytearray(32)])
def test_miniscript_data_of_another_type_is_refused(data: Any) -> None:
    """Hex text is not the digest: `parse` is what reads hex."""
    err_msg = f"^invalid data type: {type(data).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        replace(_SHA256, data=data)


_K = PrvKeyData(1).pub.sec.hex()
_K2 = PrvKeyData(2).pub.sec.hex()
_MINISCRIPT = parse(f"wsh(and_v(v:pk({_K}),older(1)))")
assert isinstance(_MINISCRIPT, WshDescriptor)
# one descriptor of each fragment, as `parse` builds it
_PARSED: dict[type[Descriptor], Descriptor] = {
    type(descriptor): descriptor
    for descriptor in (
        parse(f"pk({_K})"),
        parse(f"pkh({_K})"),
        parse(f"wpkh({_K})"),
        parse(f"sh(wpkh({_K}))"),
        parse(f"wsh(pk({_K}))"),
        _MINISCRIPT.inner,
        parse(f"multi(1,{_K},{_K2})"),
        parse(f"combo({_K})"),
        parse("addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)"),
        parse("raw(51)"),
        parse(f"rawpkh({'00' * 20})"),
        parse(f"tr({_X})"),
        parse(f"rawtr({_X})"),
        parse(f"unused({_K})"),
    )
}
_KEY_FIELD_CLASSES = (
    PkDescriptor,
    PkhDescriptor,
    WpkhDescriptor,
    ComboDescriptor,
    RawTrDescriptor,
    UnusedDescriptor,
)
# (fragment, field, a value of the wrong type, the name the refusal gives)
_WRONG: list[tuple[type[Descriptor], str, Any, str]] = [
    *(
        (cls, "network", value, "network")
        for cls in _PARSED
        for value in (5, None, b"mainnet")
    ),
    *(
        (cls, "key", value, "key")
        for cls in _KEY_FIELD_CLASSES
        for value in (_K, 5, None, _MINISCRIPT.inner)
    ),
    *(
        (cls, "inner", value, "inner descriptor")
        for cls in (ShDescriptor, WshDescriptor)
        for value in (f"pk({_K})", 5, _KEY)
    ),
    (MiniscriptDescriptor, "node", "and_v(v:pk(K),older(1))", "miniscript"),
    (MiniscriptDescriptor, "node", _MINISCRIPT, "miniscript"),
    (MultiDescriptor, "threshold", "1", "threshold"),
    (MultiDescriptor, "threshold", 1.0, "threshold"),
    (MultiDescriptor, "threshold", True, "threshold"),
    (MultiDescriptor, "keys", [_KEY, _KEY2], "keys"),
    (MultiDescriptor, "keys", _KEY, "keys"),
    (MultiDescriptor, "keys", (_KEY, _K2), "key"),
    (MultiDescriptor, "sort", 1, "sort"),
    (MultiDescriptor, "sort", "sortedmulti", "sort"),
    (AddrDescriptor, "addr", b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "address"),
    (AddrDescriptor, "addr", 5, "address"),
    (RawDescriptor, "script", "51", "script"),
    (RawPkhDescriptor, "key_hash", "00" * 20, "key hash"),
    (TrDescriptor, "internal_key", _X, "internal key"),
    (TrDescriptor, "tree", 5, "script tree node"),
]


def _fragments(cls: type) -> list[type]:
    """Return every subclass of `cls`, at any depth."""
    found: list[type] = []
    subs: list[type] = cls.__subclasses__()
    for sub in subs:
        found += [sub, *_fragments(sub)]
    return found


def test_every_field_of_every_fragment_has_a_wrong_type_tried() -> None:
    """The census: a fragment or a field added later is tried here too."""
    module = Descriptor.__module__
    assert set(_PARSED) == {c for c in _fragments(Descriptor) if c.__module__ == module}
    tried = {(cls, name) for cls, name, _, _ in _WRONG}
    every = {(cls, f.name) for cls in _PARSED for f in fields(cls)}
    assert tried == every


@pytest.mark.parametrize("cls", list(_PARSED), ids=lambda cls: cls.__name__)
def test_a_fragment_rebuilt_from_its_own_fields_is_the_same(
    cls: type[Descriptor],
) -> None:
    """The control: each field `parse` builds is one the fragment takes."""
    descriptor = _PARSED[cls]
    assert type(descriptor) is cls
    assert replace(descriptor) == descriptor


@pytest.mark.parametrize(
    "cls,name,value,what",
    _WRONG,
    ids=[f"{c.__name__}-{n}-{type(v).__name__}" for c, n, v, _ in _WRONG],
)
def test_a_fragment_field_of_another_type_is_refused(
    cls: type[Descriptor], name: str, value: Any, what: str
) -> None:
    """A `BTClibTypeError` when it is built, naming the field."""
    err_msg = f"^invalid {what} type: "
    with pytest.raises(BTClibTypeError, match=err_msg):
        replace(_PARSED[cls], **{name: value})


# a ranged key, which `parse` takes in wpkh() and refuses in unused()
(_RANGED_KEY,) = parse(f"wpkh({rootxprv_from_seed('00' * 32)}/*)").key_expressions


def test_an_unused_ranged_key_is_refused_when_built() -> None:
    """Built directly or by `replace`, with the message `parse` gives."""
    parsed = _PARSED[UnusedDescriptor]
    assert isinstance(parsed, UnusedDescriptor)
    err_msg = r"^unused\(\): key cannot be ranged$"
    with pytest.raises(BTClibValueError, match=err_msg):
        UnusedDescriptor(_RANGED_KEY)
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(parsed, key=_RANGED_KEY)


_WRAPPERS = {ShDescriptor: "sh", WshDescriptor: "wsh"}


@pytest.mark.parametrize("wrapper", _WRAPPERS, ids=lambda cls: cls.__name__)
@pytest.mark.parametrize("cls", list(_PARSED), ids=lambda cls: cls.__name__)
def test_an_inner_fragment_parse_refuses_is_refused_when_built(
    cls: type[Descriptor], wrapper: type[ShDescriptor | WshDescriptor]
) -> None:
    """Built directly or by `replace`, with the message `parse` gives.

    The census: every fragment inside ``sh()`` and ``wsh()``. One `parse`
    takes there is built, and its text parses back. Issue
    btclib-org/bip32-descriptors#158.
    """
    inner = _PARSED[cls]
    parsed = cast("ShDescriptor | WshDescriptor", _PARSED[wrapper])
    try:
        by_parse = parse(f"{_WRAPPERS[wrapper]}({inner})")
    except BTClibValueError as e:
        err_msg = f"^{re.escape(str(e))}$"
        with pytest.raises(BTClibValueError, match=err_msg):
            wrapper(inner)
        with pytest.raises(BTClibValueError, match=err_msg):
            replace(parsed, inner=inner)
    else:
        assert wrapper(inner) == by_parse
        assert replace(parsed, inner=inner) == by_parse


@pytest.mark.parametrize(
    "wrapper,cls,err_msg",
    [
        (ShDescriptor, TrDescriptor, r"^tr\(\) is not allowed inside sh\(\)$"),
        (WshDescriptor, ComboDescriptor, r"^combo\(\) is not allowed inside wsh\(\)$"),
        (ShDescriptor, UnusedDescriptor, r"^unused\(\) is not allowed inside sh\(\)$"),
        (ShDescriptor, ShDescriptor, r"^sh\(\) is not allowed inside sh\(\)$"),
        (WshDescriptor, ShDescriptor, r"^sh\(\) is not allowed inside wsh\(\)$"),
        (WshDescriptor, WshDescriptor, r"^wsh\(\) is not allowed inside wsh\(\)$"),
        (
            ShDescriptor,
            MiniscriptDescriptor,
            r"^Miniscript expressions can only be used in wsh or tr\.$",
        ),
    ],
    ids=lambda case: getattr(case, "__name__", ""),
)
def test_the_issue_s_inner_fragments_are_refused_when_built(
    wrapper: type[ShDescriptor | WshDescriptor], cls: type[Descriptor], err_msg: str
) -> None:
    """The cases the census above derives from `parse`, written out."""
    with pytest.raises(BTClibValueError, match=err_msg):
        wrapper(_PARSED[cls])


@pytest.mark.parametrize(
    "expression,read_as",
    [
        (
            f"and_v(v:pk({_K}),older(1))",
            "Miniscript expressions can only be used in wsh or tr.",
        ),
        (f"and_v(v:multi(1,{_K},{_K2}),older(1))", "A function is needed within P2SH"),
    ],
    ids=["and_v-over-pk", "and_v-over-multi"],
)
def test_a_miniscript_inside_sh_is_refused_whatever_its_text_reads_as(
    expression: str, read_as: str
) -> None:
    """With the position fault `parse` names for a miniscript there.

    `parse` never builds a `MiniscriptDescriptor` inside ``sh()``, and
    its text there reads as a miniscript `parse` refuses there, or as
    nothing `parse` accepts, ``multi()`` being no tapscript fragment.
    """
    node = MiniscriptDescriptor(miniscript.parse(expression))
    try:
        read = type(cast("ShDescriptor", parse(f"sh({node})")).inner).__name__
    except BTClibValueError as e:
        read = str(e)
    assert read == read_as
    err_msg = r"^Miniscript expressions can only be used in wsh or tr\.$"
    with pytest.raises(BTClibValueError, match=err_msg):
        ShDescriptor(node)


class _Renamed(PkDescriptor):
    """A subclass writing a function name `parse` has no parser for."""

    @override
    def __str__(self) -> str:
        return f"foo({self.key})"


class _Bare(PkDescriptor):
    """A subclass writing a key, as a text with no bracket to name."""

    @override
    def __str__(self) -> str:
        return _RANDOM_HEX


@pytest.mark.parametrize("wrapper", _WRAPPERS, ids=lambda cls: cls.__name__)
@pytest.mark.parametrize("cls", [_Renamed, _Bare], ids=lambda cls: cls.__name__)
def test_an_inner_subclass_writing_no_function_parse_reads_is_refused(
    cls: type[PkDescriptor], wrapper: type[ShDescriptor | WshDescriptor]
) -> None:
    """As a `BTClibValueError` naming the type, not quoting its text."""
    inner = cls(_C_KEY)
    context = re.escape(f"{_WRAPPERS[wrapper]}()")
    err_msg = f"^{cls.__name__} writes no function parse reads inside {context}$"
    with pytest.raises(BTClibValueError, match=err_msg) as e:
        wrapper(inner)
    assert_secret_free(e.value, [_RANDOM_HEX, _C])


(_MUSIG,) = parse(f"tr(musig({_K},{_K2}))").key_expressions
(_C_KEY,) = parse(f"pk({_C})").key_expressions
# each key `parse` reads in taproot only, its text, and the refusal
# `miniscript.parse` gives elsewhere
_TAPROOT_ONLY = [
    (_MUSIG, str(_MUSIG), r"musig\(\) is only allowed in tr\(\) and rawtr\(\)"),
    (_KEY, _X, "x-only public keys are allowed in a taproot key expression only"),
]
_TAPROOT_ONLY_IDS = ["musig", "x-only"]
# P2WSH miniscripts whose last key is the one `{}` stands for
_P2WSH_HOLDING = ["pk({})", "pkh({})", f"multi(1,{_C},{{}})"]


def _key_holder(node: miniscript.Miniscript) -> miniscript.Miniscript:
    """Return the node of `_P2WSH_HOLDING` that holds the keys."""
    return node if node.keys else node.subs[0]


def _node_holding(expression: str, key: Any) -> miniscript.Miniscript:
    """Return the P2WSH `expression` of `_C2` with `key` in its place.

    In an unpickled copy, which skips `Miniscript`'s own check of the
    keys, so that what is reached is `MiniscriptDescriptor`'s.
    """
    node = _unpickled(miniscript.parse(expression.format(_C2)))
    holder = _key_holder(node)
    object.__setattr__(holder, "keys", (*holder.keys[:-1], key))
    return node


# (fragment, field, its value made to hold `key`, the text `parse` refuses)
_TAPROOT_ONLY_FIELDS: list[tuple[type[Descriptor], str, Callable[[Any], Any], str]] = [
    (PkDescriptor, "key", lambda key: key, "pk({})"),
    (PkhDescriptor, "key", lambda key: key, "pkh({})"),
    (WpkhDescriptor, "key", lambda key: key, "wpkh({})"),
    (ComboDescriptor, "key", lambda key: key, "combo({})"),
    (UnusedDescriptor, "key", lambda key: key, "unused({})"),
    (MultiDescriptor, "keys", lambda key: (key, _C_KEY), f"multi(1,{{}},{_C})"),
    (MultiDescriptor, "keys", lambda key: (_C_KEY, key), f"multi(1,{_C},{{}})"),
    *(
        (
            MiniscriptDescriptor,
            "node",
            lambda key, expression=expression: _node_holding(expression, key),
            f"wsh({expression})",
        )
        for expression in _P2WSH_HOLDING
    ),
]


def test_every_fragment_holding_a_key_is_tried_with_a_taproot_only_one() -> None:
    """The census: a key `tr()` and `rawtr()` take, every other refuses."""
    holding = {
        cls
        for cls in _PARSED
        for f in fields(cls)
        if any(name in str(f.type) for name in ("KeyExpression", "Miniscript"))
    }
    tried = {cls for cls, _, _, _ in _TAPROOT_ONLY_FIELDS}
    assert holding == tried | {TrDescriptor, RawTrDescriptor}


@pytest.mark.parametrize("key,spelling,refusal", _TAPROOT_ONLY, ids=_TAPROOT_ONLY_IDS)
@pytest.mark.parametrize(
    "cls,name,value,template",
    _TAPROOT_ONLY_FIELDS,
    ids=[
        f"{c.__name__}-{t.replace(_C, 'C')}-{n}" for c, n, _, t in _TAPROOT_ONLY_FIELDS
    ],
)
def test_a_taproot_only_key_outside_tr_is_refused_when_built(
    cls: type[Descriptor],
    name: str,
    value: Callable[[Any], Any],
    template: str,
    key: Any,
    spelling: str,
    refusal: str,
) -> None:
    """Built directly or by `replace`, with the message `parse` gives.

    Its text would not parse back. A p2wpkh or p2pkh script of a
    ``musig()`` key also wants an ECDSA signature, and what a MuSig2 group
    makes is a BIP340 one, BIP327 says. Issues
    btclib-org/bip32-descriptors#150 and btclib-org/bip32-descriptors#161.
    """
    match = rf"^key \d+: {refusal}$"
    with pytest.raises(BTClibValueError, match=match) as by_parse:
        parse(template.format(spelling))
    err_msg = f"^{re.escape(str(by_parse.value))}$"
    parsed = _PARSED[cls]
    fixed = {f.name: getattr(parsed, f.name) for f in fields(cls)}
    with pytest.raises(BTClibValueError, match=err_msg):
        cls(**{**fixed, name: value(key)})
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(parsed, **{name: value(key)})


@pytest.mark.parametrize("key,spelling,refusal", _TAPROOT_ONLY, ids=_TAPROOT_ONLY_IDS)
@pytest.mark.parametrize(
    "expression", _P2WSH_HOLDING, ids=[e.replace(_C, "C") for e in _P2WSH_HOLDING]
)
def test_a_p2wsh_node_holding_a_taproot_only_key_is_refused_when_built(
    expression: str, key: Any, spelling: str, refusal: str
) -> None:
    """Built directly or by `replace`, with `miniscript.parse`'s message.

    Issues btclib-org/bip32-descriptors#159 and
    btclib-org/bip32-descriptors#161.
    """
    with pytest.raises(BTClibValueError, match=f"^{refusal}$") as by_parse:
        miniscript.parse(expression.format(spelling))
    err_msg = f"^{re.escape(str(by_parse.value))}$"
    holder = _key_holder(miniscript.parse(expression.format(_C2)))
    keys = (*holder.keys[:-1], key)
    with pytest.raises(BTClibValueError, match=err_msg):
        miniscript.Miniscript(
            holder.fragment, miniscript.P2WSH, keys=keys, threshold=holder.threshold
        )
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(holder, keys=keys)


@pytest.mark.parametrize(
    "key,spelling", [case[:2] for case in _TAPROOT_ONLY], ids=_TAPROOT_ONLY_IDS
)
def test_a_tapscript_node_holding_a_taproot_only_key_is_built(
    key: Any, spelling: str
) -> None:
    """The control: the node `miniscript.parse` reads there."""
    node = miniscript.Miniscript(
        "c:",
        miniscript.TAPSCRIPT,
        (miniscript.Miniscript("pk_k", miniscript.TAPSCRIPT, keys=(key,)),),
    )
    assert miniscript.parse(f"pk({spelling})", miniscript.TAPSCRIPT) == node


def test_a_musig_key_inside_tr_is_built() -> None:
    """The control: the same key where `parse` gives one, read back."""
    leaf = miniscript.parse(f"pkh({_MUSIG})", miniscript.TAPSCRIPT)
    for descriptor in (
        TrDescriptor(_MUSIG, leaf),
        TrDescriptor(_KEY, MultiA(1, (_MUSIG,))),
        RawTrDescriptor(_MUSIG),
    ):
        assert parse(str(descriptor)) == descriptor


# the key of the issue's example: 0x02, then an x that no point has
_OFF_CURVE = b"\x02" + b"\xff" * 32
_UNCOMPRESSED_WIF = b58.wif_from_prv_key(3, "mainnet", compressed=False)
_UNCOMPRESSED = b58.prv_key_data_from_wif(_UNCOMPRESSED_WIF).pub.sec
# the private key 6, the first whose public key has an odd y
_ODD_WIF = b58.wif_from_prv_key(6, "mainnet", compressed=True)


@pytest.mark.parametrize(
    "pub_key,error,err_msg",
    [
        (_OFF_CURVE, EccValueError, "not a public key"),
        (b"\x05" + _OFF_CURVE[1:], BTClibValueError, "invalid public key prefix: 0x05"),
        (b"\x04" + _OFF_CURVE[1:], BTClibValueError, "invalid public key prefix: 0x04"),
        (
            b"\x06" + _UNCOMPRESSED[1:],
            BTClibValueError,
            "invalid public key prefix: 0x06",
        ),
        (
            b"\x02" + _UNCOMPRESSED[1:],
            BTClibValueError,
            "invalid public key prefix: 0x02",
        ),
    ],
    ids=["no point", "0x05", "0x04 short", "hybrid", "0x02 long"],
)
def test_a_pub_key_parse_refuses_is_refused_when_built(
    pub_key: bytes, error: type[Exception], err_msg: str
) -> None:
    """With the message `parse` gives after the position of the key."""
    with pytest.raises(error, match=f"^key 0: {re.escape(err_msg)}$"):
        parse(f"pk({pub_key.hex()})")
    with pytest.raises(error, match=f"^{re.escape(err_msg)}$"):
        KeyExpression(pub_key=pub_key)
    with pytest.raises(error, match=f"^{re.escape(err_msg)}$"):
        replace(_C_KEY, pub_key=pub_key)


@pytest.mark.parametrize("size", [0, 1, 32, 34, 64, 66])
def test_a_pub_key_of_no_sec_size_is_refused_when_built(size: int) -> None:
    """Counted in bytes, where `parse` counts the characters of the hex."""
    err_msg = f"^invalid public key length in bytes: {size}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        KeyExpression(pub_key=b"\x02" * size)


@pytest.mark.parametrize("pub_key", [_C, bytearray.fromhex(_C), 2])
def test_a_pub_key_of_another_type_is_refused(pub_key: Any) -> None:
    """Hex text is not the key: `parse` is what reads hex."""
    err_msg = f"^invalid pub_key type: {type(pub_key).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        KeyExpression(pub_key=pub_key)


@pytest.mark.parametrize("key", [_RANGED_KEY, _MUSIG], ids=["xkey", "musig"])
def test_an_x_only_key_with_no_pub_key_is_refused(key: KeyExpression) -> None:
    """`parse` reads an extended key and a ``musig()`` as not x-only."""
    assert not key.x_only
    with pytest.raises(BTClibValueError, match="^invalid x-only key: no pub_key$"):
        replace(key, x_only=True)


@pytest.mark.parametrize(
    "kwargs",
    [{}, {"wildcard": 0}, {"der_path": (0,)}],
    ids=["empty", "wildcard", "der_path"],
)
def test_a_key_expression_with_no_key_is_refused(kwargs: dict[str, Any]) -> None:
    """A key expression must have a pub_key, xkey, or participants."""
    with pytest.raises(BTClibValueError, match="^No key provided$"):
        KeyExpression(**kwargs)


@pytest.mark.parametrize("step", [-1, 2**32, 2**32 + 1])
def test_an_invalid_der_path_step_is_refused(step: int) -> None:
    """A der_path step outside 0..2**32-1 is refused."""
    with pytest.raises(
        BTClibValueError, match=r"^invalid index: not in 0\.\.2\*\*32-1$"
    ):
        KeyExpression(xkey=_RANGED_KEY.xkey, der_path=(step,))


@pytest.mark.parametrize("step", ["0", 1.5, True])
def test_a_der_path_step_of_invalid_type_is_refused(step: Any) -> None:
    """A der_path step that is not an integer is refused."""
    err_msg = f"^invalid derivation index type: {type(step).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        KeyExpression(xkey=_RANGED_KEY.xkey, der_path=(step,))


def test_an_uncompressed_x_only_key_is_refused_as_parse_refuses_it() -> None:
    """The key of an uncompressed WIF in a ``tr()``, which `parse` refuses."""
    err_msg = "uncompressed public keys are not allowed here"
    with pytest.raises(BTClibValueError, match=f"^key 0: {err_msg}$"):
        parse(f"tr({_UNCOMPRESSED_WIF})")
    with pytest.raises(BTClibValueError, match=f"^{err_msg}$"):
        KeyExpression(pub_key=_UNCOMPRESSED, x_only=True)


_U_KEY = KeyExpression(pub_key=_UNCOMPRESSED)
_KEYS = tuple(KeyExpression(pub_key=PrvKeyData(i).pub.sec) for i in range(1, 22))
_P2WSH = miniscript.P2WSH


def _and_v_older(key: KeyExpression) -> MiniscriptDescriptor:
    """Return ``and_v(v:pk(KEY),older(1))``, its node unpickled.

    A P2WSH `Miniscript` node refuses an uncompressed key when built, and
    unpickling skips that check, so the key is given to an unpickled copy.
    """
    node = _unpickled(miniscript.parse(f"and_v(v:pk({_C}),older(1))", _P2WSH))
    object.__setattr__(node.subs[0].subs[0].subs[0], "keys", (key,))
    return MiniscriptDescriptor(node)


def _unpickled_multi(keys: tuple[KeyExpression, ...]) -> Descriptor:
    """Return ``multi(1,KEY,...)``, unpickled.

    `MultiDescriptor` refuses no key and more than 20 keys when built, and
    unpickling skips those checks, so the keys are given to an unpickled
    copy.
    """
    parsed = _PARSED[MultiDescriptor]
    multi: MultiDescriptor = pickle.loads(pickle.dumps(parsed))  # noqa: S301
    object.__setattr__(multi, "keys", keys)
    return multi


def _unpickled_sortedmulti(keys: tuple[KeyExpression, ...]) -> Descriptor:
    """Return ``sortedmulti(1,KEY,...)``, as `_unpickled_multi` does."""
    multi = _unpickled_multi(keys)
    object.__setattr__(multi, "sort", True)
    return multi


def _unpickled_wpkh(key: KeyExpression) -> Descriptor:
    """Return ``wpkh(KEY)``, unpickled.

    `WpkhDescriptor` refuses an uncompressed key when built, and
    unpickling skips that check, so the key is given to an unpickled copy.
    """
    parsed = _PARSED[WpkhDescriptor]
    wpkh: WpkhDescriptor = pickle.loads(pickle.dumps(parsed))  # noqa: S301
    object.__setattr__(wpkh, "key", key)
    return wpkh


def _unpickled_pk(key: KeyExpression) -> Descriptor:
    """Return ``pk(KEY)``, unpickled.

    `PkDescriptor` refuses a key ``tr()`` and ``rawtr()`` alone take when
    built, and unpickling skips that check, so the key is given to an
    unpickled copy.
    """
    parsed = _PARSED[PkDescriptor]
    pk: PkDescriptor = pickle.loads(pickle.dumps(parsed))  # noqa: S301
    object.__setattr__(pk, "key", key)
    return pk


def _unpickled_and_v_pk(first: KeyExpression, second: KeyExpression) -> Descriptor:
    """Return ``and_v(v:pk(FIRST),pk(SECOND))``, unpickled.

    A P2WSH `Miniscript` node refuses an uncompressed key and a key
    ``tr()`` and ``rawtr()`` alone take when built, and unpickling skips
    those checks, so the keys are given to an unpickled copy.
    """
    parsed = parse(f"wsh(and_v(v:pk({_C}),pk({_C2})))")
    assert isinstance(parsed, WshDescriptor)
    ms: MiniscriptDescriptor = pickle.loads(pickle.dumps(parsed.inner))  # noqa: S301
    object.__setattr__(ms.node.subs[0].subs[0].subs[0], "keys", (first,))
    object.__setattr__(ms.node.subs[1].subs[0], "keys", (second,))
    return ms


def _unpickled_wsh(inner: Descriptor) -> Descriptor:
    """Return ``wsh(INNER)``, unpickled.

    `WshDescriptor` refuses an argument `parse` refuses inside ``wsh()``
    when built, unless the argument is invalid by itself, as `Descriptor`
    says. Unpickling skips that check, so the argument is given to an
    unpickled copy.
    """
    parsed = _PARSED[WshDescriptor]
    wsh: WshDescriptor = pickle.loads(pickle.dumps(parsed))  # noqa: S301
    object.__setattr__(wsh, "inner", inner)
    return wsh


_UNCOMPRESSED_HERE = "uncompressed public keys are not allowed here"
_MUSIG_HERE = "musig() is only allowed in tr() and rawtr()"
_X_ONLY_HERE = "x-only public keys are allowed in a taproot key expression only"
_SH_AND_WSH: tuple[type[ShDescriptor | WshDescriptor], ...] = (
    WshDescriptor,
    ShDescriptor,
)
# (wrapper, its argument, the refusal `parse` gives for their text)
_REFUSED_INSIDE: list[tuple[type[ShDescriptor | WshDescriptor], Descriptor, str]] = [
    (WshDescriptor, PkDescriptor(_U_KEY), f"key 0: {_UNCOMPRESSED_HERE}"),
    (WshDescriptor, PkhDescriptor(_U_KEY), f"key 0: {_UNCOMPRESSED_HERE}"),
    (
        WshDescriptor,
        MultiDescriptor(1, (_C_KEY, _U_KEY)),
        f"key 1: {_UNCOMPRESSED_HERE}",
    ),
    (
        WshDescriptor,
        MultiDescriptor(1, (_U_KEY, _C_KEY), sort=True),
        f"key 0: {_UNCOMPRESSED_HERE}",
    ),
    (WshDescriptor, _and_v_older(_U_KEY), f"key 0: {_UNCOMPRESSED_HERE}"),
    (
        WshDescriptor,
        _unpickled_multi(_KEYS),
        "multi() takes at most 20 keys, 21 given",
    ),
    (ShDescriptor, _unpickled_wpkh(_U_KEY), f"key 0: {_UNCOMPRESSED_HERE}"),
    (
        ShDescriptor,
        _unpickled_multi(_KEYS),
        "multi() takes at most 20 keys, 21 given",
    ),
    (
        WshDescriptor,
        _unpickled_multi(()),
        "multi() takes a threshold and at least one key",
    ),
    (
        ShDescriptor,
        _unpickled_multi(()),
        "multi() takes a threshold and at least one key",
    ),
    (
        ShDescriptor,
        MultiDescriptor(1, _KEYS[:16]),
        (
            "multi() inside sh() is a 547-byte redeem script,"
            " over the 520-byte push limit"
        ),
    ),
    (
        ShDescriptor,
        MultiDescriptor(1, (_U_KEY,) * 8, sort=True),
        (
            "sortedmulti() inside sh() is a 531-byte redeem script,"
            " over the 520-byte push limit"
        ),
    ),
    *(
        (wrapper, inner, f"key 0: {refusal}")
        for wrapper in _SH_AND_WSH
        for key, refusal in ((_MUSIG, _MUSIG_HERE), (_KEY, _X_ONLY_HERE))
        for inner in (_unpickled_multi((key,)), _unpickled_pk(key))
    ),
    (
        WshDescriptor,
        _unpickled_multi((_U_KEY, _MUSIG)),
        f"key 0: {_UNCOMPRESSED_HERE}",
    ),
    (WshDescriptor, _unpickled_multi((_MUSIG, _U_KEY)), f"key 0: {_MUSIG_HERE}"),
    (ShDescriptor, _unpickled_multi((_U_KEY, _MUSIG)), f"key 1: {_MUSIG_HERE}"),
    *(
        (ShDescriptor, _unpickled_wsh(inner), refusal)
        for inner, refusal in (
            (_unpickled_multi((_C_KEY, _U_KEY)), f"key 1: {_UNCOMPRESSED_HERE}"),
            (_unpickled_multi((_U_KEY, _MUSIG)), f"key 0: {_UNCOMPRESSED_HERE}"),
            (_unpickled_multi((_U_KEY, _KEY)), f"key 0: {_UNCOMPRESSED_HERE}"),
            (
                _unpickled_multi((_C_KEY, _U_KEY, _MUSIG)),
                f"key 1: {_UNCOMPRESSED_HERE}",
            ),
            (_unpickled_and_v_pk(_U_KEY, _MUSIG), f"key 0: {_UNCOMPRESSED_HERE}"),
            (_unpickled_and_v_pk(_U_KEY, _KEY), f"key 0: {_UNCOMPRESSED_HERE}"),
        )
    ),
    *(
        (ShDescriptor, _unpickled_wsh(inner), f"key 0: {refusal}")
        for key, refusal in ((_MUSIG, _MUSIG_HERE), (_KEY, _X_ONLY_HERE))
        for inner in (_unpickled_multi((key,)), _unpickled_pk(key))
    ),
    (
        ShDescriptor,
        _unpickled_wsh(_PARSED[WshDescriptor]),
        "wsh() is not allowed inside wsh()",
    ),
    (
        ShDescriptor,
        _unpickled_wsh(_PARSED[WpkhDescriptor]),
        "wpkh() is not allowed inside wsh()",
    ),
    (
        ShDescriptor,
        _unpickled_wsh(_unpickled_multi(_KEYS)),
        "multi() takes at most 20 keys, 21 given",
    ),
    (
        ShDescriptor,
        _unpickled_wsh(PkDescriptor(_U_KEY)),
        f"key 0: {_UNCOMPRESSED_HERE}",
    ),
    (
        ShDescriptor,
        _unpickled_wsh(_unpickled_wsh(PkDescriptor(_U_KEY))),
        "wsh() is not allowed inside wsh()",
    ),
    (
        ShDescriptor,
        _unpickled_wsh(_unpickled_wpkh(_U_KEY)),
        "wpkh() is not allowed inside wsh()",
    ),
    (
        ShDescriptor,
        _unpickled_wsh(_unpickled_multi(())),
        "multi() takes a threshold and at least one key",
    ),
    (
        ShDescriptor,
        _unpickled_wsh(_unpickled_sortedmulti(())),
        "sortedmulti() takes a threshold and at least one key",
    ),
    (
        ShDescriptor,
        _unpickled_wsh(RawDescriptor(bytes(MAX_SCRIPT_SIZE + 1))),
        (
            f"raw() inside wsh() is {MAX_SCRIPT_SIZE + 1} bytes,"
            f" over the {MAX_SCRIPT_SIZE}-byte limit"
        ),
    ),
]
_REFUSED_INSIDE_IDS = [
    "wsh-pk",
    "wsh-pkh",
    "wsh-multi",
    "wsh-sortedmulti",
    "wsh-miniscript",
    "wsh-21-keys",
    "sh-wpkh",
    "sh-21-keys",
    "wsh-no-keys",
    "sh-no-keys",
    "sh-547-bytes",
    "sh-531-bytes",
    *(
        f"{wrapper}-{inner}-{key}"
        for wrapper in ("wsh", "sh")
        for key in _TAPROOT_ONLY_IDS
        for inner in ("multi", "pk")
    ),
    "wsh-uncompressed-then-musig",
    "wsh-musig-then-uncompressed",
    "sh-uncompressed-then-musig",
    "sh-wsh-compressed-then-uncompressed",
    "sh-wsh-uncompressed-then-musig",
    "sh-wsh-uncompressed-then-x-only",
    "sh-wsh-compressed-uncompressed-musig",
    "sh-wsh-miniscript-uncompressed-then-musig",
    "sh-wsh-miniscript-uncompressed-then-x-only",
    *(
        f"sh-wsh-{inner}-{key}"
        for key in _TAPROOT_ONLY_IDS
        for inner in ("multi", "pk")
    ),
    "sh-wsh-wsh",
    "sh-wsh-wpkh",
    "sh-wsh-21-keys",
    "sh-wsh-uncompressed",
    "sh-wsh-wsh-uncompressed",
    "sh-wsh-wpkh-uncompressed",
    "sh-wsh-no-keys",
    "sh-wsh-sortedmulti-no-keys",
    "sh-wsh-raw-over-the-limit",
]


@pytest.mark.parametrize(
    "wrapper,inner,refusal", _REFUSED_INSIDE, ids=_REFUSED_INSIDE_IDS
)
def test_what_parse_refuses_inside_sh_or_wsh_is_refused_when_built(
    wrapper: type[ShDescriptor | WshDescriptor], inner: Descriptor, refusal: str
) -> None:
    """Built directly or by `replace`, with the message `parse` gives.

    A ``raw()`` over the size limit, directly inside either, is tried in
    `raw_descriptors_test`. Issues btclib-org/bip32-descriptors#175,
    btclib-org/bip32-descriptors#233 and btclib-org/bip32-descriptors#242.
    """
    err_msg = f"^{re.escape(refusal)}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(f"{_WRAPPERS[wrapper]}({inner})")
    with pytest.raises(BTClibValueError, match=err_msg):
        wrapper(inner)
    parsed = cast("ShDescriptor | WshDescriptor", _PARSED[wrapper])
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(parsed, inner=inner)


class _NoText:
    """A value whose `str` raises."""

    @override
    def __str__(self) -> str:
        raise RuntimeError("no text")


def test_a_value_with_no_text_raises_when_written_out() -> None:
    """The control of the no-text case: `str` cannot write `_NoText` out."""
    with pytest.raises(RuntimeError, match="^no text$"):
        str(_NoText())


@pytest.mark.parametrize(
    "value",
    [5, None, f"pk({_C})", _NoText()],
    ids=["int", "none", "str", "no-text"],
)
def test_an_unpickled_wsh_holding_no_descriptor_is_refused_inside_sh(
    value: Any,
) -> None:
    """Refused with `WshDescriptor`'s type error, directly or by `replace`.

    Issue btclib-org/bip32-descriptors#242.
    """
    err_msg = f"^invalid inner descriptor type: {type(value).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        WshDescriptor(value)
    inner = _unpickled_wsh(value)
    with pytest.raises(BTClibTypeError, match=err_msg):
        ShDescriptor(inner)
    parsed = cast("ShDescriptor", _PARSED[ShDescriptor])
    with pytest.raises(BTClibTypeError, match=err_msg):
        replace(parsed, inner=inner)


@pytest.mark.parametrize(
    "wrapper,inner",
    [
        (ShDescriptor, PkDescriptor(_U_KEY)),
        (ShDescriptor, MultiDescriptor(1, (_U_KEY,) * 7)),
        (ShDescriptor, MultiDescriptor(1, _KEYS[:15])),
        (WshDescriptor, MultiDescriptor(1, _KEYS[:20])),
    ],
    ids=["sh-pk", "sh-465-bytes", "sh-513-bytes", "wsh-20-keys"],
)
def test_a_key_or_size_parse_takes_inside_sh_or_wsh_is_built(
    wrapper: type[ShDescriptor | WshDescriptor], inner: Descriptor
) -> None:
    """The control: what `parse` reads there is built, and parses back."""
    assert parse(str(wrapper(inner))) == wrapper(inner)


# (wrapper, its argument holding a key) for each argument an unpickled
# copy of hands a key unchecked
_HOLDING_KEY: list[
    tuple[type[ShDescriptor | WshDescriptor], Callable[[Any], Descriptor]]
] = [
    (WshDescriptor, lambda key: _unpickled_and_v_pk(key, _C_KEY)),
    (ShDescriptor, lambda key: _unpickled_wsh(_unpickled_and_v_pk(key, _C_KEY))),
    (ShDescriptor, _unpickled_wpkh),
    (WshDescriptor, lambda key: _unpickled_multi((key,))),
    (ShDescriptor, lambda key: _unpickled_multi((key,))),
    (ShDescriptor, lambda key: _unpickled_wsh(_unpickled_multi((key,)))),
    (WshDescriptor, _unpickled_pk),
    (ShDescriptor, lambda key: _unpickled_wsh(_unpickled_sortedmulti((key,)))),
    # beside a fault `parse` names, which the key's type comes before
    (WshDescriptor, lambda key: _unpickled_multi((_U_KEY, key))),
    (ShDescriptor, lambda key: _unpickled_wsh(_unpickled_and_v_pk(_MUSIG, key))),
    (ShDescriptor, lambda key: _unpickled_multi((_KEY, key))),
    (WshDescriptor, lambda key: _unpickled_multi((*_KEYS[:20], key))),
    (ShDescriptor, lambda key: _unpickled_multi((*_KEYS[:15], key))),
]
_HOLDING_KEY_IDS = [
    "wsh-miniscript",
    "sh-wsh-miniscript",
    "sh-wpkh",
    "wsh-multi",
    "sh-multi",
    "sh-wsh-multi",
    "wsh-pk",
    "sh-wsh-sortedmulti",
    "wsh-uncompressed-then-key",
    "sh-wsh-miniscript-musig-then-key",
    "sh-x-only-then-key",
    "wsh-21-keys",
    "sh-547-bytes",
]


@pytest.mark.parametrize("key", ["abc", 5, None], ids=["str", "int", "none"])
@pytest.mark.parametrize("wrapper,holding", _HOLDING_KEY, ids=_HOLDING_KEY_IDS)
def test_a_key_of_another_type_inside_sh_or_wsh_is_refused_when_built(
    wrapper: type[ShDescriptor | WshDescriptor],
    holding: Callable[[Any], Descriptor],
    key: Any,
) -> None:
    """An unpickled argument skips its own check of the keys' type.

    Issue btclib-org/bip32-descriptors#257.
    """
    err_msg = f"^invalid key type: {type(key).__name__}$"
    with pytest.raises(BTClibTypeError, match=err_msg):
        wrapper(holding(key))


_WPKH_INSIDE_WSH = r"^wpkh\(\) is not allowed inside wsh\(\)$"


@pytest.mark.parametrize("key", ["abc", 5, None], ids=["str", "int", "none"])
@pytest.mark.parametrize(
    "wrapper,holding,refusal",
    [
        (WshDescriptor, _unpickled_wpkh, _WPKH_INSIDE_WSH),
        (
            ShDescriptor,
            lambda key: _unpickled_and_v_pk(key, _C_KEY),
            MINISCRIPT_OUTSIDE,
        ),
        (
            ShDescriptor,
            lambda key: _unpickled_wsh(_unpickled_wpkh(key)),
            _WPKH_INSIDE_WSH,
        ),
    ],
    ids=["wsh-wpkh", "sh-miniscript", "sh-wsh-wpkh"],
)
def test_an_argument_parse_refuses_by_function_is_refused_before_its_key_type(
    wrapper: type[ShDescriptor | WshDescriptor],
    holding: Callable[[Any], Descriptor],
    refusal: str,
    key: Any,
) -> None:
    """The function is named before the key's type.

    Issue btclib-org/bip32-descriptors#257.
    """
    with pytest.raises(BTClibValueError, match=refusal):
        wrapper(holding(key))


@pytest.mark.parametrize(
    "script,context",
    [
        (b"\x21" + _OFF_CURVE + b"\xac", miniscript.P2WSH),
        (b"\x20" + _OFF_CURVE[1:] + b"\xac", miniscript.TAPSCRIPT),
    ],
    ids=["p2wsh", "tapscript"],
)
def test_a_script_holding_no_point_reads_back_as_no_miniscript(
    script: bytes, context: str
) -> None:
    """`from_script` refuses the key as `KeyExpression` does."""
    with pytest.raises(EccValueError, match="^not a public key$"):
        miniscript.from_script(script, context)
    assert not miniscript.reads_back(script, context)


@pytest.mark.parametrize(
    "name,value",
    [
        ("xkey", _RANGED_KEY.xkey),
        ("participants", _MUSIG.participants),
        ("der_path", (1,)),
        ("wildcard", 0),
    ],
)
def test_a_pub_key_beside_another_key_or_a_derivation_is_refused(
    name: str, value: Any
) -> None:
    """`parse` would not read what `str` writes back as this key."""
    with pytest.raises(BTClibValueError, match=f"^a pub_key takes no {name}$"):
        replace(_C_KEY, **{name: value})


@pytest.mark.parametrize(
    "key", [_C_KEY, _RANGED_KEY, _MUSIG], ids=["pub_key", "xkey", "musig"]
)
@pytest.mark.parametrize("hardening", ["x", "H", ""])
def test_a_hardening_symbol_bip380_does_not_allow_is_refused(
    key: KeyExpression, hardening: str
) -> None:
    """A symbol BIP380 does not allow, an uppercase H included."""
    err_msg = "^invalid hardening symbol: h or ' expected$"
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(key, hardening=hardening)


def test_a_hardening_symbol_of_another_type_is_refused() -> None:
    """The symbol is text, as `parse` reads it."""
    with pytest.raises(BTClibTypeError, match="^invalid hardening type: int$"):
        KeyExpression(pub_key=bytes.fromhex(_C), hardening=1)  # type: ignore[arg-type]


@pytest.mark.parametrize("hardening", ["h", "'"])
def test_a_key_of_either_hardening_symbol_is_built(hardening: str) -> None:
    """The control: either symbol BIP380 allows is built."""
    for key in (_C_KEY, _RANGED_KEY):
        rebuilt = replace(key, hardening=hardening)
        assert rebuilt.hardening == hardening


_XPUB_A = xpub_from_xprv(rootxprv_from_seed(bytes(32)))
_XPUB_B = xpub_from_xprv(rootxprv_from_seed(b"\x01" * 32))
_FIXED_A = KeyExpression(pub_key=bytes.fromhex(_K))
_FIXED_B = KeyExpression(pub_key=bytes.fromhex(_K2))
_EXTENDED = (KeyExpression(xkey=_XPUB_A), KeyExpression(xkey=_XPUB_B))
(_ORIGIN_KEY,) = parse(f"wpkh([deadbeef/1h]{_K})").key_expressions
_MUSIG_PAIR = (_FIXED_A, _FIXED_B)


@pytest.mark.parametrize(
    "values,err_msg,text",
    [
        (
            {"participants": _MUSIG_PAIR, "origin": _ORIGIN_KEY.origin},
            "musig() cannot be nested inside a key origin",
            f"tr([deadbeef/1h]musig({_K},{_K2}))",
        ),
        (
            {"participants": (KeyExpression(participants=_MUSIG_PAIR), _FIXED_A)},
            "Too many ')' in musig() expression",
            f"tr(musig(musig({_K},{_K2}),{_K}))",
        ),
        (
            {"participants": (replace(_FIXED_A, x_only=True), _FIXED_B)},
            "musig(): x-only public keys are allowed in a taproot key expression only",
            f"tr(musig({_K[2:]},{_K2}))",
        ),
        (
            {"participants": (KeyExpression(pub_key=_UNCOMPRESSED), _FIXED_B)},
            "musig(): uncompressed public keys are not allowed here",
            f"tr(musig({_UNCOMPRESSED.hex()},{_K2}))",
        ),
        (
            {"participants": _MUSIG_PAIR, "der_path": (1,)},
            "musig() derivation requires every participant to be extended",
            f"tr(musig({_K},{_K2})/1)",
        ),
        (
            {"participants": _MUSIG_PAIR, "wildcard": 0},
            "musig() derivation requires every participant to be extended",
            f"tr(musig({_K},{_K2})/*)",
        ),
        (
            {
                "participants": (replace(_EXTENDED[0], wildcard=0), _EXTENDED[1]),
                "der_path": (1,),
            },
            "musig() cannot have a ranged participant and derivation too",
            f"tr(musig({_XPUB_A}/*,{_XPUB_B})/1)",
        ),
        (
            {"participants": _EXTENDED, "wildcard": 2**31},
            "musig() cannot have a hardened wildcard",
            f"tr(musig({_XPUB_A},{_XPUB_B})/*h)",
        ),
        (
            {"participants": _EXTENDED, "der_path": (2**31,)},
            "musig() cannot have hardened derivation steps",
            f"tr(musig({_XPUB_A},{_XPUB_B})/0h)",
        ),
    ],
    ids=[
        "origin",
        "nested",
        "x-only participant",
        "uncompressed participant",
        "path, fixed participant",
        "wildcard, fixed participant",
        "path, ranged participant",
        "hardened wildcard",
        "hardened step",
    ],
)
def test_a_musig_parse_refuses_is_refused_when_built(
    values: dict[str, Any], err_msg: str, text: str
) -> None:
    """With the message `parse` gives after the position of the key."""
    with pytest.raises(BTClibValueError, match=f"^key [0-9]+: {re.escape(err_msg)}$"):
        parse(text)
    with pytest.raises(BTClibValueError, match=f"^{re.escape(err_msg)}$"):
        KeyExpression(**values)


def test_a_musig_with_an_xkey_is_refused() -> None:
    """`str` writes the ``musig()`` alone; `parse` has no message for it."""
    with pytest.raises(BTClibValueError, match=r"^a musig\(\) takes no xkey$"):
        KeyExpression(xkey=_XPUB_A, participants=_MUSIG_PAIR)


@pytest.mark.parametrize(
    "values,err_msg",
    [
        ({"participants": (_FIXED_A, _K2)}, "invalid participant type: str"),
        (
            {"participants": _EXTENDED, "der_path": ("1",)},
            "invalid derivation index type: str",
        ),
        ({"xkey": _XPUB_A, "wildcard": "*"}, "invalid wildcard type: str"),
        ({"xkey": _XPUB_A, "wildcard": True}, "invalid wildcard type: bool"),
        ({"der_path": [1]}, "invalid der_path type: list"),
        ({"der_path": 1}, "invalid der_path type: int"),
        ({"participants": [_FIXED_A, _FIXED_B]}, "invalid participants type: list"),
        ({"participants": 1}, "invalid participants type: int"),
        ({"participants": _FIXED_A}, "invalid participants type: KeyExpression"),
    ],
    ids=[
        "participant",
        "musig step",
        "wildcard",
        "bool wildcard",
        "der_path list",
        "der_path int",
        "participants list",
        "participants int",
        "participants KeyExpression",
    ],
)
def test_a_key_field_of_another_type_is_refused(
    values: dict[str, Any], err_msg: str
) -> None:
    """A key expression checks the type of its fields when built.

    ``der_path`` and ``participants`` are tuples; a participant is a
    `KeyExpression`, a step and a wildcard an int.
    """
    with pytest.raises(BTClibTypeError, match=f"^{err_msg}$"):
        KeyExpression(**values)


@pytest.mark.parametrize(
    "values",
    [
        {"xkey": _XPUB_A, "wildcard": 5},
        {"xkey": _XPUB_A, "wildcard": -1},
        {"participants": _EXTENDED, "wildcard": 5},
    ],
    ids=["xkey 5", "xkey -1", "musig 5"],
)
def test_a_wildcard_parse_never_reads_is_refused(values: dict[str, Any]) -> None:
    """`parse` reads what `str` writes for it as 0 or 2**31."""
    with pytest.raises(
        BTClibValueError, match=r"^invalid wildcard: None, 0 or 2\*\*31 expected$"
    ):
        KeyExpression(**values)


@pytest.mark.parametrize(
    "key",
    [
        KeyExpression(xkey=_XPUB_A),
        KeyExpression(xkey=_XPUB_A, wildcard=0),
        KeyExpression(xkey=_XPUB_A, wildcard=2**31),
        KeyExpression(participants=_MUSIG_PAIR),
        KeyExpression(participants=_EXTENDED, der_path=(1,), wildcard=0),
        KeyExpression(participants=(replace(_EXTENDED[0], wildcard=0), _EXTENDED[1])),
    ],
    ids=["xkey", "wildcard", "hardened wildcard", "musig", "musig path", "ranged"],
)
def test_a_key_parse_builds_is_built_and_read_back(key: KeyExpression) -> None:
    """The control: what `str` writes, `parse` reads back as the key."""
    assert parse(str(TrDescriptor(key))).key_expressions == (key,)


def test_a_musig_of_wallet_policy_placeholders_is_built() -> None:
    """The control: the stand-ins `wallet_policy` writes for a ``musig()``."""
    descriptor = parse(f"tr(musig({_XPUB_A},{_XPUB_B})/*)")
    template, _ = descriptors_module.wallet_policy(descriptor)
    assert template == "tr(musig(@0,@1)/*)"
    placeholders = tuple(KeyExpression(xkey=f"@{i}") for i in range(2))
    assert KeyExpression(participants=placeholders, wildcard=0).is_aggregate


@pytest.mark.parametrize(
    "build",
    [
        lambda: replace(_MUSIG, hardening="'"),
        lambda: KeyExpression(participants=_MUSIG_PAIR, hardening="'"),
        lambda: KeyExpression(
            participants=_EXTENDED, der_path=(1,), wildcard=0, hardening="'"
        ),
    ],
    ids=["replace", "musig", "musig path"],
)
def test_a_musig_whose_hardening_is_not_h_is_refused(
    build: Callable[[], KeyExpression],
) -> None:
    """`str` writes it as the ``musig()`` with h, which `parse` reads back."""
    err_msg = r"^invalid musig\(\) hardening symbol: h expected$"
    with pytest.raises(BTClibValueError, match=err_msg):
        build()


def test_a_musig_parse_builds_has_the_hardening_h() -> None:
    """The control: whatever symbol its participants are spelled with."""
    text = f"tr(musig([deadbeef/1']{_XPUB_A}/0'/1,{_XPUB_B})/2/*)"
    (key,) = parse(text).key_expressions
    assert key.hardening == "h"
    assert key.participants[0].hardening == "'"
    assert parse(str(TrDescriptor(key))).key_expressions == (key,)


def test_an_odd_x_only_key_is_refused_as_parse_lifts_it() -> None:
    """`parse` holds the odd key of a WIF in a ``tr()`` as its even-y form."""
    odd = b58.prv_key_data_from_wif(_ODD_WIF).pub.sec
    assert odd[0] == 3
    (key,) = parse(f"tr({_ODD_WIF})").key_expressions
    assert key == KeyExpression(pub_key=b"\x02" + odd[1:], x_only=True)
    with pytest.raises(BTClibValueError, match="^invalid x-only key prefix: 0x03$"):
        KeyExpression(pub_key=odd, x_only=True)
    with pytest.raises(BTClibValueError, match="^invalid x-only key prefix: 0x03$"):
        replace(key, pub_key=odd)
    # the control: the same key is built where it is not x-only
    assert KeyExpression(pub_key=odd).pub_key == odd


# P2WSH miniscripts whose text `parse` reads as a descriptor function, and
# the fragment it reads
_READ_AS_FUNCTION = [
    (f"pk({_K})", PkDescriptor),
    (f"c:pk_k({_K})", PkDescriptor),
    (f"pkh({_K})", PkhDescriptor),
    (f"c:pk_h({_K})", PkhDescriptor),
    (f"multi(1,{_K},{_K2})", MultiDescriptor),
    (f"rawpkh({'00' * 20})", RawPkhDescriptor),
]


@pytest.mark.parametrize(
    "expression,cls",
    _READ_AS_FUNCTION,
    ids=[e.partition("(")[0] for e, _ in _READ_AS_FUNCTION],
)
def test_a_miniscript_parse_reads_as_a_function_is_refused_when_built(
    expression: str, cls: type[Descriptor]
) -> None:
    """Built directly or by `replace`, naming the function.

    Inside ``wsh()`` its text parses back as that function, and so does
    the expression. Issue btclib-org/bip32-descriptors#174.
    """
    node = miniscript.parse(expression)
    read = cast("WshDescriptor", parse(f"wsh({node})"))
    assert type(read.inner) is cls
    assert parse(f"wsh({expression})") == read
    name = re.escape(str(node).partition("(")[0])
    err_msg = rf"^parse reads {name}\(\) as a descriptor function, not a miniscript$"
    with pytest.raises(BTClibValueError, match=err_msg):
        MiniscriptDescriptor(node)
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(cast("MiniscriptDescriptor", _PARSED[MiniscriptDescriptor]), node=node)


@pytest.mark.parametrize("template", ["wsh({})", "sh(wsh({}))"])
@pytest.mark.parametrize(
    "written,read_as",
    [(f"c:pk_k({_K})", f"pk({_K})"), (f"c:pk_h({_K})", f"pkh({_K})")],
    ids=["c:pk_k", "c:pk_h"],
)
def test_parse_reads_a_miniscript_written_as_a_function_as_that_function(
    written: str, read_as: str, template: str
) -> None:
    """Which its text parses back to, as no `MiniscriptDescriptor` would."""
    parsed = parse(template.format(written))
    assert parsed == parse(template.format(read_as))
    assert parse(str(parsed)) == parsed


@pytest.mark.parametrize(
    "wif,network",
    [
        (b58.wif_from_prv_key(1, "mainnet", compressed=True), "regtest"),
        (b58.wif_from_prv_key(1, "testnet", compressed=True), "mainnet"),
    ],
    ids=["mainnet-wif-on-regtest", "testnet-wif-on-mainnet"],
)
@pytest.mark.parametrize(
    "template",
    [
        "wsh(c:pk_k({}))",
        "wsh(c:pk_h({}))",
        "sh(wsh(c:pk_k({})))",
        "sh(wsh(c:pk_h({})))",
    ],
)
def test_a_miniscript_read_as_a_function_keeps_its_wif_network_check(
    template: str, wif: str, network: str
) -> None:
    """A WIF of another network is refused, as inside ``pk()``."""
    err_msg = rf"^key 0: not a {network} key: WIF prefix$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(f"wsh(pk({wif}))", network)
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(template.format(wif), network)


@pytest.mark.parametrize("template", ["wpkh({})", "sh(wpkh({}))"])
def test_an_uncompressed_wpkh_key_is_refused_when_built(template: str) -> None:
    """Built directly or by `replace`, with the message `parse` gives."""
    err_msg = f"^key 0: {_UNCOMPRESSED_HERE}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(template.format(_U_KEY))
    with pytest.raises(BTClibValueError, match=err_msg):
        WpkhDescriptor(_U_KEY)
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(cast("WpkhDescriptor", _PARSED[WpkhDescriptor]), key=_U_KEY)


# (wrapper, the template of its text)
_MULTI_WRAPPERS: list[tuple[Callable[[Descriptor], Descriptor], str]] = [
    (lambda inner: inner, "{}"),
    (ShDescriptor, "sh({})"),
    (WshDescriptor, "wsh({})"),
]


@pytest.mark.parametrize("wrapper,template", _MULTI_WRAPPERS, ids=["bare", "sh", "wsh"])
@pytest.mark.parametrize(
    "threshold,keys,sort,refusal",
    [
        (0, _KEYS[:1], False, "invalid k in k-of-n multi: 0"),
        (2, _KEYS[:1], False, "invalid k in k-of-n multi: 2"),
        (0, _KEYS[:1], True, "invalid k in k-of-n sortedmulti: 0"),
        (2**32, _KEYS[:1], False, "invalid multi() threshold: not in 0..2**32-1"),
        (1, _KEYS, False, "multi() takes at most 20 keys, 21 given"),
        (1, _KEYS, True, "sortedmulti() takes at most 20 keys, 21 given"),
        (0, _KEYS, False, "multi() takes at most 20 keys, 21 given"),
        (0, _KEYS[:16], False, "invalid k in k-of-n multi: 0"),
        (17, _KEYS[:16], False, "invalid k in k-of-n multi: 17"),
        (1, (), False, "multi() takes a threshold and at least one key"),
        (0, (), True, "sortedmulti() takes a threshold and at least one key"),
    ],
    ids=[
        "k-0",
        "k-over-n",
        "sorted-k-0",
        "k-over-uint32",
        "21-keys",
        "sorted-21-keys",
        "k-0-of-21-keys",
        "k-0-of-16-keys",
        "k-17-of-16-keys",
        "no-keys",
        "sorted-k-0-of-no-keys",
    ],
)
def test_a_multi_k_or_n_parse_refuses_is_refused_when_built(
    threshold: int,
    keys: tuple[KeyExpression, ...],
    sort: bool,
    refusal: str,
    wrapper: Callable[[Descriptor], Descriptor],
    template: str,
) -> None:
    """Built directly or by `replace`, with the message `parse` gives.

    In `parse`'s order: the threshold Bitcoin Core reads, the keys, their
    number, the threshold against it, then the size of the redeem script
    inside ``sh()``.
    """
    name = "sortedmulti" if sort else "multi"
    arguments = ",".join([str(threshold), *map(str, keys)])
    text = template.format(f"{name}({arguments})")
    err_msg = f"^{re.escape(refusal)}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(text)
    with pytest.raises(BTClibValueError, match=err_msg):
        wrapper(MultiDescriptor(threshold, keys, sort=sort))
    parsed = cast("MultiDescriptor", _PARSED[MultiDescriptor])
    with pytest.raises(BTClibValueError, match=err_msg):
        wrapper(replace(parsed, threshold=threshold, keys=keys, sort=sort))


@pytest.mark.parametrize("sort", [False, True])
def test_a_negative_multi_threshold_is_refused_before_the_keys(sort: bool) -> None:
    """As one over 2**32-1 is: Bitcoin Core reads neither.

    `parse` cannot write one, a minus sign being no digit.
    """
    name = "sortedmulti" if sort else "multi"
    err_msg = rf"^invalid {name}\(\) threshold: not in 0\.\.2\*\*32-1$"
    with pytest.raises(BTClibValueError, match=err_msg):
        MultiDescriptor(-1, _KEYS, sort=sort)
    parsed = cast("MultiDescriptor", _PARSED[MultiDescriptor])
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(parsed, threshold=-1, keys=_KEYS, sort=sort)


@pytest.mark.parametrize("sort", [False, True])
def test_a_bare_multi_of_four_keys_builds_and_writes_what_parse_refuses(
    sort: bool,
) -> None:
    """The bound of three keys on a bare ``multi()`` is `parse`'s alone.

    The same value is valid inside ``sh()`` and ``wsh()``, and
    `infer_descriptor` answers the ``raw()`` of its bare script.
    """
    name = "sortedmulti" if sort else "multi"
    multi = MultiDescriptor(1, _KEYS[:4], sort=sort)
    script_pub_key = multi.script_pub_key()
    assert script_pub_key.type == "p2ms"
    text = str(multi)
    err_msg = rf"^a bare {name}\(\) takes at most 3 keys, 4 given$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(text)
    for wrapper in (ShDescriptor, WshDescriptor):
        wrapped = wrapper(multi)
        assert parse(str(wrapped)).script_pub_key() == wrapped.script_pub_key()
    raw = add_checksum(f"raw({script_pub_key.script.hex()})")
    assert infer_descriptor(script_pub_key.script, Provider()) == raw


@pytest.mark.parametrize(
    "text,parse_refusal,build,build_refusal",
    [
        (
            f"wsh(multi(3,{_C_KEY},{_U_KEY}))",
            f"key 1: {_UNCOMPRESSED_HERE}",
            lambda: WshDescriptor(MultiDescriptor(3, (_C_KEY, _U_KEY))),
            "invalid k in k-of-n multi: 3",
        ),
        (
            f"wsh(wpkh({_U_KEY}))",
            "wpkh() is not allowed inside wsh()",
            lambda: WshDescriptor(WpkhDescriptor(_U_KEY)),
            f"key 0: {_UNCOMPRESSED_HERE}",
        ),
        (
            f"sh(sh(multi(0,{_C_KEY})))",
            "sh() is not allowed inside sh()",
            lambda: ShDescriptor(ShDescriptor(MultiDescriptor(0, (_C_KEY,)))),
            "invalid k in k-of-n multi: 0",
        ),
    ],
    ids=["wsh-multi-key", "wsh-wpkh-function", "sh-sh-function"],
)
def test_an_argument_invalid_by_itself_names_its_own_fault_first(
    text: str, parse_refusal: str, build: Callable[[], object], build_refusal: str
) -> None:
    """Where `parse` names the wrapper's fault, which it reads first.

    The argument refuses its own fault when built, before the wrapper
    sees it.
    """
    with pytest.raises(BTClibValueError, match=f"^{re.escape(parse_refusal)}$"):
        parse(text)
    with pytest.raises(BTClibValueError, match=f"^{re.escape(build_refusal)}$"):
        build()


@pytest.mark.parametrize(
    "size,refusal",
    [
        (0, "Rawpkh hash is not hex"),
        (19, "160 bits digest expected"),
        (21, "160 bits digest expected"),
    ],
    ids=["empty", "19-bytes", "21-bytes"],
)
@pytest.mark.parametrize(
    "template", ["rawpkh({})", "sh(rawpkh({}))", "wsh(rawpkh({}))"]
)
def test_a_rawpkh_hash_of_other_than_20_bytes_is_refused_when_built(
    size: int, refusal: str, template: str
) -> None:
    """Built directly or by `replace`, with the message `parse` gives.

    An empty hash is what `parse` reads as no hex. An unpickled one skips
    that check, and refuses to give its script.
    """
    key_hash = b"\xab" * size
    err_msg = f"^{refusal}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(template.format(key_hash.hex()))
    with pytest.raises(BTClibValueError, match=err_msg):
        RawPkhDescriptor(key_hash)
    parsed = cast("RawPkhDescriptor", _PARSED[RawPkhDescriptor])
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(parsed, key_hash=key_hash)
    unpickled: RawPkhDescriptor = pickle.loads(pickle.dumps(parsed))  # noqa: S301
    object.__setattr__(unpickled, "key_hash", key_hash)
    with pytest.raises(BTClibValueError, match=err_msg):
        unpickled.script_pub_key()


_TAPSCRIPT = miniscript.TAPSCRIPT


@pytest.mark.parametrize(
    "context,fragment,keys,threshold",
    [
        (_P2WSH, "pk_k", (_U_KEY,), 0),
        (_P2WSH, "multi", (_C_KEY, _U_KEY), 1),
        (_TAPSCRIPT, "pk_k", (_U_KEY,), 0),
        (_TAPSCRIPT, "multi_a", (_KEY2, _U_KEY), 1),
    ],
    ids=["p2wsh-pk_k", "p2wsh-multi", "tapscript-pk_k", "tapscript-multi_a"],
)
def test_an_uncompressed_key_in_a_miniscript_node_is_refused_when_built(
    context: str, fragment: str, keys: tuple[KeyExpression, ...], threshold: int
) -> None:
    """Built directly or by `replace`, with the message `parse` gives."""
    text = ",".join(map(str, keys))
    if threshold:
        text = f"{threshold},{text}"
    err_msg = f"^{_UNCOMPRESSED_HERE}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        miniscript.parse(f"{fragment}({text})", context)
    with pytest.raises(BTClibValueError, match=err_msg):
        miniscript.Miniscript(fragment, context, keys=keys, threshold=threshold)
    built = miniscript.Miniscript(
        fragment, context, keys=_KEYS[: len(keys)], threshold=threshold
    )
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(built, keys=keys)


@pytest.mark.parametrize("last", [False, True], ids=["first", "last"])
@pytest.mark.parametrize(
    "context,fragment,at_limit",
    [(_P2WSH, "multi", _KEYS[:20]), (_TAPSCRIPT, "multi_a", (_KEY2,) * 999)],
    ids=["p2wsh-multi", "tapscript-multi_a"],
)
def test_an_uncompressed_key_is_refused_before_the_number_of_keys(
    context: str, fragment: str, at_limit: tuple[KeyExpression, ...], last: bool
) -> None:
    """In a node of one key over its limit, as `miniscript.parse` reads it."""
    keys = list(at_limit)
    keys.insert(len(keys) if last else 0, _U_KEY)
    err_msg = f"^{_UNCOMPRESSED_HERE}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        miniscript.parse(f"{fragment}(1,{','.join(map(str, keys))})", context)
    with pytest.raises(BTClibValueError, match=err_msg):
        miniscript.Miniscript(fragment, context, keys=tuple(keys), threshold=1)


def _unpickled_multi_a(keys: tuple[KeyExpression, ...]) -> MultiA:
    """Return ``multi_a(1,KEY,...)``, unpickled.

    `MultiA` refuses an uncompressed key when built, and unpickling skips
    that check, so the keys are given to an unpickled copy.
    """
    multi_a: MultiA = pickle.loads(pickle.dumps(MultiA(1, (_KEY2,))))  # noqa: S301
    object.__setattr__(multi_a, "keys", keys)
    return multi_a


def _tapscript_and_v_older(key: KeyExpression) -> miniscript.Miniscript:
    """Return the tapscript ``and_v(v:pk(KEY),older(1))``, unpickled.

    A tapscript `Miniscript` node refuses an uncompressed key when built,
    and unpickling skips that check, so the key is given to an unpickled
    copy.
    """
    expression = f"and_v(v:pk({_X2}),older(1))"
    node = _unpickled(miniscript.parse(expression, _TAPSCRIPT))
    object.__setattr__(node.subs[0].subs[0].subs[0], "keys", (key,))
    return node


@pytest.mark.parametrize(
    "internal_key,tree,text,position",
    [
        (_U_KEY, None, f"tr({_U_KEY})", 0),
        (_KEY, _U_KEY, f"tr({_X},pk({_U_KEY}))", 1),
        (_KEY, (_KEY2, _U_KEY), f"tr({_X},{{pk({_X2}),pk({_U_KEY})}})", 2),
        (
            _KEY,
            _unpickled_multi_a((_KEY2, _U_KEY)),
            f"tr({_X},multi_a(1,{_X2},{_U_KEY}))",
            2,
        ),
        (
            _KEY,
            _tapscript_and_v_older(_U_KEY),
            f"tr({_X},and_v(v:pk({_U_KEY}),older(1)))",
            1,
        ),
        (_MUSIG, _U_KEY, f"tr({_MUSIG},pk({_U_KEY}))", 3),
        (_KEY, (_MUSIG, _U_KEY), f"tr({_X},{{pk({_MUSIG}),pk({_U_KEY})}})", 4),
        (
            _KEY,
            (_MUSIG, _unpickled_multi_a((_KEY2, _U_KEY))),
            f"tr({_X},{{pk({_MUSIG}),multi_a(1,{_X2},{_U_KEY})}})",
            5,
        ),
    ],
    ids=[
        "internal",
        "pk-leaf",
        "second-leaf",
        "multi_a-leaf",
        "miniscript-leaf",
        "after-musig-internal",
        "after-musig-leaf",
        "multi_a-after-musig-leaf",
    ],
)
def test_an_uncompressed_tr_key_is_refused_when_built(
    internal_key: KeyExpression, tree: Any, text: str, position: int
) -> None:
    """Built directly or by `replace`, with the message `parse` gives.

    The position counts a ``musig()`` as each of its participants and
    itself, as `parse` does. A leaf that refuses the key itself when
    built is given it unpickled.
    """
    err_msg = f"^key {position}: {_UNCOMPRESSED_HERE}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(text)
    with pytest.raises(BTClibValueError, match=err_msg):
        TrDescriptor(internal_key, tree)
    parsed = cast("TrDescriptor", _PARSED[TrDescriptor])
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(parsed, internal_key=internal_key, tree=tree)


def test_an_uncompressed_internal_key_is_refused_before_the_tree() -> None:
    """As `parse` reads them, before a tree deeper than `parse` reads."""
    levels = 129
    text = f"{{pk({_X2})," * levels + f"pk({_X2})" + "}" * levels
    tree: Any = _KEY2
    for _ in range(levels):
        tree = (_KEY2, tree)
    err_msg = r"^tr\(\) supports at most 128 nesting levels$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(f"tr({_X},{text})")
    with pytest.raises(BTClibValueError, match="^script tree deeper than 128$"):
        TrDescriptor(_KEY, tree)
    err_msg = f"^key 0: {_UNCOMPRESSED_HERE}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(f"tr({_U_KEY},{text})")
    with pytest.raises(BTClibValueError, match=err_msg):
        TrDescriptor(_U_KEY, tree)


@pytest.mark.parametrize(
    "threshold,keys",
    [(1, (_KEY2, _U_KEY)), (3, (_KEY2, _U_KEY)), (1, (*(_KEY2,) * 999, _U_KEY))],
    ids=["k-1", "k-over-n", "n-over-999"],
)
@pytest.mark.parametrize("sort", [False, True], ids=["multi_a", "sortedmulti_a"])
def test_an_uncompressed_multi_a_key_is_refused_when_built(
    threshold: int, keys: tuple[KeyExpression, ...], sort: bool
) -> None:
    """Built directly or by `replace`, before k and n, as `parse` reads them.

    The message is `parse`'s without the key's position in the ``tr()``,
    which the leaf does not know.
    """
    name = "sortedmulti_a" if sort else "multi_a"
    arguments = ",".join([str(threshold), *map(str, keys)])
    err_msg = f"^key {len(keys)}: {_UNCOMPRESSED_HERE}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(f"tr({_X},{name}({arguments}))")
    err_msg = f"^{_UNCOMPRESSED_HERE}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        MultiA(threshold, keys, sort=sort)
    built = MultiA(1, (_KEY2,), sort=sort)
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(built, threshold=threshold, keys=keys)


def test_an_uncompressed_rawtr_key_is_refused_when_built() -> None:
    """Built directly or by `replace`, with the message `parse` gives."""
    err_msg = f"^key 0: {_UNCOMPRESSED_HERE}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(f"rawtr({_U_KEY})")
    with pytest.raises(BTClibValueError, match=err_msg):
        RawTrDescriptor(_U_KEY)
    parsed = cast("RawTrDescriptor", _PARSED[RawTrDescriptor])
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(parsed, key=_U_KEY)


# keys that are none of `_KEY`, `_KEY2`, `_U_KEY` and `_KEYS`, which the
# tests below hold beside them
_X_KEYS = tuple(
    KeyExpression(pub_key=b"\x02" + PrvKeyData(i).pub.sec[1:], x_only=True)
    for i in range(44, 1045)
)
_C_KEYS = tuple(KeyExpression(pub_key=PrvKeyData(i).pub.sec) for i in range(22, 44))
_X_ONLY_HERE = "x-only public keys are allowed in a taproot key expression only"
# each fragment holding keys, the number of keys over its limit, and the
# expression it is read from in each context, with the path to its node
_HOLDING: dict[str, tuple[int, str, str, tuple[int, ...]]] = {
    "pk_k": (2, "and_v(v:pk({}),pk({}))", "and_v(v:pk({}),pk({}))", (1, 0)),
    "pk_h": (2, "and_v(v:pk({}),pkh({}))", "and_v(v:pk({}),pkh({}))", (1, 0)),
    "multi": (21, "and_v(v:pk({}),multi_a(1,{}))", "and_v(v:pk({}),multi(1,{}))", (1,)),
    "multi_a": (
        1000,
        "and_v(v:pk({}),multi_a(1,{}))",
        "and_v(v:pk({}),multi(1,{}))",
        (1,),
    ),
}


def _holding(
    fragment: str, context: str, keys: tuple[KeyExpression, ...]
) -> miniscript.Miniscript:
    """Return an unpickled node whose node of `fragment` holds `keys`.

    Unpickling skips `Miniscript`'s own checks, so a multisig of the other
    context is read as the context's own and given the fragment.
    """
    _, tapscript, p2wsh, path = _HOLDING[fragment]
    expression = tapscript if context == _TAPSCRIPT else p2wsh
    own = _X_KEYS if context == _TAPSCRIPT else _C_KEYS
    root = _unpickled(miniscript.parse(expression.format(own[0], own[1]), context))
    node = root
    for index in path:
        node = node.subs[index]
    object.__setattr__(node, "fragment", fragment)
    object.__setattr__(node, "keys", keys)
    return root


def _node_at(
    root: miniscript.Miniscript, path: tuple[int, ...]
) -> miniscript.Miniscript:
    """Return the node `path` reaches from `root`."""
    for index in path:
        root = root.subs[index]
    return root


_WRAPPED: dict[str, tuple[str, Callable[[miniscript.Miniscript], Descriptor]]] = {
    "tr": (_TAPSCRIPT, lambda node: TrDescriptor(_KEY, node)),
    "bare": (_P2WSH, MiniscriptDescriptor),
    "wsh": (_P2WSH, lambda node: WshDescriptor(MiniscriptDescriptor(node))),
    "sh-wsh": (
        _P2WSH,
        lambda node: ShDescriptor(WshDescriptor(MiniscriptDescriptor(node))),
    ),
}


@pytest.mark.parametrize("wrapped", _WRAPPED)
@pytest.mark.parametrize("too_many", [False, True], ids=["no-key", "too-many"])
@pytest.mark.parametrize("fragment", _HOLDING)
def test_a_node_holding_a_number_of_keys_its_fragment_does_not_take_is_refused(
    fragment: str, too_many: bool, wrapped: str
) -> None:
    """With the message the node's own build gives, before its text is written.

    A multisig of the other context is refused for its context, as its
    build refuses it. Issue btclib-org/bip32-descriptors#235.
    """
    context, wrap = _WRAPPED[wrapped]
    own = _X_KEYS if context == _TAPSCRIPT else _C_KEYS
    keys = own[:1] * (_HOLDING[fragment][0] if too_many else 0)
    if fragment in {"multi", "multi_a"} and (fragment == "multi") == (
        context == _TAPSCRIPT
    ):
        err_msg = (
            "multi() is not allowed in a tapscript"
            if fragment == "multi"
            else "multi_a() is only allowed in a tapscript"
        )
    else:
        err_msg = f"invalid number of keys in {fragment}: {len(keys)}"
    root = _holding(fragment, context, keys)
    node = _node_at(root, _HOLDING[fragment][3])
    with pytest.raises(BTClibValueError, match=f"^{re.escape(err_msg)}$"):
        replace(node, keys=keys)
    with pytest.raises(BTClibValueError, match=f"^{re.escape(err_msg)}$"):
        wrap(root)


# (fragment, context, the keys of its node, the refusal `parse` gives)
_KEY_BEFORE_NUMBER = [
    ("multi", _P2WSH, (_X_KEYS[0], *_C_KEYS[1:21]), f"key 1: {_X_ONLY_HERE}"),
    ("multi", _P2WSH, (_U_KEY, *_C_KEYS[1:21]), f"key 1: {_UNCOMPRESSED_HERE}"),
    ("pk_k", _P2WSH, (_X_KEYS[0], _C_KEYS[2]), f"key 1: {_X_ONLY_HERE}"),
    ("pk_k", _P2WSH, (_U_KEY, _C_KEYS[2]), f"key 1: {_UNCOMPRESSED_HERE}"),
    ("pk_h", _P2WSH, (_U_KEY, _C_KEYS[2]), f"key 1: {_UNCOMPRESSED_HERE}"),
    ("pk_k", _TAPSCRIPT, (_U_KEY, _X_KEYS[2]), f"key 2: {_UNCOMPRESSED_HERE}"),
    ("pk_h", _TAPSCRIPT, (_U_KEY, _X_KEYS[2]), f"key 2: {_UNCOMPRESSED_HERE}"),
    ("multi_a", _TAPSCRIPT, (_U_KEY, *_X_KEYS[1:1000]), f"key 2: {_UNCOMPRESSED_HERE}"),
]
_TEMPLATES = {"tr": f"tr({_X},{{}})", "wsh": "wsh({})", "sh-wsh": "sh(wsh({}))"}


@pytest.mark.parametrize(
    "wrapped,fragment,keys,refusal",
    [
        (wrapped, fragment, keys, refusal)
        for fragment, context, keys, refusal in _KEY_BEFORE_NUMBER
        for wrapped in (("tr",) if context == _TAPSCRIPT else ("wsh", "sh-wsh"))
    ],
)
def test_a_key_is_refused_before_the_number_of_keys_of_its_node(
    wrapped: str, fragment: str, keys: tuple[KeyExpression, ...], refusal: str
) -> None:
    """With the message `parse` gives, naming the key by its position.

    `parse` reads the keys of a node before it counts them, and so does
    the node's own build. Issue btclib-org/bip32-descriptors#235.
    """
    context, wrap = _WRAPPED[wrapped]
    root = _holding(fragment, context, keys)
    err_msg = f"^{re.escape(refusal)}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(_TEMPLATES[wrapped].format(root))
    with pytest.raises(BTClibValueError, match=err_msg):
        wrap(root)


# (fragment, the keys of its node, the refusal `parse` gives in each
# wrapper) where another node holds `_U_KEY`
_KEY_ELSEWHERE = [
    ("pk_k", 2, {"tr": "key 1", "wsh": "key 0", "sh-wsh": "key 0"}),
    ("multi", 21, {"wsh": "key 0", "sh-wsh": "key 0"}),
    ("multi_a", 1000, {"tr": "key 1"}),
]


@pytest.mark.parametrize(
    "wrapped,fragment,number,position",
    [
        (wrapped, fragment, number, position)
        for fragment, number, positions in _KEY_ELSEWHERE
        for wrapped, position in positions.items()
    ],
)
def test_a_key_another_node_holds_is_refused_before_the_number_of_keys(
    wrapped: str, fragment: str, number: int, position: str
) -> None:
    """With the message `parse` gives, as main gives it.

    The text of the node of the wrong count can be written, so the key
    check of ``tr()`` or ``wsh()`` names the key, and a bare
    `MiniscriptDescriptor` builds it. Issue
    btclib-org/bip32-descriptors#235.
    """
    context, wrap = _WRAPPED[wrapped]
    own = _X_KEYS if context == _TAPSCRIPT else _C_KEYS
    root = _holding(fragment, context, own[1 : number + 1])
    object.__setattr__(_node_at(root, (0, 0, 0)), "keys", (_U_KEY,))
    err_msg = f"^{position}: {_UNCOMPRESSED_HERE}$"
    with pytest.raises(BTClibValueError, match=err_msg):
        parse(_TEMPLATES[wrapped].format(root))
    with pytest.raises(BTClibValueError, match=err_msg):
        wrap(root)
    if context == _P2WSH:
        assert str(MiniscriptDescriptor(root)) == str(root)


@pytest.mark.parametrize("wrapped", _WRAPPED)
def test_a_pk_k_holding_no_key_is_refused_beside_an_uncompressed_key(
    wrapped: str,
) -> None:
    """For its number of keys: it has no text to write.

    Issue btclib-org/bip32-descriptors#235.
    """
    context, wrap = _WRAPPED[wrapped]
    root = _holding("pk_k", context, ())
    object.__setattr__(_node_at(root, (0, 0, 0)), "keys", (_U_KEY,))
    with pytest.raises(BTClibValueError, match="^invalid number of keys in pk_k: 0$"):
        wrap(root)


@pytest.mark.parametrize("wrapped", _WRAPPED)
def test_a_multisig_of_the_other_context_is_refused_before_its_keys(
    wrapped: str,
) -> None:
    """For its context, as its build refuses it, even holding a refused key.

    Issue btclib-org/bip32-descriptors#235.
    """
    context, wrap = _WRAPPED[wrapped]
    if context == _TAPSCRIPT:
        fragment, keys = "multi", (_U_KEY, *_X_KEYS[1:21])
        err_msg = "^multi\\(\\) is not allowed in a tapscript$"
    else:
        fragment, keys = "multi_a", (_U_KEY, *_C_KEYS[1:2] * 999)
        err_msg = "^multi_a\\(\\) is only allowed in a tapscript$"
    root = _holding(fragment, context, keys)
    with pytest.raises(BTClibValueError, match=err_msg):
        replace(_node_at(root, (1,)), keys=keys)
    with pytest.raises(BTClibValueError, match=err_msg):
        wrap(root)


@pytest.mark.parametrize("wrapped", ["tr", "bare"])
@pytest.mark.parametrize("fault", ["context", "type"])
def test_a_node_s_type_or_context_is_refused_before_another_node_s_keys(
    wrapped: str, fault: str
) -> None:
    """Wherever in the leaf either node is.

    The keys are counted once every node has passed its type and its
    context. Issue btclib-org/bip32-descriptors#235.
    """
    context, wrap = _WRAPPED[wrapped]
    root = _holding("pk_k", context, ())
    other = _P2WSH if context == _TAPSCRIPT else _TAPSCRIPT
    if fault == "context":
        _with_context(_node_at(root, (0, 0, 0)), other)
        error: type[Exception] = BTClibValueError
        node = "tapscript" if context == _TAPSCRIPT else "P2WSH"
        err_msg = f"^not a {node} node: pk_k in {other}$"
    else:
        object.__setattr__(_node_at(root, (0, 0)), "subs", ("not a node",))
        error = BTClibTypeError
        err_msg = "^invalid miniscript node type: str$"
    with pytest.raises(error, match=err_msg):
        wrap(root)


def test_a_node_of_a_fragment_holding_no_key_is_refused_holding_one() -> None:
    """Named "a node" where the library does not define its fragment.

    Issue btclib-org/bip32-descriptors#235.
    """
    root = _unpickled(miniscript.parse(f"and_v(v:pk({_X}),older(1))", _TAPSCRIPT))
    object.__setattr__(root.subs[1], "keys", (_KEY2,))
    with pytest.raises(BTClibValueError, match="^invalid number of keys in older: 1$"):
        TrDescriptor(_KEY, root)
    object.__setattr__(root.subs[1], "fragment", ["older"])
    with pytest.raises(BTClibValueError, match="^invalid number of keys in a node: 1$"):
        TrDescriptor(_KEY, root)


@pytest.mark.parametrize("wrapped", _WRAPPED)
def test_a_node_s_keys_given_as_a_list_are_refused(wrapped: str) -> None:
    """As `Miniscript` refuses them. Issue btclib-org/bip32-descriptors#235."""
    context, wrap = _WRAPPED[wrapped]
    own = _X_KEYS if context == _TAPSCRIPT else _C_KEYS
    root = _holding("pk_k", context, (own[2],))
    object.__setattr__(_node_at(root, (1, 0)), "keys", [own[2]])
    with pytest.raises(BTClibTypeError, match="^invalid keys type: list$"):
        wrap(root)


@pytest.mark.parametrize("first", [False, True], ids=["second", "first"])
@pytest.mark.parametrize("wrapped", _WRAPPED)
def test_a_key_of_another_type_is_refused_before_the_number_of_keys(
    wrapped: str, first: bool
) -> None:
    """In a ``pk_k`` holding two keys, naming the type alone.

    Issue btclib-org/bip32-descriptors#246.
    """
    context, wrap = _WRAPPED[wrapped]
    own = _X_KEYS if context == _TAPSCRIPT else _C_KEYS
    keys: tuple[object, ...] = ("abc", own[2]) if first else (own[2], "abc")
    root = _holding("pk_k", context, cast("tuple[KeyExpression, ...]", keys))
    with pytest.raises(BTClibTypeError, match="^invalid key type: str$"):
        wrap(root)


@pytest.mark.parametrize("beside", [False, True], ids=["alone", "beside"])
@pytest.mark.parametrize(
    "keys,err_msg",
    [
        ([_KEY2], "^invalid keys type: list$"),
        (None, "^invalid keys type: NoneType$"),
        ((_KEY2, "abc"), "^invalid key type: str$"),
    ],
    ids=["list", "None", "str"],
)
def test_an_unpickled_multi_a_leaf_holding_keys_of_another_type_is_refused(
    keys: object, err_msg: str, beside: bool
) -> None:
    """Alone and beside a miniscript leaf, before anything reads a key.

    An unpickled `MultiA` skips its own check of its keys. Issue
    btclib-org/bip32-descriptors#249.
    """
    leaf = _unpickled_multi_a(cast("tuple[KeyExpression, ...]", keys))
    other = miniscript.parse(f"and_v(v:pk({_X}),older(1))", _TAPSCRIPT)
    with pytest.raises(BTClibTypeError, match=err_msg):
        TrDescriptor(_KEY, (leaf, other) if beside else leaf)
