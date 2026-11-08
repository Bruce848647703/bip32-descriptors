# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `parse` never builds is refused when a descriptor is built by hand.

A field of the wrong type, in every `Descriptor` fragment and in a
`MultiA`, leaves as a `BTClibTypeError`. `TrDescriptor`,
`MiniscriptDescriptor`, `UnusedDescriptor` and `MultiA` also refuse a
value `parse` refuses, as a `BTClibValueError`, and every fragment
holding a key that `parse` reads outside ``tr()`` and ``rawtr()``, and a
P2WSH `Miniscript` node, refuses a ``musig()`` one and an x-only one.
Issues btclib-org/bip32-descriptors#46, btclib-org/bip32-descriptors#85,
btclib-org/bip32-descriptors#103, btclib-org/bip32-descriptors#119,
btclib-org/bip32-descriptors#134, btclib-org/bip32-descriptors#150,
btclib-org/bip32-descriptors#159 and btclib-org/bip32-descriptors#161.

`KeyExpression` refuses a `pub_key` that `parse` refuses, an x-only key
with no `pub_key`, a `pub_key` beside another key or a derivation, and a
hardening symbol BIP380 does not allow. Issues
btclib-org/bip32-descriptors#171 and btclib-org/bip32-descriptors#178.
"""

from __future__ import annotations

import pickle
import re
from collections.abc import Callable
from dataclasses import fields, replace
from typing import Any

import pytest
from btclib import b58
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.key import PrvKeyData
from ecc.exceptions import EccValueError
from typing_extensions import override

from bip32_descriptors.bip32 import derive, rootxprv_from_seed, xpub_from_xprv
from bip32_descriptors.descriptors import at_index, miniscript, normalized, parse
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


class _Network(str):
    """A network name whose methods record whether `parse` was building."""

    __slots__ = ()
    # each call, with whether `parse` was building a descriptor then
    calls: list[tuple[str, bool]] = []  # noqa: RUF012

    def _record(self, name: str) -> None:
        _Network.calls.append((name, descriptors_module._SANE_BY_PARSE.get()))

    @override
    def strip(self, chars: str | None = None) -> str:
        self._record("strip")
        return _Network(str.strip(self, chars))

    @override
    def lower(self) -> str:
        self._record("lower")
        return _Network(str.lower(self))

    @override
    def __eq__(self, other: object) -> bool:
        self._record("__eq__")
        return str.__eq__(self, other)

    @override
    def __hash__(self) -> int:
        self._record("__hash__")
        return str.__hash__(self)


@pytest.mark.parametrize(
    "text",
    [f"wsh(and_v(v:pk({_C}),pk({PrvKeyData(4).pub.sec.hex()})))", f"tr({_X},pk({_X}))"],
    ids=["wsh", "tr"],
)
def test_parse_builds_with_no_method_of_a_caller_s_network(text: str) -> None:
    """`parse` hands the constructors the network table's own string."""
    _Network.calls.clear()
    network = _Network(" MAINNET ")
    descriptor = parse(text, network)
    # the control: its methods run, as `parse` validates the name
    assert ("lower", False) in _Network.calls
    assert all(not building for _, building in _Network.calls)
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
    assert set(_PARSED) == set(_fragments(Descriptor))
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


@pytest.mark.parametrize(
    "key",
    [KeyExpression(), _RANGED_KEY, _MUSIG],
    ids=["no key", "xkey", "musig"],
)
def test_an_x_only_key_with_no_pub_key_is_refused(key: KeyExpression) -> None:
    """`parse` reads an extended key and a ``musig()`` as not x-only."""
    assert not key.x_only
    with pytest.raises(BTClibValueError, match="^invalid x-only key: no pub_key$"):
        replace(key, x_only=True)


def test_an_uncompressed_x_only_key_is_refused_as_parse_refuses_it() -> None:
    """The key of an uncompressed WIF in a ``tr()``, which `parse` refuses."""
    err_msg = "uncompressed public keys are not allowed here"
    with pytest.raises(BTClibValueError, match=f"^key 0: {err_msg}$"):
        parse(f"tr({_UNCOMPRESSED_WIF})")
    with pytest.raises(BTClibValueError, match=f"^{err_msg}$"):
        KeyExpression(pub_key=_UNCOMPRESSED, x_only=True)


def test_an_odd_x_only_key_is_built_as_parse_builds_it() -> None:
    """The control: a WIF in a ``tr()`` keeps the 0x03 byte of its key."""
    (key,) = parse(f"tr({_ODD_WIF})").key_expressions
    assert key.pub_key is not None
    assert key.pub_key[0] == 3
    assert KeyExpression(pub_key=key.pub_key, x_only=True) == key


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
    for key in (_C_KEY, _RANGED_KEY, _MUSIG):
        rebuilt = replace(key, hardening=hardening)
        assert rebuilt.hardening == hardening
