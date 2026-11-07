# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `.github/scripts/compare_descriptors.py`.

The script is loaded by path, `.github/scripts` being no package, as the
other scripts under it are tested. Neither `bitcoind` nor `cargo` is needed:
`disagreements` reads verdicts, the Rust program is a stub, and `FakeCore`
answers for the node.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import runpy
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.descriptors import bitcoin_s_test

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "compare_descriptors.py"


@pytest.fixture
def script(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Return the script, imported by path.

    Its dataclasses resolve their string annotations through
    `sys.modules[cls.__module__]` before Python 3.15, so the module is named
    there before it runs, and removed after the test.
    """
    spec = importlib.util.spec_from_file_location("compare_descriptors", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "compare_descriptors", module)
    spec.loader.exec_module(module)
    return module


def test_bitcoin_s_cases_reads_the_real_file(script: ModuleType) -> None:
    """Every descriptor of both tables is read, a row naming a constant too."""
    texts = [case.text for case in script._bitcoin_s_cases()]

    tables = bitcoin_s_test.ACCEPTED + bitcoin_s_test.REFUSED
    assert texts == [row[0] for row in tables]


def test_disagreements_flags_a_refusal_by_rust_alone(script: ModuleType) -> None:
    """Core and `parse` accept what rust-miniscript refuses."""
    accepted = script.Verdict(True, scripts=("0014aa",))
    refused = script.Verdict(False)

    assert script.disagreements(accepted, accepted, refused) == ["acceptance"]


def test_disagreements_flags_an_acceptance_by_core_alone(script: ModuleType) -> None:
    """Core accepts what `parse` and rust-miniscript refuse."""
    accepted = script.Verdict(True)
    refused = script.Verdict(False)

    assert script.disagreements(accepted, refused, refused) == ["acceptance"]


def test_disagreements_flags_a_refusal_by_core_alone(script: ModuleType) -> None:
    """Core refuses what `parse` and rust-miniscript accept."""
    accepted = script.Verdict(True)
    refused = script.Verdict(False)

    assert script.disagreements(refused, accepted, accepted) == ["acceptance"]


def test_disagreements_flags_an_acceptance_by_rust_alone(script: ModuleType) -> None:
    """Only rust-miniscript accepts."""
    accepted = script.Verdict(True)
    refused = script.Verdict(False)

    assert script.disagreements(refused, refused, accepted) == ["acceptance"]


def test_disagreements_flags_an_acceptance_by_parse_alone(script: ModuleType) -> None:
    """Only `parse` accepts."""
    accepted = script.Verdict(True)
    refused = script.Verdict(False)

    assert script.disagreements(refused, accepted, refused) == ["acceptance"]


def test_disagreements_is_empty_where_all_refuse(script: ModuleType) -> None:
    """A descriptor that all three refuse is no disagreement."""
    refused = script.Verdict(False)

    assert script.disagreements(refused, refused, refused) == []


def test_disagreements_is_empty_where_all_accept_alike(script: ModuleType) -> None:
    """The same script and address from all three is no disagreement."""
    core = script.Verdict(True, addresses=("bc1qa",))
    ours = script.Verdict(True, scripts=("0014aa",), addresses=("bc1qa",))
    rust = script.Verdict(True, scripts=("0014aa",), addresses=("bc1qa",))

    assert script.disagreements(core, ours, rust) == []


def test_disagreements_flags_a_different_script(script: ModuleType) -> None:
    """All three accept, and `parse` and rust-miniscript derive two scripts."""
    core = script.Verdict(True)
    ours = script.Verdict(True, scripts=("0014aa",))
    rust = script.Verdict(True, scripts=("0014bb",))

    assert script.disagreements(core, ours, rust) == ["script parse/rust"]


def test_disagreements_flags_a_different_address(script: ModuleType) -> None:
    """All three accept, and each pair of addresses that differs is named."""
    core = script.Verdict(True, addresses=("bc1qa",))
    ours = script.Verdict(True, addresses=("bc1qb",))
    rust = script.Verdict(True, addresses=("bc1qc",))

    assert script.disagreements(core, ours, rust) == [
        "address parse/core",
        "address rust/core",
        "address parse/rust",
    ]


@pytest.fixture
def stub(script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Return a program that answers like the Rust one, and stops at `crash`.

    It reads one hex-encoded input per line and answers each with a row of
    the tab-separated form `index status script address note`, the index
    counted from its own first line. At `crash` it exits with 3 and no row.
    The script runs the program as a command, which Windows cannot do with a
    Python file, so the interpreter is put in front of it.
    """
    path = tmp_path / "stub.py"
    path.write_text(
        "import sys\n"
        "for index, line in enumerate(sys.stdin):\n"
        "    text = bytes.fromhex(line.strip()).decode()\n"
        "    if text == 'crash':\n"
        "        sys.exit(3)\n"
        "    print(f'{index}\\taccepted\\t{text.encode().hex()}\\t-\\t-', flush=True)\n",
        encoding="utf-8",
    )
    real_run = subprocess.run

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return real_run([sys.executable, *args], **kwargs)

    monkeypatch.setattr(script.subprocess, "run", run)
    return path


def test_first_path_keeps_the_first_of_a_multipath_answer(script: ModuleType) -> None:
    """A multipath answer is a list per path, of which the first is kept."""
    assert script._first_path([["a"], ["b"]]) == ("a",)
    assert script._first_path(["a"]) == ("a",)


def test_disagreements_compares_the_first_of_several_addresses(
    script: ModuleType,
) -> None:
    """Core and `parse` give every address of a combo(), rust-miniscript one."""
    core = script.Verdict(True, addresses=("bc1qa", "bc1qb"))
    ours = script.Verdict(True, scripts=("0014aa",), addresses=("bc1qa", "bc1qb"))
    rust = script.Verdict(True, scripts=("0014aa",), addresses=("bc1qa",))

    assert script.disagreements(core, ours, rust) == []


def test_read_with_rust_answers_every_input(script: ModuleType, stub: Path) -> None:
    """A run that answers every input needs no restart."""
    verdicts = script.read_with_rust(stub, ["a", "b"])

    assert [verdict.accepted for verdict in verdicts] == [True, True]
    assert [verdict.scripts for verdict in verdicts] == [
        ("61",),
        ("62",),
    ]


def test_read_with_rust_restarts_after_a_crash(script: ModuleType, stub: Path) -> None:
    """The input a run stopped on is a refusal, and the rest are asked again."""
    verdicts = script.read_with_rust(stub, ["a", "crash", "b", "c"])

    assert [verdict.accepted for verdict in verdicts] == [True, False, True, True]
    assert verdicts[1].note == "rust-miniscript stopped with 3"
    assert verdicts[2].scripts == (b"b".hex(),)
    assert verdicts[3].scripts == (b"c".hex(),)


def test_read_with_rust_survives_a_crash_on_the_first_input(
    script: ModuleType, stub: Path
) -> None:
    """A run that stops before any answer still moves past its input."""
    verdicts = script.read_with_rust(stub, ["crash", "a"])

    assert [verdict.accepted for verdict in verdicts] == [False, True]


_A = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
# the master key of BIP32's first test vector
_XPUB = (
    "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje"
    "8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
)


def _write(path: Path, data: str | bytes) -> None:
    """Write `data` at `path`, making the directories above it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)


@pytest.fixture
def root(script: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Return a repository of one input per source, made the script's `ROOT`.

    The bitcoin-s file holds a table under each spelling of an assignment
    the script reads, and statements beside them that it passes over. The
    fuzz corpus holds a file that is not UTF-8, and a directory.
    """
    path = tmp_path / "repository"
    _write(
        path / "tests" / "_data" / "miniscript_fixed_tests.json",
        json.dumps([{"miniscript": f"pk({_A})"}]),
    )
    _write(
        path / "tests" / "descriptors" / "bitcoin_s_test.py",
        "NOTE: str\n"
        "ACCEPTED: list[tuple[str, str]] = [('raw(51)', NOTE)]\n"
        "REFUSED = [('nonsense', NOTE)]\n"
        "FIRST = SECOND = 1\n"
        "OTHER = [('raw(52)', NOTE)]\n",
    )
    _write(
        path / "tests" / "_data" / "descriptor_checksums.json",
        json.dumps([{"desc": "raw(51)", "checksum": "8lvh9jxk"}]),
    )
    corpus = path / "fuzz" / "corpus" / "fuzz_descriptor"
    _write(corpus / "a", f"pkh({_A})")
    _write(corpus / "b", b"\xff")
    (corpus / "c").mkdir()
    monkeypatch.setattr(script, "ROOT", path)
    return path


def test_cases_reads_every_source_in_order(
    script: ModuleType,
    root: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Each source in the docstring's order, octets not UTF-8 left out."""
    qa_assets = tmp_path / "qa-assets"
    _write(qa_assets / "fuzz_corpora" / "descriptor_parse" / "q", "raw(53)")
    extra = tmp_path / "extra.txt"
    _write(extra, "raw(54)\nraw(55)\n")

    found = script.cases(qa_assets, [extra])

    xonly = _A[2:]
    assert [(case.source, case.name, case.text) for case in found] == [
        ("fixed", "0 wsh", f"wsh(pk({_A}))"),
        ("fixed", "0 tr", f"tr({script._INTERNAL_KEY},pk({xonly}))"),
        ("bitcoin-s", "ACCEPTED 0", "raw(51)"),
        ("bitcoin-s", "REFUSED 0", "nonsense"),
        ("checksums", "0", "raw(51)#8lvh9jxk"),
        ("fuzz-corpus", "a", f"pkh({_A})"),
        ("qa-assets", "q", "raw(53)"),
        ("extra", "extra.txt 0", "raw(54)"),
        ("extra", "extra.txt 1", "raw(55)"),
    ]
    assert capsys.readouterr().err == "fuzz-corpus: 1 inputs are not UTF-8, left out\n"


def test_cases_refuses_an_empty_corpus(
    script: ModuleType, root: Path, tmp_path: Path
) -> None:
    """A corpus directory with no file stops the run, naming it."""
    empty = tmp_path / "qa-assets" / "fuzz_corpora" / "descriptor_parse"
    empty.mkdir(parents=True)

    with pytest.raises(SystemExit, match="holds no file"):
        script.cases(tmp_path / "qa-assets", [])


def test_read_with_parse_tells_a_refusal_from_a_failed_derivation(
    script: ModuleType,
) -> None:
    """A refusal is not accepted; a derivation that fails is, with no script."""
    refused = script.read_with_parse("nonsense")
    underived = script.read_with_parse(f"pkh({_XPUB}/0h/*)")
    derived = script.read_with_parse(f"pkh({_A})")

    assert not refused.accepted
    assert refused.note.startswith("BTClibValueError: ")
    assert underived.accepted
    assert underived.scripts == ()
    assert underived.note.startswith("BTClibValueError: ")
    assert derived == script.Verdict(
        True,
        scripts=("76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",),
        addresses=("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",),
    )


class FakeCore:
    """What `Node` reads from `bitcoind`, answered without one.

    `Popen` of the path `BITCOIND` makes a process that writes the RPC
    cookie, and every HTTP connection is answered here, the batch in reverse
    order, as JSON-RPC allows. `getdescriptorinfo` refuses `nonsense`, and
    `deriveaddresses` refuses a `raw()`; an address names the descriptor and
    the range it was derived from, two paths where it is multipath.
    """

    BITCOIND = Path("bitcoind")
    COOKIE = "__cookie__:secret"

    def __init__(self) -> None:
        """Start with a node that answers at once and stops when asked."""
        self.down = 0
        self.busy = 0
        self.exits = False
        self.stop_fails = False
        self.killed = False
        self.args: list[str] = []
        self.calls: list[tuple[str, list[Any]]] = []

    def answer(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return the answer to one request of a batch."""
        method, params = request["method"], request["params"]
        self.calls.append((method, params))
        answer: dict[str, Any] = {"id": request["id"], "error": None}
        if method == "getblockchaininfo" and self.busy:
            self.busy -= 1
            answer["error"] = {"code": -28, "message": "Loading block index"}
        elif method == "getdescriptorinfo" and params[0] == "nonsense":
            answer["error"] = {"code": -5, "message": "not a descriptor"}
        elif method == "getdescriptorinfo":
            answer["result"] = {"checksum": "cccccccc", "isrange": "*" in params[0]}
        elif method == "deriveaddresses" and params[0].startswith("raw("):
            answer["error"] = {"code": -5, "message": "no addresses"}
        elif method == "deriveaddresses":
            address = f"{params[0]} {params[1:]}"
            two = "<" in params[0]
            answer["result"] = [[address], [address + " 1"]] if two else [address]
        else:
            answer["result"] = {}
        return answer


class _FakeProcess:
    """The `Popen` of `FakeCore.BITCOIND`."""

    def __init__(self, core: FakeCore, args: list[str]) -> None:
        core.args = args
        datadir = next(arg for arg in args if arg.startswith("-datadir="))
        Path(datadir.removeprefix("-datadir="), ".cookie").write_text(
            core.COOKIE, encoding="utf-8"
        )
        self._core = core
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if self._core.exits:
            self.returncode = 1
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self._core.killed = True


class _FakeConnection:
    """An `HTTPConnection` that `FakeCore` answers."""

    def __init__(self, core: FakeCore) -> None:
        self._core = core
        self._payload = b""

    def request(
        self, method: str, url: str, body: str, headers: dict[str, str]
    ) -> None:
        cookie = base64.b64encode(self._core.COOKIE.encode()).decode()
        assert (method, url, headers) == (
            "POST",
            "/",
            {"Authorization": f"Basic {cookie}"},
        )
        batch = json.loads(body)
        if self._core.down:
            self._core.down -= 1
            raise ConnectionRefusedError
        if self._core.stop_fails and batch[0]["method"] == "stop":
            raise ConnectionResetError
        answers = [self._core.answer(each) for each in reversed(batch)]
        self._payload = json.dumps(answers).encode()

    def getresponse(self) -> _FakeConnection:
        return self

    def read(self) -> bytes:
        return self._payload

    def close(self) -> None:
        pass


@pytest.fixture
def core(script: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeCore]:
    """Return the `bitcoind` that `Node` starts, and wait for none of it.

    Every directory a node makes is removed after the test, the one of a
    node that never started included.
    """
    fake = FakeCore()
    real_popen = subprocess.Popen

    def popen(args: list[str], **kwargs: Any) -> Any:
        if args[0] == str(FakeCore.BITCOIND):
            return _FakeProcess(fake, args)
        return real_popen(args, **kwargs)

    real_directory = tempfile.TemporaryDirectory
    made: list[tempfile.TemporaryDirectory[str]] = []

    def directory(**kwargs: Any) -> tempfile.TemporaryDirectory[str]:
        made.append(real_directory(**kwargs))
        return made[-1]

    monkeypatch.setattr(script.subprocess, "Popen", popen)
    monkeypatch.setattr(script.tempfile, "TemporaryDirectory", directory)
    monkeypatch.setattr(
        script.http.client,
        "HTTPConnection",
        lambda *_args, **_kwargs: _FakeConnection(fake),
    )
    monkeypatch.setattr(script.time, "sleep", lambda _seconds: None)
    yield fake
    for each in made:
        each.cleanup()


def test_node_waits_until_core_answers(script: ModuleType, core: FakeCore) -> None:
    """A refused connection and an error answer are waited out."""
    core.down = 1
    core.busy = 1

    node = script.Node(core.BITCOIND)
    datadir = Path(node._directory.name)
    node.stop()

    assert core.args[0] == str(core.BITCOIND)
    assert f"-datadir={datadir}" in core.args
    assert [method for method, _ in core.calls] == [
        "getblockchaininfo",
        "getblockchaininfo",
        "stop",
    ]
    assert not datadir.exists()
    assert not core.killed


def test_node_stops_where_bitcoind_exits(script: ModuleType, core: FakeCore) -> None:
    """A node that exits before answering ends the run with its code."""
    core.exits = True

    with pytest.raises(SystemExit, match="bitcoind exited with 1"):
        script.Node(core.BITCOIND)


def test_node_stops_where_core_never_answers(
    script: ModuleType, core: FakeCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the deadline the node is stopped and the run ends."""
    monkeypatch.setattr(script, "_NODE_STARTUP_SECONDS", 0.0)

    with pytest.raises(SystemExit, match="did not answer in time"):
        script.Node(core.BITCOIND)

    assert [method for method, _ in core.calls] == ["stop"]


def test_node_is_killed_where_stop_fails(script: ModuleType, core: FakeCore) -> None:
    """A stop that is not answered kills the process, and still cleans up."""
    node = script.Node(core.BITCOIND)
    core.stop_fails = True

    node.stop()

    assert core.killed
    assert not Path(node._directory.name).exists()


def test_read_with_core_derives_from_the_text_as_given(
    script: ModuleType, core: FakeCore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Core's checksum replaces the text's, and a range derives index 0."""
    monkeypatch.setattr(script, "_BATCH", 2)
    texts = [
        "nonsense",
        f"pkh({_A})#xxxxxxxx",
        f"pkh({_XPUB}/*)",
        f"pkh({_XPUB}/<0;1>/*)",
        "raw(51)",
    ]
    node = script.Node(core.BITCOIND)

    verdicts = script.read_with_core(node, texts)
    node.stop()

    single = f"pkh({_A})#cccccccc"
    ranged = f"pkh({_XPUB}/*)#cccccccc"
    multipath = f"pkh({_XPUB}/<0;1>/*)#cccccccc"
    assert verdicts == [
        script.Verdict(False, note="not a descriptor"),
        script.Verdict(True, addresses=(f"{single} []",)),
        script.Verdict(True, addresses=(f"{ranged} [[0, 0]]",)),
        script.Verdict(True, addresses=(f"{multipath} [[0, 0]]",)),
        script.Verdict(True, note="no addresses"),
    ]


def test_show_reports_each_parser_and_shortens_a_long_input(
    script: ModuleType,
) -> None:
    """Every parser has a line, and an input past 120 characters is cut."""
    case = script.Case("extra", "x 0", "r" * 121)
    core = script.Verdict(False, note="refused")
    ours = script.Verdict(True, scripts=("51",))

    shown = script._show(case, ["acceptance"], (core, ours, ours))

    assert shown.splitlines() == [
        "extra x 0: acceptance",
        f"    input  {'r' * 117 + '...'!r}",
        "    core   refuse  refused",
        "    parse  accept  ('51',)",
        "    rust   accept  ('51',)",
    ]


def test_main_prints_the_disagreements_and_writes_the_report(
    script: ModuleType,
    root: Path,
    core: FakeCore,
    stub: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Every input is in the report, and the tally ends the output."""
    report = tmp_path / "report.jsonl"
    argv = ["--bitcoind", str(core.BITCOIND), "--miniscript-compare", str(stub)]

    assert script.main([*argv, "--report", str(report)]) == 0

    rows = [
        json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()
    ]
    assert [row["text"] for row in rows] == [
        case.text for case in script.cases(None, [])
    ]
    assert rows[3]["name"] == "REFUSED 0"
    assert rows[3]["core"]["accepted"] is False
    assert rows[3]["parse"]["accepted"] is False
    assert rows[3]["rust"]["accepted"] is True
    assert rows[3]["disagreements"] == ["acceptance"]
    out = capsys.readouterr().out
    assert "bitcoin-s REFUSED 0: acceptance" in out
    assert out.endswith(
        f"{sum(bool(row['disagreements']) for row in rows)} of 6 inputs differ\n"
    )
    assert not core.killed


def test_main_tallies_an_agreement_and_writes_no_report_unless_asked(
    script: ModuleType,
    root: Path,
    core: FakeCore,
    stub: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An input all three accept, with nothing to compare, is an agreement.

    `parse` derives no script from a hardened step under an xpub, and the
    stub gives no address, so no pair of answers is compared.
    """
    extra = tmp_path / "extra.txt"
    _write(extra, f"pkh({_XPUB}/0h/*)\n")
    argv = ["--bitcoind", str(core.BITCOIND), "--miniscript-compare", str(stub)]

    assert script.main([*argv, "--extra", str(extra)]) == 0

    out = capsys.readouterr().out
    assert "extra extra.txt 0" not in out
    assert f"{'extra':12} {'agree':40} 1\n" in out
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "extra.txt",
        "repository",
        "stub.py",
    ]


def test_the_script_runs_main(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run as a program, the script hands its arguments to `main`."""
    monkeypatch.setattr(sys, "argv", [str(_SCRIPT), "--help"])

    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(_SCRIPT), run_name="__main__")

    assert excinfo.value.code == 0
    assert "--miniscript-compare" in capsys.readouterr().out
