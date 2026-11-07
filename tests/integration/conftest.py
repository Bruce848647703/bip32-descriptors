# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the integration tests need, and what makes them skip.

Two switches for the node's tests, and both have to be on.
`BTCLIB_INTEGRATION` in the environment is the opt-in: these tests
start programs, listen on a socket and write to disk, which is not what
`uv run pytest` should do to somebody who asked for the unit suite.
The second is the program itself -- `bitcoind` here -- because an
opt-in that fails for a missing binary would report a defect that is not
one.

So the ordinary run reports them skipped and says which switch was off,
and the whole flow is one command:

    BTCLIB_INTEGRATION=1 uv run pytest tests/integration

The node is this session's own: a regtest data directory under pytest's
tmp_path, an ephemeral rpc port, and a cookie file for the
credentials. It never touches a node the maintainer is running, which is
the reason none of the defaults -- port 18443, ~/.bitcoin -- is used.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import TypeVar

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

# how long the node is given to answer its first rpc call: a regtest
# bitcoind is up in well under a second on any machine that can run this
# suite, and the wait is a poll rather than a sleep, so this bounds only
# the failure case
_STARTUP_TIMEOUT = 30.0

_T = TypeVar("_T")


def _free_port() -> int:
    """Return a port nothing is listening on, by letting the OS pick one.

    Bound and closed rather than guessed: a fixed port is what makes two
    runs of a test suite fight each other, and the maintainer's own
    regtest node is exactly the kind of thing already on 18443.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture(scope="session")
def bitcoind_path() -> str:
    """Return the bitcoind to run, skipping the whole module without one."""
    if not os.environ.get("BTCLIB_INTEGRATION"):
        pytest.skip("set BTCLIB_INTEGRATION=1 to run the integration tests")
    path = os.environ.get("BTCLIB_BITCOIND") or shutil.which("bitcoind")
    if path is None:
        pytest.skip("no bitcoind: name one in BTCLIB_BITCOIND or put it on PATH")
    return path


def _bitcoind_args(bitcoind: Sequence[str], datadir: Path, port: int) -> list[str]:
    """Return the command line of a throwaway regtest node, `node`'s own.

    `bitcoind` is the command that runs the program: the program's path,
    for the real one.
    """
    return [
        *bitcoind,
        "-regtest",
        f"-datadir={datadir}",
        f"-rpcport={port}",
        "-rpcbind=127.0.0.1",
        # without it bitcoind ignores `-rpcbind` and binds `::1` as well as
        # `127.0.0.1` (src/httpserver.cpp, bitcoin/bitcoin@f0de87f040), and
        # keeps running when only `127.0.0.1` is taken, which the
        # start-again on a taken port cannot see
        "-rpcallowip=127.0.0.1",
        "-listen=0",
        "-natpmp=0",
        "-discover=0",
        "-listenonion=0",
        "-fallbackfee=0.0002",
        "-printtoconsole=0",
    ]


@pytest.fixture(scope="session")
def node(
    bitcoind_path: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[BitcoinCoreRpcClient]:
    """Yield an rpc client of a regtest node started for this session.

    `-fallbackfee` because a regtest chain has no fee history to estimate
    from, and Core refuses to fund a transaction without one, which
    `infer_test.py` asks of it through `fundrawtransaction`.

    `-listen=0` because nothing here dials the node over p2p. `-natpmp`,
    `-discover` and `-listenonion` are switched off by name as well: each
    reaches past this machine -- a port mapping asked of the gateway, a
    public address looked up, a Tor control port dialled -- which is not
    what a throwaway regtest node wants of a developer's own network.
    """
    datadir = tmp_path_factory.mktemp("regtest")
    process, client, _ = start_on_free_ports(
        lambda: _start_node([bitcoind_path], datadir)
    )
    try:
        yield client
    finally:
        _stop(process)


def _wait_for(
    client: BitcoinCoreRpcClient, process: subprocess.Popen[bytes], debug_log: Path
) -> None:
    """Poll until the node answers, or fail with what it did instead.

    A node that exited because its rpc port is taken raises `PortTaken`.
    """
    deadline = time.monotonic() + _STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log = (
                debug_log.read_text(encoding="utf-8", errors="replace")
                if debug_log.exists()
                else ""
            )
            if any(marker in log for marker in _NODE_PORT_TAKEN):
                raise PortTaken(log)
            pytest.fail(f"bitcoind exited with {process.returncode}")
        try:
            client.call("getblockchaininfo")
        # every failure before the node is up is the same failure: the
        # cookie file is not written yet, or the socket is not listening
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
        else:
            return
    pytest.fail(f"bitcoind did not answer within {_STARTUP_TIMEOUT} s")


# how many times the node is started, each on a fresh port, while the port
# it was given is taken
_BIND_ATTEMPTS = 5


# what bitcoind writes to its `debug.log` when it cannot bind a port: its
# rpc port (src/httpserver.cpp, bitcoin/bitcoin@f0de87f040) or its p2p
# port ("Unable to bind to <address> on this computer"); `-printtoconsole=0`
# leaves its stdout empty
_NODE_PORT_TAKEN = (
    "Unable to bind any endpoint for RPC server",
    "Unable to bind to ",
)


class PortTaken(Exception):  # noqa: N818
    """The node exited because the port it was given is taken."""


def start_on_free_ports(start: Callable[[], _T], attempts: int = _BIND_ATTEMPTS) -> _T:
    """Return what `start` returns, calling it again while a port is taken.

    `_free_port` closes the port it picked, so another process can bind
    it before the node does, and the node then exits. `start` picks its
    port itself, so each call is a fresh try; the last attempt's
    `PortTaken` is not caught.
    """
    for _ in range(attempts - 1):
        try:
            return start()
        except PortTaken:
            continue
    return start()


def _start(command: list[str], log: Path) -> subprocess.Popen[bytes]:
    with log.open("wb") as sink:
        return subprocess.Popen(  # noqa: S603
            command, stdout=sink, stderr=subprocess.STDOUT
        )


def _stop(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _start_node(
    bitcoind: Sequence[str], datadir: Path
) -> tuple[subprocess.Popen[bytes], BitcoinCoreRpcClient, int]:
    """Return a node, a client of it and its rpc port, once it answers.

    The node is stopped again where it does not get there, `PortTaken`
    included, so that the next try does not leave it behind.
    """
    port = _free_port()
    # a try that failed left its log behind, and its complaint must not be
    # read as this one's
    (datadir / "regtest" / "debug.log").unlink(missing_ok=True)
    process = _start(_bitcoind_args(bitcoind, datadir, port), datadir / "stdout.log")
    client = BitcoinCoreRpcClient(
        f"http://127.0.0.1:{port}", cookie_path=datadir / "regtest" / ".cookie"
    )
    try:
        _wait_for(client, process, datadir / "regtest" / "debug.log")
    except BaseException:
        _stop(process)
        raise
    return process, client, port
