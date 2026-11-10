# Assurance case

[SECURITY](./SECURITY.md) states what a user can and cannot expect of
bip32-descriptors in terms of security. This page argues why those
expectations hold: the threat model, the trust boundaries, how secure
design principles are applied, and how common implementation weaknesses
are countered. Each argument below names the file, the test or the
workflow that supports it; where SECURITY.md already states a fact, this
page points at it instead of repeating it.

## What is claimed

- **A key, a path and a descriptor agree with the specification that
  defines them.** BIP32 against its own vectors; descriptors against
  BIP380 to BIP390's, Bitcoin Core's `descriptor_tests.cpp` and
  bitcoin-s's; miniscript against Core's `miniscript_tests.cpp`.
  `tests/_data/README.md` says where each came from, pins it to the
  upstream commit it was taken from, and says whether the two still
  match. `.github/workflows/vendored-vectors.yml` runs weekly: it holds
  each vendored file to the `ours` or `blob` recorded there and `blob` to
  upstream's at the pinned commit, and reports a pin that is no longer
  upstream's tip. `.github/workflows/integration-bitcoind.yml` asks a
  Bitcoin Core node what it infers for each descriptor shape
  `tests/descriptors/infer_test.py` records. For each of `OWN_VECTORS` in
  `tests/descriptors/raw_descriptors_test.py`, it asks the node to refuse
  the vector and, where the vector names a descriptor Core reads in its
  place, to derive the vector's script from that one.
- **Malformed input is refused the way the package says it is.** A
  public function handed an argument it cannot use raises btclib's
  `BTClibTypeError` or `BTClibValueError`, or ecc's class of the same
  kind (`tests/input_validation_test.py`, `tests/integer_policy_test.py`,
  `tests/bool_parameter_test.py`, `tests/serialization_boundary_test.py`),
  and a parser handed hostile input raises one of those and nothing else
  (`tests/fuzz_test.py`, `tests/parse_contract_test.py`).
- **A published distribution is what this tree built.** SECURITY.md's
  *Supported versions* states how that is verified.

## Threat model

bip32-descriptors is a library in its caller's process. It opens no
socket, runs no subprocess and writes no file, and the one file it reads
is its own installed metadata, for `__version__`.

**What is defended.**

- A private key, an extended private key or a seed, against recovery
  from what a refusal prints.
- The correctness of every answer: a derived key, a script, an address, a
  witness.
- The caller's process, against a descriptor, a key or a path built to
  make a parser raise an exception this package does not document, or
  to spend unbounded time.

**The adversaries.**

- A party handing this package a descriptor, a key or a path built to
  exploit a parser, or to be accepted as another one.
- A party tampering with a distribution between this tree and the user.

**What is not defended**, each stated in SECURITY.md's *Where constant
time ends*:

- side channels where the Python arithmetic answers
- memory disclosure: secret material in a Python object is not zeroized
- the operating system and the interpreter

## Trust boundaries

**The caller and the public API.** Arguments cross from the caller into
bip32-descriptors at every public function, and each is validated there.
CONTRIBUTING.md's *The public surface* states the rule and names the
tests that drive it.

**Text and octets from outside.** A descriptor, an extended key or a
serialized key is typed, scanned or received, and every parser that takes
one -- those `tests/fuzz_test.py` lists -- is driven by Hypothesis there
and by `fuzz/fuzz_bip32.py` and `fuzz/fuzz_descriptor.py` under
ClusterFuzzLite (`.github/workflows/fuzz.yml`);
`tests/fuzz_corpus_test.py` checks that each harness calls what it
declares and that every seed of its corpus is still read.
`.github/workflows/qa-assets.yml` replays Bitcoin Core's descriptor fuzz
corpus weekly.

**The curve arithmetic.** Below this package, ecc and, where installed,
libsecp256k1 compute on the keys; SECURITY.md says where that boundary
is.

## Secure design principles

Saltzer and Schroeder's principles, over the package's layers described
in [ARCHITECTURE.md](./ARCHITECTURE.md).

- **Economy of mechanism.** One parser per expression kind, and a
  descriptor's keys, scripts and addresses derived from the one parsed
  tree.
- **Fail-safe defaults.** A descriptor's checksum is verified wherever
  one is given, and a flag that decides what is computed refuses a
  non-bool (`tests/bool_parameter_test.py`).
- **Complete mediation.** Every public function validates its inputs;
  a private twin trusts its inputs because its callers checked them.
- **Open design.** The code, the vendored vectors and the fuzzing corpus
  are published, and SECURITY.md states what is not defended.
- **Least privilege.** No network, no subprocess, no file written.
- **Psychological acceptability.** A refusal is one of btclib's or
  ecc's classes, each a `ValueError` or a `TypeError`, so a caller
  catching the built-in catches it too.

## Common implementation weaknesses

Weaknesses from MITRE's CWE list that a package of this kind is exposed
to, and what counters each.

- **Improper input validation (CWE-20).** The trust boundaries above, and
  `tests/integer_policy_test.py`, which refuses a `bool` where an
  integer field -- a depth, an index, a search bound -- is expected.
- **Uncaught exceptions on hostile input (CWE-248, CWE-755).**
  `tests/fuzz_test.py`'s contract, driven by Hypothesis and by
  ClusterFuzzLite.
- **Uncontrolled resource consumption (CWE-400).** A number read from
  text is bounded before `int()` reads it, and a `thresh()` whose
  arguments pass the size limit is refused before it is analysed
  (`tests/parser_limits_test.py`).
- **Exposure of sensitive information (CWE-209).** A refusal does not
  quote the private key or the extended private key it was handed. The
  rule is section 7's *A refusal carries no secret* in the
  [organization's standard](https://github.com/btclib-org/.github#a-refusal-carries-no-secret);
  its helper, `assert_secret_free` in `tests/secret_free/__init__.py`, is
  called by the tests of `tests/bip32/` and `tests/descriptors/` that feed
  a secret, and reads each exception the refusal chains.
- **Type confusion (CWE-843).** mypy runs with `strict = true` over the
  package and the suite, as a hook of the lint gate.
- **Code that is wrong and still passes.** Line and branch coverage is
  held at 100% by `fail_under` in `pyproject.toml`, and mutation testing,
  profiled under `.github/mutation/` and run by
  `.github/workflows/mutation.yml`, asks whether the suite notices a
  wrong line.
- **Supply chain.** SECURITY.md's *Supported versions* describes the
  attestations and the bill of materials. `uv.lock` pins the runtime
  dependencies a development install resolves, the tools and the test
  oracles, and every third-party action is pinned to a commit sha.
