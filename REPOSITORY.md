# Repository configuration

Read this before changing a workflow, a branch rule or a repository
setting; writing code does not need it. `AGENTS.md` points here rather than
carrying it, so that a session fixing a bug in the package does not hold it
in context.

The branch rules and the repository settings live *outside* the
repository. What is recorded is the settings the organization standard
asks about — the ones section 16's checklist sets on a new repository,
the ones a section of the standard states a rule for, and the ones a
behaviour it describes rests on — together with whatever a call quoted
for one of those answers alongside it. That is this file's scope, and
*What this file passes over* at the foot says what falls outside it.

The topics and `.homepage` have a second form in the tree —
`pyproject.toml`'s `keywords` and its `[project.urls]` field of that
name — so each is read back here for comparison rather than as the only
place the answer lives, which is what *Topics* and *Publishing* say of
them.

Each section carries the command that sets its setting and the command
that reads it back. **Only the read-back under *Branch protection* has
its answer recorded**: the file was written before the repository was
created, so every other block carries its command and no answer, and an
id the commands need — a ruleset's, a run's — stands as a placeholder.
Section 16's step after creation runs each read-back and writes what it
printed under it, as `#` lines with the date; the answers about a
release are read again once the first one is out. Section 11 makes such
an answer documentation, with a reader as its check: nothing re-runs
these commands, so an answer that differs later is a change made since
the date beside it.

## Creating the repository

The name and the calls that follow stand in blocks of their own. The
repository is public, and that is a prerequisite rather than a
preference: branch protection is a paid feature for a private repository
on the free plan, and section 10's `scorecard` reads a public one only.

```shell
d="BIP32 keys, output script descriptors and miniscript, built on btclib"
gh repo create btclib-org/bip32-descriptors --public --description "$d" \
  --disable-wiki
```

`main` is pushed next, being the branch every rule below names, and is
then made the default explicitly: an empty repository's first pushed
branch becomes its default whatever it is named, and this tree was built
on a branch of its own. The read-back below is what says it is:

```shell
git push git@github.com:btclib-org/bip32-descriptors.git main
gh api -X PATCH repos/btclib-org/bip32-descriptors -f default_branch=main
```

Then the switches section 11 turns off or on at the repository level, in
one call — the projects board and the wiki off, the tracker on, squash as
the only merge method with auto-merge, the head branch deleted on merge,
and the squash commit's title and body — together with the `.homepage`,
section 3's page on btclib.org:

```shell
gh api -X PATCH repos/btclib-org/bip32-descriptors \
  -F has_issues=true -F has_wiki=false -F has_projects=false \
  -F allow_squash_merge=true -F allow_merge_commit=false \
  -F allow_rebase_merge=false -F allow_auto_merge=true \
  -F delete_branch_on_merge=true \
  -f squash_merge_commit_title=COMMIT_OR_PR_TITLE \
  -f squash_merge_commit_message=COMMIT_MESSAGES \
  -f homepage=https://btclib.org/bip32-descriptors/
```

Read back:

```shell
gh api repos/btclib-org/bip32-descriptors \
  --jq '{visibility, default_branch: .default_branch, has_issues,
         wiki: .has_wiki, projects: .has_projects}'
gh api -i repos/btclib-org/bip32-descriptors/pages 2>/dev/null | head -1
```

`default_branch` is expected to answer `main`; the `PATCH` above is
what keeps it so once a branch is pushed.

`has_issues` is what `CONTRIBUTING.md`'s *The issue tracker* rests on,
and so does `.github/ISSUE_TEMPLATE/`. The Pages call answers `404`: this
tree serves no GitHub Pages site, and a recorded `404` is what makes a
later flip visible. It asks for the status line alone, the error body
being the endpoint's generic `Not Found` document.

## Naming

**Section 3 asks that the repository be named after the distribution,
hyphenated, and it is.** `pyproject.toml` declares
`name = "bip32-descriptors"`, the repository is
`btclib-org/bip32-descriptors`, and the import package is
`bip32_descriptors`.

## Required checks on main

**Never name matrix contexts in the branch rule.** The rule lives outside
the repository, so a context that stops being produced blocks every merge
with nothing in the tree to explain why. `test: every job passed` is an
aggregate job at the end of `test.yml` that `needs` every other job there;
a new job in `test.yml` belongs in that job's `needs`, or it gates
nothing.

`main` requires these checks and nothing else:

| Check | Produced by |
| --- | --- |
| `test: every job passed` | `test.yml`, aggregate over its jobs |
| `docs / Build the documentation` | `docs.yml`, calling `reusable-docs.yml` |
| `lint / Lint and type-check` | `lint.yml`, calling `reusable-lint.yml` |
| `lint / Dependency review` | `lint.yml`, calling `reusable-lint.yml` |
| `lint / Sign-off` | `lint.yml`, calling `reusable-lint.yml` |
| `regtest / Regtest against Bitcoin Core` | `integration-bitcoind.yml` |
| `sourcery / Sourcery` | `sourcery.yml`, calling `reusable-sourcery.yml` |

A merge waits for all of these checks, except an administrator's:
`enforce_admins` is off (*Branch protection*).

A job whose whole body is a call to a reusable workflow contributes no
name of its own: the context joins the calling job's id to the called
job's own name, so `docs.yml`'s `docs` job calling a job named `Build the
documentation` produces `docs / Build the documentation`. A context is
matched by name, not by the workflow that reported it, so moving a job is
free and renaming one is not.

[Section 10 of the organization's
standard](https://github.com/btclib-org/.github#the-set-and-its-cadence)
says when a tree's rule names `sourcery / Sourcery`.

No sentinel appears in the rule, and none of them may: a workflow
`CONTRIBUTING.md`'s *What gates a merge, and what only reports* lists as
running weekly can go red for reasons no pull request introduced,
and a red check nobody can act on from a branch is noise.
`codeql: every job passed` is not required either: the analysis is more
cells a merge would wait for, against the ceiling *Plan-gated settings*
has, and `zizmor` in `lint.yml` already audits the workflows on every
pull request.

Every required check is an Actions check, bound to the app that produces
it — `checks` with an `app_id` rather than the bare `contexts` list, 15368
for Actions — so nothing else can satisfy one.

## Branch protection

Classic protection carries the required checks with `strict` off
(section 11 of the organization's standard gives the ground), one
approving review, `dismiss_stale_reviews`, linear history, no force
pushes, no deletions, `required_conversation_resolution`, and
`enforce_admins` **off**. The whole object is `PUT` once, here, on a
branch that has none; every later change `PATCH`es the sub-endpoint it is
about, a partial `PUT` dropping the rest:

```shell
gh api -X PUT repos/btclib-org/bip32-descriptors/branches/main/protection \
  --input - <<'JSON'
{"required_status_checks": {"strict": false, "checks": [
   {"context": "test: every job passed", "app_id": 15368},
   {"context": "docs / Build the documentation", "app_id": 15368},
   {"context": "lint / Lint and type-check", "app_id": 15368},
   {"context": "lint / Dependency review", "app_id": 15368},
   {"context": "lint / Sign-off", "app_id": 15368},
   {"context": "regtest / Regtest against Bitcoin Core", "app_id": 15368},
   {"context": "sourcery / Sourcery", "app_id": 15368}]},
 "enforce_admins": false,
 "required_pull_request_reviews": {"dismiss_stale_reviews": true,
   "require_code_owner_reviews": false,
   "required_approving_review_count": 1},
 "restrictions": null,
 "required_linear_history": true,
 "allow_force_pushes": false,
 "allow_deletions": false,
 "required_conversation_resolution": true}
JSON
```

The body arrives on stdin because `-f` sends every value as a string,
where the endpoint types `app_id` as an integer.

Read back:

```shell
gh api repos/btclib-org/bip32-descriptors/branches/main/protection \
  --jq '{checks: [.required_status_checks.checks[] | [.context, .app_id]],
         strict: .required_status_checks.strict,
         reviews: .required_pull_request_reviews
                  | {required_approving_review_count, dismiss_stale_reviews},
         enforce_admins: .enforce_admins.enabled,
         linear: .required_linear_history.enabled,
         force_pushes: .allow_force_pushes.enabled,
         deletions: .allow_deletions.enabled,
         conversation: .required_conversation_resolution.enabled}'
# {"checks":[["test: every job passed",15368],
#   ["docs / Build the documentation",15368],
#   ["lint / Lint and type-check",15368],
#   ["lint / Dependency review",15368],
#   ["lint / Sign-off",15368],
#   ["regtest / Regtest against Bitcoin Core",15368],
#   ["sourcery / Sourcery",15368]],
#  "conversation":true,"deletions":false,"enforce_admins":false,
#  "force_pushes":false,"linear":true,
#  "reviews":{"dismiss_stale_reviews":true,
#   "required_approving_review_count":1},
#  "strict":false}
```

Read on 2026-11-05T07:18Z, after a `PATCH` of `required_status_checks`
carrying the `checks` of the `PUT` above, it printed the answer above.

Three rulesets sit beside it, additive — rules aggregate across rulesets
and classic protection, taking the most restrictive combination.
`main-integrity` has no bypass actor, for anyone:

```shell
gh api -X POST repos/btclib-org/bip32-descriptors/rulesets --input - <<'JSON'
{"name": "main-integrity", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
 "bypass_actors": [],
 "rules": [{"type": "required_linear_history"},
           {"type": "non_fast_forward"},
           {"type": "deletion"}]}
JSON
```

`main-self-merge` requires a pull request, so a direct push to `main` is
refused, and a merge needs an approval from somebody other than its
author. It has no bypass actor either: the standard asks that of a tree
whose `README.md` carries the OpenSSF Best Practices badge, and this one
is to once the project is registered (section 11 of
[btclib-org/.github's `README.md`](https://github.com/btclib-org/.github#branch-protection-and-rulesets)).
btclib-org/.github's
[`GOVERNANCE.md`](https://github.com/btclib-org/.github/blob/main/GOVERNANCE.md#how-a-decision-is-made),
*How a decision is made*, says when a bypass is added back; the
commands to add and remove it follow the read-back below.

```shell
gh api -X POST repos/btclib-org/bip32-descriptors/rulesets --input - <<'JSON'
{"name": "main-self-merge", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
 "bypass_actors": [],
 "rules": [{"type": "pull_request", "parameters": {
   "allowed_merge_methods": ["squash"],
   "dismiss_stale_reviews_on_push": true,
   "require_code_owner_review": false,
   "require_last_push_approval": false,
   "required_approving_review_count": 1,
   "required_review_thread_resolution": true}}]}
JSON
```

The `POST` answers with the ruleset's id, which is `<ruleset-id>` below.
It has no bypass actor:

```shell
gh api repos/btclib-org/bip32-descriptors/rulesets/<ruleset-id> --jq .bypass_actors
```

The bypass is added back and removed with a `PUT`. A `PUT` replaces the
whole ruleset, so each body carries every parameter the ruleset holds,
which the read above (without `--jq`) shows. The `POST` above omits some
of them. When added back, the bypass is actor `3296421`, `fametrano`'s
account id (`gh api users/fametrano --jq .id`), in `pull_request` mode.
To add it:

```shell
gh api -X PUT repos/btclib-org/bip32-descriptors/rulesets/<ruleset-id> \
  --input - <<'JSON'
{"name": "main-self-merge", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
 "bypass_actors": [{"actor_id": 3296421, "actor_type": "User",
                    "bypass_mode": "pull_request"}],
 "rules": [{"type": "pull_request", "parameters": {
   "allowed_merge_methods": ["squash"],
   "dismiss_stale_reviews_on_push": true,
   "dismissal_restriction": {"allowed_actors": [], "enabled": false},
   "require_code_owner_review": false,
   "require_extra_approval_for_unattributed_changes": true,
   "require_last_push_approval": false,
   "required_approving_review_count": 1,
   "required_review_thread_resolution": true,
   "required_reviewers": []}}]}
JSON
```

The same `PUT` with `"bypass_actors": []` removes it:

```shell
gh api -X PUT repos/btclib-org/bip32-descriptors/rulesets/<ruleset-id> \
  --input - <<'JSON'
{"name": "main-self-merge", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
 "bypass_actors": [],
 "rules": [{"type": "pull_request", "parameters": {
   "allowed_merge_methods": ["squash"],
   "dismiss_stale_reviews_on_push": true,
   "dismissal_restriction": {"allowed_actors": [], "enabled": false},
   "require_code_owner_review": false,
   "require_extra_approval_for_unattributed_changes": true,
   "require_last_push_approval": false,
   "required_approving_review_count": 1,
   "required_review_thread_resolution": true,
   "required_reviewers": []}}]}
JSON
```

Classic protection's own copy of the signature rule is off:

```shell
gh api repos/btclib-org/bip32-descriptors/branches/main/protection \
  --jq '.required_signatures.enabled'
```

No ruleset over `main` carries `required_signatures`, so nothing refuses an
unsigned commit at the push: `verified-signatures.yml` checks after each push
that every commit pushed is `verified` on the forge, and a red run is read in
the Actions tab. It is not a required check. [The standard states these values
for every
repository](https://github.com/btclib-org/.github#branch-protection-and-rulesets).

## Tag protection

`tag-integrity`, `target: tag`, `refs/tags/v*`: required signatures, and
nothing else, so the recovery path RELEASING.md gives — delete and
re-tag a release that failed before `publish-pypi` — still works:

```shell
gh api -X POST repos/btclib-org/bip32-descriptors/rulesets --input - <<'JSON'
{"name": "tag-integrity", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
 "bypass_actors": [],
 "rules": [{"type": "required_signatures"}]}
JSON
```

`GET /rulesets` answers a summary per ruleset, with neither `rules` nor
`bypass_actors` among its keys, so those two come from the single-ruleset
endpoint:

```shell
for id in $(gh api repos/btclib-org/bip32-descriptors/rulesets --jq '.[].id'); do
  gh api repos/btclib-org/bip32-descriptors/rulesets/"$id" \
    --jq '{name, target, enforcement, include: .conditions.ref_name.include,
           rules: [.rules[].type],
           bypass: [.bypass_actors[] | [.actor_id, .bypass_mode]],
           methods: [.rules[] | select(.type=="pull_request")
                              | .parameters.allowed_merge_methods]}'
done
```

The loop is expected to print the three rulesets above, each matching
the standard.

A `v*` tag push that brings an unsigned commit is refused. A tag on a
commit already on `main` is accepted whether it is signed, unsigned or
lightweight, so the rule does not make a release tag signed
(btclib-org/.github#1635). That rests on `git tag -s` in the release
steps and on reading the signature back:

```shell
gh api repos/<owner>/<repo>/git/tags/<sha> --jq .verification
```

## Merge methods

**Squash is the only method GitHub can be asked for**, and auto-merge
presses it once the review and the checks are in; the call is the one
under *Creating the repository*. Read back:

```shell
gh api repos/btclib-org/bip32-descriptors \
  --jq '{allow_squash_merge, allow_merge_commit, allow_rebase_merge,
         allow_auto_merge, squash_merge_commit_title,
         squash_merge_commit_message, delete_branch_on_merge}'
```

`COMMIT_OR_PR_TITLE` is the subject: the pull request title with its
number, or the subject of the single commit where a branch has one.
`COMMIT_MESSAGES` is the body, and it is where a `Co-Authored-By`
trailer written in the branch's commits survives the squash.
`delete_branch_on_merge` keeps the branch list a list of live work; a
pull request closed without merging keeps its head branch.

## Token permissions

**The default `GITHUB_TOKEN` is read-only repository-wide**, so a job
needing more must declare it, and the declarations are the record of
which jobs do:

```shell
git grep -nE '^ +[a-z-]+: write([[:blank:]]+#|$)' -- .github/workflows
```

Each grant that command finds carries its reason on its own line. The
workflow-level `permissions: contents: read` every workflow declares is
belt and braces, and it is what makes the intent readable in the file.

A caller's `permissions:` block bounds the workflow it calls and refuses
rather than trims: a scope a called job declares that the caller leaves
off fails the run before any job starts (btclib-org/.github#912). That is
why `release.yml`'s `test` job names `pull-requests: read`, which
`test.yml`'s `changes` job declares.

Whether this repository pins its own default or inherits the
organization's is unreadable afterwards — no endpoint reports an
override — so it is left to inherit, and this is the call that reads the
value it gets:

```shell
gh api repos/btclib-org/bip32-descriptors/actions/permissions/workflow \
  --jq '{default_workflow_permissions, can_approve_pull_request_reviews}'
```

The expected answer is `read` and `false`. Where it is not, the
organization default has moved, and section 11's command is the one that
moves it back for the organization rather than here.

## Allowed actions and SHA pinning

Read for this repository and for the organization:

```shell
gh api repos/btclib-org/bip32-descriptors/actions/permissions \
  --jq '{allowed_actions, sha_pinning_required}'
gh api orgs/btclib-org/actions/permissions \
  --jq '{allowed_actions, sha_pinning_required}'
```

`sha_pinning_required` is set at the organization level: [section 11 of
the standard has the reasons for both
fields](https://github.com/btclib-org/.github#tokens-publishing-scanning).

## Sign-off on web commits

```shell
gh api repos/btclib-org/bip32-descriptors --jq .web_commit_signoff_required
gh api orgs/btclib-org --jq .web_commit_signoff_required
```

Set at the organization level, [for the reason section 11
gives](https://github.com/btclib-org/.github/blob/main/README.md#signatures).

## Publishing

**Publishing waits for an approval**: the `pypi` and `testpypi`
environments both require a review from one of `fametrano`,
`giacomocaironi` and `pmazzocchi`, and `pypi` is restricted to `v*`
tags. `RELEASING.md` records the reasoning and the trusted publishers
each index is given.

```shell
gh api -X PUT repos/btclib-org/bip32-descriptors/environments/pypi \
  --input - <<'JSON'
{"reviewers": [{"type": "User", "id": 3296421},
               {"type": "User", "id": 30932677},
               {"type": "User", "id": 7437256}],
 "prevent_self_review": false,
 "deployment_branch_policy": {"protected_branches": false,
                              "custom_branch_policies": true}}
JSON
env=repos/btclib-org/bip32-descriptors/environments/pypi
gh api -X POST "$env/deployment-branch-policies" -f name='v*' -f type=tag
gh api -X PUT repos/btclib-org/bip32-descriptors/environments/testpypi \
  --input - <<'JSON'
{"reviewers": [{"type": "User", "id": 3296421},
               {"type": "User", "id": 30932677},
               {"type": "User", "id": 7437256}],
 "prevent_self_review": false}
JSON
```

`30932677` is `giacomocaironi`'s account id and `7437256` is
`pmazzocchi`'s, read back the same way as `fametrano`'s above:
`gh api users/giacomocaironi --jq .id`,
`gh api users/pmazzocchi --jq .id`.

Read back:

```shell
gh api repos/btclib-org/bip32-descriptors/environments \
  --jq '.environments[] | {name, dbp: .deployment_branch_policy,
         rules: [.protection_rules[] | .type],
         reviewers: [.protection_rules[].reviewers[]?.reviewer.login]}'
env=repos/btclib-org/bip32-descriptors/environments/pypi
gh api "$env/deployment-branch-policies" \
  --jq '.branch_policies[] | [.name, .type]'
```

The two trusted publishers `RELEASING.md`'s *One-time setup* names, on
PyPI and on TestPyPI, are to be added as pending publishers under the
project name `bip32-descriptors`, environment `pypi` and `testpypi`
respectively and workflow `release.yml` for both, adding them being an
account action and the maintainer's. No call here reads a publisher
back. What a call reads is whether each index holds the project, and
what was uploaded to it:

```shell
for u in https://pypi.org/pypi/bip32-descriptors/json \
         https://test.pypi.org/pypi/bip32-descriptors/json; do
  curl -s -o /dev/null -w '%{http_code}\n' "$u"
  curl -s "$u" | jq -c '{version: .info.version,
    releases: (.releases | keys),
    files: [.urls[] | .filename]}'
done
```

Then the project pages, and the jobs of the release run, `<run-id>`:

```shell
for u in https://pypi.org/project/bip32-descriptors/ \
         https://test.pypi.org/project/bip32-descriptors/; do
  curl -s -o /dev/null -w '%{http_code}\n' "$u"
done
gh run view <run-id> --repo btclib-org/bip32-descriptors --json jobs \
  --jq '.jobs[] | select(.name == "Publish to PyPI"
        or .name == "Publish to TestPyPI"
        or (.name | startswith("documented"))) | [.name, .conclusion]'
```

Each pending publisher becomes an ordinary one with its first upload,
the `Publish to PyPI` job of that run. Its step passes
`pypa/gh-action-pypi-publish` no password, so it uploads with the OIDC
token `release.yml` gives the job, which is trusted publishing.
The last command finds no `password` in the workflow:

```shell
git grep -n -B1 'uses: pypa/gh-action-pypi-publish' \
  -- .github/workflows/release.yml \
  | sed -e 's#.github/workflows/##' \
        -e 's/@\([0-9a-f]\{7\}\)[0-9a-f]*/@\1…/'
git grep -n 'password' -- .github/workflows/release.yml
```

The `.dev` versions on TestPyPI are rehearsal uploads; the release
run's `Publish to TestPyPI` job is skipped.

**The repository's `.homepage` is its page on btclib.org**, as
section 3 has it, set under *Creating the repository* and read back
here rather than from `pyproject.toml`'s own copy of it:

```shell
gh api repos/btclib-org/bip32-descriptors --jq '.homepage'
```

## Read the Docs, which is bip32-descriptors.readthedocs.io

The project is to be imported on [readthedocs.org](https://app.readthedocs.org/)
from `btclib-org/bip32-descriptors` under the slug `bip32-descriptors`, which
is what `release.yml`'s `documented` job and `pyproject.toml`'s
`documentation` url name. The slug is what serves the site, and it is not
the project's name: renaming the slug makes the old one stop answering
rather than redirect. The site answers:

```shell
curl -sL -o /dev/null -w '%{http_code} %{url_effective}\n' \
  https://bip32-descriptors.readthedocs.io/
```

The project's public API answers without a token:

```shell
p=https://app.readthedocs.org/api/v3/projects/bip32-descriptors
curl -s "$p/" | jq -c '{default_branch, repository: .repository.url}'
curl -s "$p/" | jq -c '[.programming_language.code, .homepage]'
diff <(curl -s "$p/" | jq -r '.tags[]' | sort) \
     <(gh api repos/btclib-org/bip32-descriptors --jq '.topics[]' | sort)
```

The project's tags are the repository's topics, which *Topics* sets, and
its homepage is the repository rather than the site it serves.

`stable` follows the highest semantic-version tag, so each release
changes this answer with nothing here having decided differently:

```shell
curl -s "$p/versions/?active=true" \
  | jq -c '.results[] | select(.slug == "latest" or .slug == "stable")
           | [.slug, .type, .ref]'
curl -s "$p/versions/?active=true" | jq -c '[.results[].slug]'
git tag --list 'v*' --sort=version:refname | tail -1
for v in latest stable v<version>; do
  curl -sL -o /dev/null -w '%{http_code} %{url_effective}\n' \
    https://bip32-descriptors.readthedocs.io/en/$v/
done
```

An automation rule, "Activate each v* release tag", is to activate each
new `v*` tag: it matches tags against the custom pattern `^v` and
activates the version. The maintainer adds it in the Read the Docs
interface; its name and pattern rest on that statement. No call reads it back:
the API does not expose it,
`automation-rules/` answering `404` where an endpoint needing a token,
such as `redirects/`, answers `401`. What shows it at work is the
release: the `documented / Check read the docs built the tag` job of
the release run succeeding (the job list under *Publishing* prints it),
and the tag's `/en/v<version>/` answering `200` above, says the tag was
activated and built. That is evidence of the rule's effect, not
a read of the rule.

**Neither the `default_branch` call nor the versions call fails on a
slug nothing holds.** The first reads the `404` body,
`{"detail":"No Project matches the given query."}`, through its filter
as a pair of `null`s, and the versions endpoint answers `200` with an
empty `results`, which the second prints as nothing. The status
is what tells an absent project from one with nothing active:

```shell
curl -s -o /dev/null -w '%{http_code}\n' \
  https://app.readthedocs.org/api/v3/projects/bip32-descriptors/
```

**What connects the repository to Read the Docs is the organization-wide
`read-the-docs-community` GitHub App, not a per-repository webhook**, so
the repository is expected to carry no hook:

```shell
gh api orgs/btclib-org/installations \
  --jq '.installations[] | select(.app_slug == "read-the-docs-community")
        | [.app_slug, .repository_selection]'
gh api repos/btclib-org/bip32-descriptors/hooks --jq length
```

A hook the second command finds is stale and is deleted rather than
repaired, which is section 11's rule.

## Claude Code review

`claude-review.yml` needs the Claude Code GitHub App on the repository.
The organization's installation of it, `150677504`, covers selected
repositories, not all:

```shell
gh api orgs/btclib-org/installations \
  --jq '.installations[] | select(.app_slug == "claude")
        | [.id, .repository_selection]'
```

The maintainer adds this repository to that installation. The
installation's repository list needs a user token with the `read:user`
scope, which this read-back lacks, so a successful `claude-review` run,
`<run-id>` on pull request `<pr>`, is the evidence:

```shell
r=btclib-org/bip32-descriptors
gh run view <run-id> --repo $r --json conclusion --jq .conclusion
gh pr view <pr> --repo $r --json reviews --jq '[.reviews[]
  | select(.author.login == "claude")] | last | .body | split("\n")[0]'
```

## Security settings

Secret scanning, its push protection, Dependabot alerts, Dependabot
security updates and private vulnerability reporting are free on a
public repository and off by default:

```shell
gh api -X PATCH repos/btclib-org/bip32-descriptors --input - <<'JSON'
{"security_and_analysis": {
   "secret_scanning": {"status": "enabled"},
   "secret_scanning_push_protection": {"status": "enabled"}}}
JSON
gh api -X PUT repos/btclib-org/bip32-descriptors/vulnerability-alerts
gh api -X PUT repos/btclib-org/bip32-descriptors/automated-security-fixes
gh api -X PUT repos/btclib-org/bip32-descriptors/private-vulnerability-reporting
```

Code scanning is `codeql.yml`'s, and GitHub's **default setup** has to
stay off: the two are exclusive, and while the setting is on the
workflow's upload is refused. The code-quality setting beside it is off
too, its analysis being slots against the ceiling *Plan-gated settings*
has. `PATCH`, not `PUT`: that endpoint answers a PUT with a bare 404.

```shell
gh api -X PATCH -F state=not-configured \
  repos/btclib-org/bip32-descriptors/code-scanning/default-setup
gh api -X PATCH -F state=not-configured \
  repos/btclib-org/bip32-descriptors/code-quality/setup
```

Read back:

```shell
gh api repos/btclib-org/bip32-descriptors --jq '.security_and_analysis'
gh api -i repos/btclib-org/bip32-descriptors/vulnerability-alerts | head -1
gh api repos/btclib-org/bip32-descriptors/automated-security-fixes
gh api repos/btclib-org/bip32-descriptors/private-vulnerability-reporting
gh api repos/btclib-org/bip32-descriptors/code-scanning/default-setup --jq .state
gh api repos/btclib-org/bip32-descriptors/code-quality/setup --jq .state
```

The alerts endpoint has no body and answers with its status, 204 for
enabled and 404 for not. The two `disabled` fields are the ones
*Plan-gated settings* names. Private vulnerability reporting is what
`SECURITY.md` sends a reporter to, and `.github/ISSUE_TEMPLATE/config.yml`
links the same door: with it disabled that link is a 404.

## Topics

Section 3 makes a package's `keywords` its topics, entry for entry, so
the topics are set from `pyproject.toml` rather than typed a second time:

```shell
sed -n '/^keywords = \[/,/^]/s/^ *"\(.*\)",$/\1/p' pyproject.toml \
  | jq -R . | jq -s '{names: .}' \
  | gh api -X PUT repos/btclib-org/bip32-descriptors/topics --input -
```

Read back, and compared, sorted because GitHub returns topics
alphabetically rather than in `keywords`' order; the diff is expected
empty:

```shell
diff <(gh api repos/btclib-org/bip32-descriptors --jq '.topics[]' | sort) \
     <(sed -n '/^keywords = \[/,/^]/s/^ *"\(.*\)",$/\1/p' pyproject.toml \
       | sort)
```

What the diff compares, the topics as the endpoint returns them:

```shell
gh api repos/btclib-org/bip32-descriptors --jq '.topics'
```

## Plan-gated settings

**The ceiling on concurrent jobs lives here**, and nowhere else in this
tree: it is a number the plan decides rather than anything this repository
configures, so prose that needs the reasoning — a workflow header,
`CONTRIBUTING.md` — states the ceiling unnumbered and points here:

```shell
gh api orgs/btclib-org --jq .plan.name
```

[GitHub's own table](https://docs.github.com/en/actions/reference/limits)
is what turns that answer into a number, shared across every repository
in the organization. That is what every trade above spends: a check
required of a pull request holds a slot every other pull request in the
organization then waits for.

Secret scanning's non-provider patterns and validity checks need paid
Secret Protection, and the API answers a `PATCH` with 200 while leaving
them disabled. The `detect-secrets` hook is the compensating control.

## What this file passes over

The endpoints above answer for more than this repository decides, and the
scope at the top is what leaves the rest out.

**Most of the repository document is not a setting.**
`gh api repos/btclib-org/bip32-descriptors --jq 'keys[]'` answers with URLs,
counts, timestamps and derived state beside the switches, and the
switches among them this file records are the ones a section above reads
back with a call of its own.

**A switch no section of the standard states a rule for stays out.**
`allow_forking`, `allow_update_branch`, `has_discussions`,
`has_downloads` and `is_template` are in that document and no section
above reads any of them back.

**A credential this repository spends and does not hold.**
`claude-review.yml` reads `secrets.CLAUDE_CODE_OAUTH_TOKEN`, which
section 11 makes an organization secret at `visibility=all` in both
stores, so the repository's own stores are expected empty and a copy in
either would be that decision undone:

```shell
gh api repos/btclib-org/bip32-descriptors/actions/secrets --jq .total_count
gh api repos/btclib-org/bip32-descriptors/dependabot/secrets --jq .total_count
gh api repos/btclib-org/bip32-descriptors/actions/organization-secrets \
  --jq '[.total_count, [.secrets[].name]]'
```

The third call reads the organization secrets the repository can see.

**A switch this repository does not set.** `claude-review.yml` calls
`btclib-org/.github`'s `reusable-claude-review.yml`, whose jobs guard on
`vars.CLAUDE_REVIEW_ENABLED`; a variable set here would take precedence
over one of the same name on the organization, so the repository's own
store is read too:

```shell
gh api repos/btclib-org/bip32-descriptors/actions/variables --jq .total_count
```
