# How to verify the Pick of the Day record

0xinsider publishes up to 10 picks a day, each 1 hour before its own kickoff, and
a running record of how those picks did. The record is served from our
database, and this repository is what makes it checkable from outside: every
picks that reach this repository before kickoff carry a hash that can be
reopened after settlement. Git author dates are writer-controlled; this
repository alone cannot independently prove when GitHub received a hash.

This document specifies the scheme precisely enough to reimplement, and states
what it does not prove. Read the last section. A verification document that only
lists its strengths is marketing wearing a lab coat.

## The one-command check

```
git clone https://github.com/0xinsider/picks && cd picks && python3 verify.py
```

`verify.py` uses the Python standard library and nothing else, talks to no
network service, and needs no credentials. Exit 0 means every check passed. Exit
1 names the pick that failed and why.

Clone it properly. `--depth 1` silently disables the two checks that matter,
because both read git history. `verify.py --skip-git` does the same thing on
purpose, and says so in its output.

## What is committed, and when

Each pick has three moments.

**Publish, kickoff minus one hour.** The pick goes live on the site. The backed
side of it -- which market, which outcome, at what price -- is behind sign-in
for rank 1 and behind Pro for ranks 2 to 6. In the same pass the backend
computes

```
commitment_hash = sha256(canonical_json(payload) || nonce)
```

over the eight fields below, using a fresh 32-byte nonce from the operating
system CSPRNG.

**Seal, within minutes of publish.** `seal.yml` in this repository fetches
`GET /api/v1/pick-of-the-day/ledger` and appends the hash, the algorithm
identifier, the seal instant and the kickoff to `ledger/<YYYY>/<MM>/<date>.json`.
No nonce, no payload, no side. Publishing a bare `sha256(payload)` would be
useless here: a pick payload is one market from a known board, one of two sides,
and a price on a one-cent grid, so the whole space is enumerable in seconds. The
nonce is what makes the hash safe to publish while the pick is still live.

That commit is evidence of the pick's contents. `verify.py` compares its git
author date against kickoff. New Seal commits also get a signed receipt for
their exact SHA. A receipt independently witnessed before kickoff, or a clone
retained by someone else before kickoff, provides stronger timing evidence.

**Open, after the market settles.** `reveal.yml` appends the nonce, the full
payload, and the outcome. Anyone can now recompute the hash and confirm it
matches the one committed before the game.

The backend refuses to seal a pick whose kickoff has passed. A pick that reaches
kickoff unsealed stays unsealed forever, and shows up here as a settled pick with
no proof rather than as a proof written after the fact.

## The canonical form

The hash is taken over one JSON object serialized exactly this way. The backend
owns this form (`pick_of_day::commitment` in the 0xinsider backend); this is a
copy of its specification, not a second design.

- **Eight members, no more and no fewer:** `backed_price`, `condition_id`,
  `kickoff`, `pick_date`, `pick_outcome_index`, `pick_outcome_label`,
  `pick_rank`, `platform`.
- **Keys sorted ascending by UTF-8 byte value.** The list above is already in
  that order.
- **No insignificant whitespace.** `{"a":1,"b":"x"}`, never `{ "a": 1 }`. No
  trailing comma and no trailing newline.
- **Strings escaped per RFC 8259 minimal escaping.** `"` and `\` backslashed,
  control characters below U+0020 as `\b \f \n \r \t` where a short form exists
  and `\u00XX` otherwise. Non-ASCII is emitted as raw UTF-8 and is never
  `\u`-escaped. The forward slash is never escaped.
- **`pick_date`:** string, `YYYY-MM-DD`, zero-padded.
- **`kickoff`:** string, RFC 3339 UTC, `YYYY-MM-DDTHH:MM:SSZ`. Whole seconds
  always, with a literal `Z`, never an offset such as `+00:00`. The precision is
  fixed, not chosen from the value. A kickoff carrying a sub-second component is
  refused rather than truncated, so two distinct kickoffs can never collide onto
  one canonical string.
- **`backed_price`:** a JSON **string**, the plain decimal text of the stored
  value at full stored precision, trailing zeros included. Never a JSON number
  and never a float: a float round-trip changes the bytes and the hash misses
  for exactly the prices that do not sit on a binary fraction. Deliberately not
  normalized -- `0.545000` stays `"0.545000"`. Trailing-zero normalization is
  value-dependent and differs between languages (Python's `Decimal.normalize()`
  renders `100` as `1E+2`; Rust's `rust_decimal` renders it as `100`), which is
  the same cross-language trap as a variable timestamp precision.
- **`pick_outcome_index` and `pick_rank`:** JSON numbers, plain integers, no
  decimal point.

In Python the whole serialization is

```python
json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

The nonce is 32 bytes, published as 64 lowercase hex characters, appended to the
UTF-8 bytes of that string and not mixed in any other way.

### Pin your implementation against this vector first

```
payload    {"pick_date": "2026-09-20", "pick_rank": 1, "condition_id": "0xabc",
            "platform": "polymarket", "pick_outcome_index": 1,
            "pick_outcome_label": "Lakers", "backed_price": "0.545000",
            "kickoff": "2026-09-20T23:05:00Z"}

canonical  {"backed_price":"0.545000","condition_id":"0xabc","kickoff":"2026-09-20T23:05:00Z","pick_date":"2026-09-20","pick_outcome_index":1,"pick_outcome_label":"Lakers","pick_rank":1,"platform":"polymarket"}

nonce      000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
sha256     44d18fa5e2aa3a2bf3c971dcc9317c8ccbdfd5480a4773b6d8ffd5fbeeea84dc
```

The canonical string is 199 bytes. The nonce is illustrative and is not a real
one. If your reimplementation does not reproduce that hash, the disagreement is
in your serializer, not in the ledger, and checking it against a real pick would
report a formatting bug as a broken proof. `verify.py` checks this vector before
it checks anything else and refuses to run if it misses.

## Reopening a commitment by hand

No Python. `jq` for the JSON, `xxd` for the nonce, `sha256sum` for the hash. On
macOS use `shasum -a 256` in place of `sha256sum`.

```sh
FILE=ledger/2026/09/2026-09-20.json
RANK=1

# The canonical bytes: compact, sorted keys, no trailing newline.
jq -cSj ".picks[] | select(.pick_rank == $RANK) | .payload" "$FILE" > canonical.json

# The nonce, hex to raw bytes.
jq -r ".picks[] | select(.pick_rank == $RANK) | .commitment_nonce" "$FILE" \
  | xxd -r -p > nonce.bin

# The hash, and the hash we committed to before the game.
cat canonical.json nonce.bin | sha256sum
jq -r ".picks[] | select(.pick_rank == $RANK) | .commitment_hash" "$FILE"
```

`jq -c` produces the compact separators and `-S` the byte-order key sort, which
is the same output Python's `json.dumps` gives with `separators=(",", ":")` and
`sort_keys=True`. `-j` suppresses the trailing newline, which is part of the
hashed bytes if you leave it in.

## Finding the commit that sealed a pick

The hash checks that the payload was not altered. To inspect the timing claim,
find the commit that first put that hash in this repository.

```sh
HASH=$(jq -r '.picks[0].commitment_hash' ledger/2026/09/2026-09-20.json)
git log --reverse --format='%H %aI %s' -S "$HASH" -- ledger/2026/09/2026-09-20.json
```

The first line is the hash's first commit. Its author date must be earlier than
the pick's `payload.kickoff` for the git-dated cohort. Author dates can be set by
the committer, so this comparison is not an independent timestamp. `verify.py`
does the same walk for every pick, reading each
commit's version of the file rather than trusting `-S`, and deliberately does
not pass `--follow`, because a rename would let an unrelated file's history
supply an earlier date.

Two more commands worth running on a repository that claims to be append-only:

```sh
# Anything ever deleted from the ledger.
git log --diff-filter=D --format='%H %aI %s' -- ledger/

# Every author who has ever committed here.
git log --format='%an <%ae>' -- ledger/ | sort -u
```

The second should list only `github-actions[bot]`, plus whoever made the initial
scaffolding commit before any pick existed.

## The file format

One file per product day, at `ledger/<YYYY>/<MM>/<YYYY-MM-DD>.json`.

```json
{
  "pick_date": "2026-09-20",
  "picks": [
    {
      "pick_rank": 1,
      "state": "sealed",
      "commitment_hash": "9f2c...",
      "commitment_algo": "sha256(canonical_json(payload)||nonce)",
      "sealed_at": "2026-09-20T22:00:04Z",
      "kickoff": "2026-09-20T23:05:00Z",
      "permalink": "https://0xinsider.com/pick-of-the-day/2026-09-20/1"
    }
  ]
}
```

When the pick settles, `state` becomes `"opened"` and the entry gains
`commitment_nonce`, `resolved_at`, `outcome`, `payload`, `matchup`, `category`
and `revisions`. `commitment_hash`, `commitment_algo`, `sealed_at` and `kickoff`
keep the values they were sealed with.

Three optional fields identify missing pre-game evidence: `"pre_commitment":
true`, `"outage": "<window id>"`, and `"late_unproven": true`. Each is described
below and excluded from the git-dated cohort.

`index.json` is every entry in one flat array with the recomputed record, for
anything that would rather not walk the tree. Its `record` object carries the
counts (`opened`, `sealed`, `pre_commitment`, `outage`, `late_unproven`, `proven`, `wins`,
`losses`, `voids`, `decided`), `hit_rate` and `roi` as percentage strings, and
the money
figures: `stake_usd`, the flat stake every decided pick is counted at
(`"1000"`); `profit_usd`, the signed P&L at that stake; and `staked`, the
total stake. `proven_record` separately reports the git-dated
cohort. The key `proven` is retained for compatibility; its basis is git author
date, not an independent receipt. None of these figures establish real fills or
subscriber profit; fees are excluded. `profit_usd` was named `profit_per_100` until September 22,
2026, when the stake moved from $100 to $1,000
(0xinsider/0xinsider#16389); every pick, including those published before
that date, is recomputed at the current stake, and `stake_usd` says which one.
`record.svg` is the chart at the top of the README, the cumulative return of
$1,000 on every decided pick. Both are generated from `ledger/` and prove
nothing on their own; `verify.yml` regenerates them and fails on any diff, so
neither can drift from the data.

### Corrections append

An outcome can legitimately change after it is published here. The backend
reconciles settlements against corrected markets in both directions, so a market
that resolves and is later corrected re-maps the pick that was backed on it.

Overwriting `outcome` in place would be indistinguishable from editing a loss
into a win. So every opened pick carries `revisions`, append-only:

```json
"revisions": [
  {
    "outcome": "loss",
    "resolved_at": "2026-09-21T02:40:11Z",
    "parent_commit": "3f1a...",
    "run": "https://github.com/0xinsider/picks/actions/runs/123"
  },
  {
    "outcome": "win",
    "resolved_at": "2026-09-23T14:02:55Z",
    "parent_commit": "8c02...",
    "run": "https://github.com/0xinsider/picks/actions/runs/456"
  }
]
```

The top-level `outcome` is the current one and always equals the last revision.
The earlier value stays visible in the file, not only in the diff.

`commitment_hash` never moves. The commitment is over the pick -- which market,
which side, at what price -- and never over the outcome. A corrected outcome
against an unchanged commitment is exactly the case this design is built to
survive.

**This is enforced, not merely requested.** `verify.py` check 6 reads every
version of a pick in the file's git history, collapses the sequence of outcomes
it has held, and requires `revisions` to record that same sequence in the same
order. It also requires each committed `revisions` array to be a prefix of the
next, and `commitment_hash` to be identical at every point.

The check exists because nothing else here looks at `outcome` at all. The
commitment is taken over the pick, so editing a settled `"loss"` to `"win"` in
place leaves checks 1, 2 and 3 green -- the payload is untouched and the hash
still reopens. That edit is the specific dishonesty this repository exists to
rule out, and check 6 is the only thing that catches it. It does not object to
an outcome changing. It objects to an outcome changing quietly:

```
CORRECTIONS 2026-09-17 rank 2: outcome went loss -> win across history but
revisions records only 1 entry
```

Check 6 reads git history, so `--depth 1` and `--skip-git` both disable it, and
the script says so when they do.

A revision cannot name the commit that carries it, because that hash does not
exist until after the write. `parent_commit` is the head it was written on top
of, and `run` is the GitHub Actions run that made it, which is GitHub's record
rather than ours. To find the commit itself:

```sh
git log --format='%H %aI' -S '8c02' -- ledger/2026/09/2026-09-20.json
```

### Picks that predate this scheme

Picks published before sealing existed carry `"pre_commitment": true`, no hash
and no nonce. They cannot carry a pre-game proof, because none was made. They
count in the record and `verify.py` reports them as a separate number, never
folded into the proven set. Saying so in the data is the honest move; mixing
them in quietly is not.

Each one still carries `payload`: the market (`condition_id`), the side
(`pick_outcome_index`, `pick_outcome_label`), the price and the kickoff, in the
same eight fields a sealed pick opens with. Nothing was hashed over them, so
they prove nothing about when the pick was made. They do let you check the
outcome against the market's own resolution on Polymarket, and they are what
the $1,000-per-pick figures are computed from. `payload.kickoff` is `null` for
a pick published before kickoffs were recorded.

The same marking covers a pick the backend did seal but whose game started
before this repository recorded its first sealed commitment. Its hash never
reached a public ledger before its game, so it has no pre-game proof either,
and presenting a hash published afterwards as one would be the backdated proof
this repository exists to rule out. That exception closes the moment the first
seal lands here: from then on, a hash that arrives after its kickoff is recorded
as it is and fails PRE-GAME.

A pick that reaches kickoff unsealed after that point is marked the same way.
It is counted, and it is not proven.

### Picks whose game started while the mirror was down

There is a third case, and it is neither of the two above: the backend sealed
the pick on time, and this repository could not read the ledger before the game.
The pick was proven to exist by a working backend and by nothing public, which
is not a proof.

Those picks carry their hash, are NOT marked `pre_commitment`, and carry
`"outage": "<window id>"` naming a file under `outages/`:

```json
{
  "id": "2026-09-22-mirror-401",
  "start": "2026-09-22T14:51:23Z",
  "end": "2026-09-22T18:39:07Z",
  "cause": "Every Seal and Reveal run answered 401 ...",
  "reference": "https://github.com/0xinsider/0xinsider/issues/16459"
}
```

`start` and `end` are in the same RFC 3339 whole-second form as a kickoff. The
`id` matches the filename. `cause` and `reference` say what happened and where
it is written up. Extra fields are allowed and ignored. `end` is `null` while
the window is open, and an open window covers every kickoff after its `start`
until it closes.

The mirror writes these windows itself, and that is the only reason the ordering
below can be relied on. The run that first fails to read the ledger commits an
open window before it exits non-zero, carrying the failing run's URL in
`first_failure`; the first run that reads the ledger again sets `end` and
`first_recovery` and commits that BEFORE it appends any hash. Check 2 dates a
window by the commit that introduced its `start` -- the commit that opened it --
and not by whatever touched the file last, because the claim being made is "the
mirror could not read the ledger from here" and it was made at the moment of
failure. Closing the window afterwards is bookkeeping about a gap that is
already on record, and dating the window by the close would push its timestamp
into the same run, sometimes the same second, as the backlog it explains.

`verify.py` reports such a pick as `OUTAGE`: printed in full on every run,
counted, and SUBTRACTED from the proven set, exactly as `pre_commitment` is. It
is not a pass and it is not a failure. The window explains the gap; it does not
close it.

A window is believed for one reason, and it is not that we wrote it. Check 2
requires the window's own commit to PREDATE the commit that first introduced
the hash it covers:

```sh
# When this window was opened, which is the commit that introduced its start.
git log --reverse --format='%H %aI' -S '"2026-09-22T14:51:23Z"' -- outages/2026-09-22-mirror-401.json

# When the hash it covers first appeared.
git log --reverse --format='%H %aI' -S '<the hash>' -- ledger/2026/09/2026-09-22.json
```

The first must come first. A window committed after the hash it names is an
excuse composed once the problem was known, and `verify.py` ignores it and
fails the pick `PRE-GAME` with both commits printed. Moving a window's `start`
earlier after the fact fails identically, because the new bound carries its own
late first commit. Pushing `end` out later does not move that date, and does not
need to: a wider `end` only reaches kickoffs the mirror was up for, and a pick
whose hash was committed before its kickoff is reported as carrying a marker for
a gap that did not happen to it.

This is the same reasoning as `pre_commitment` for a pick that predates the
mirror, applied to a case the scheme had no word for. Neither one claims a
proof. Both say, in the data, exactly which kind of gap this is, so that a red
run keeps meaning a broken proof rather than a broken mirror.

### Late hashes without a prior outage window

The September 22-24, 2026 ledger API outage left nine further hashes absent
until after their kickoffs. No outage window had been published before those
hashes, so creating one now would falsely imply contemporaneous evidence.
Those entries retain their hashes, nonces, outcomes and revisions and carry
`"late_unproven": true`. `verify.py` checks their first hash commits against the
reviewed incident list, prints the late timing and excludes them from the
git-dated cohort. A new late hash is still a PRE-GAME failure; the marker alone
does not grant an exception.

## Independent timing receipts for new seals

When `seal.yml` pushes a changed ledger head, it writes that exact 40-character
commit SHA plus a newline to `pick-seal-commit.txt` in the runner, then has
`actions/attest` sign the file's digest. This repository is public, so GitHub
uses the Sigstore Public Good instance and its independently witnessed,
immutable transparency log. The receipt is stored in GitHub's attestations API;
it is not a new field in the ledger and does not change a pick.
The manual `attest_current` option can recover a missing receipt for the current
head, but its new witness time cannot prove any earlier kickoff.

First find the commit that introduced a particular pick's hash using the
command above. Then reconstruct the receipt file and ask the GitHub CLI to
verify both the digest and the Seal workflow identity:

```sh
COMMIT=<first commit containing this pick's hash>
printf '%s\n' "$COMMIT" > pick-seal-commit.txt
gh attestation verify pick-seal-commit.txt \
  --repo 0xinsider/picks \
  --signer-workflow 0xinsider/picks/.github/workflows/seal.yml \
  --source-ref refs/heads/main \
  --format json | jq '.[].verificationResult.verifiedTimestamps'
```

Compare a **verified** witness timestamp with that pick's kickoff in the
ledger. It counts as independent pregame timing evidence only if it is earlier.
An attestation after kickoff is evidence of a late receipt, not a rescue for
the pick. A missing receipt is not evidence. The existing three-pick git-dated
cohort has no such receipt and is not upgraded by this workflow. `verify.py`
remains an offline hash and git-history check; this optional online check
requires `gh`, `jq`, and access to GitHub's attestation service.

The receipt binds the complete pushed commit, not the backend's selection
process, a real fill, Polymarket settlement, or a pick omitted from both the
site and ledger. The signed witness time is the trust boundary; the git author
date and the attestation's workflow-supplied predicate fields are not.

## What the workflows do, and do not do

Three workflows, all readable in this repository, all guarded so a fork cannot
run them, all with `permissions` denied at the workflow level and granted per
job.

- `seal.yml` appends new commitments and attests each changed pushed head. The
  0xinsider backend dispatches it when a pick is sealed, and it also runs every
  10 minutes from 11:07 UTC
  through 04:57 UTC the next morning as a fallback, which is the drop window
  (11:00 UTC to 23:00 US Eastern) plus the hour after its last drop. Dispatch
  runs show as `workflow_dispatch` in the Actions tab. They run the same
  workflow source as every other run.
- `reveal.yml`, hourly at :17, opens settled commitments. Both it and
  `seal.yml` regenerate the record, `index.json` and `record.svg` from
  `ledger/` after they write.
- `verify.yml`, on every push and pull request and daily, runs `verify.py` over
  the full history and fails the repository if anything is wrong.

None of them computes a hash. They fetch, diff, append and commit. A mirror that
derived its own hashes would prove only that it can run sha256.

None of them keeps a cursor. Each run fetches the whole ledger and appends what
is missing, so a missed run self-heals on the next one and a double run writes
nothing the second time.

Both writing workflows also keep the outage windows above. A run that cannot
read the ledger commits an open window and then fails; the next run that can
read it closes that window, commits it, and only then appends the backlog.

The mirror also refuses to write a nonce or payload for a pick the endpoint
reports as sealed, and fails the run if it sees one. The endpoint is supposed to
make that impossible by serving two different response shapes. This is a second
lock on the same door.

Branch protection on `main` is what keeps history from being rewritten. Force
pushes and branch deletion are blocked, for repository administrators too. From
outside you can read the flag:

```sh
gh api repos/0xinsider/picks/branches/main --jq '.protected'
```

Be clear about what that buys you. The settings behind the flag are readable
only by an administrator of this repository, so `true` is as far as an outsider
gets, and the rest is us telling you again. The check that does not route
through us is your own clone. See the last section.

## What this does NOT prove

**That the picks are good.** A fully verified record can be a losing one. This
repository makes the record checkable, not good. If the hit rate is bad,
the correct outcome of running `verify.py` is a green pass on a bad record.

**Anything about picks marked `pre_commitment`.** Those predate the scheme. They
have no hash, no nonce and no pre-game evidence of any kind. Their presence in
the record rests entirely on trusting us, which is the thing the rest of this
document is trying to avoid. Read the two numbers separately.

**That a pick marked `outage` was sealed before its game.** It says so, and the
backend's own timestamps say so, and neither is a public pre-game commitment.
What the window proves is narrower and still worth having: the gap was recorded
here before the hash it covers landed, so it is not an explanation invented
afterwards. The pick stays out of the proven count.

**That every pick we made is in here.** The scheme checks hashes for the picks in
the ledger. It does not prove the ledger is complete.
Nothing in a commit-and-reveal scheme can prove that, because a pick that is
never published leaves no trace anywhere. What is visible: once a pick is
sealed, it is in a public append-only file, and a sealed entry that never opens
is reported by `verify.py` 72 hours after its kickoff. On each successful
source read, the mirror compares eligible source identities with the public
ledger and refuses a missing or duplicate row. The offline verifier cannot
discover a pick omitted by both sources. Declining to publish a pick at all is not caught by this
repository or by any other commit-and-reveal design.

**That the commit dates are independently true.** A git author date is written
by whoever makes the commit. Ours are made by a GitHub Actions runner, but a
run's start time does not attest that the hash was in a public commit then.
Older hashes have no signed receipt. For a new Seal commit, verify the separate
Sigstore witness time as above; a missing or late receipt does not improve its
pregame proof. A copy you retained before kickoff is another independent check.

**That history was never rewritten.** This is the attack this design has left.
`verify.py` check 2 reads git history, so a force-push that replaced the seal
commits with later ones carrying earlier dates would defeat it and leave the
repository green. Three things make that visible and none of them makes it
impossible: `main` is protected against force-push and deletion, every write
comes from a workflow whose source is in this repository, and any clone anyone
has taken disagrees with the rewrite. If you care about this record, take a
clone. `git fetch` against your own copy is the check, and it costs nothing.

**That a late mirror is not a backdated seal.** If a hash reaches this repository
after kickoff, it supplies no pregame proof. Nine historical hashes from the
September 22-24 source outage carry `late_unproven: true`; the verifier pins
their first-commit identities and prints each one. A new late hash still fails
until reviewed. From this repository alone, a late mirror and a backdated seal
look identical, so neither is counted as pregame evidence.

A committed outage window changes what a run PRINTS and never what it counts.
The pick moves from PRE-GAME to OUTAGE, it stays out of the proven set, and the
window is honoured only because git shows it was committed before the hash. It
still cannot tell you the pick was sealed on time. It tells you the gap was on
the record before the thing it explains arrived, which is the most a repository
can say about its own downtime.

**Everything `verify.py` does not check.** It does not scan for a day file that
was deleted outright, or for a pick removed from a file that stayed. Check 6
covers every pick still present, so removing one outright is the way to drop it
without tripping the check. Deletions are visible in git history, and
`git log --diff-filter=D -- ledger/` under "Finding the commit that sealed a
pick" is how you look. The checks `verify.py` does run are listed at the top of
the script, in the order it runs them.

## Reporting a problem

If `verify.py` fails on a clone you took yourself, that is worth saying in
public. Open an issue at <https://github.com/0xinsider/picks/issues> with the
output. A failure here is either a bug in the mirror or something much worse,
and both need to be visible.
