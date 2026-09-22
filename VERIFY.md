# How to verify the Pick of the Day record

0xinsider publishes up to 6 picks a day, each 1 hour before its own kickoff, and
a running record of how those picks did. The record is served from our
database, and this repository is what makes it checkable from outside: every
pick is committed to before its game and opened after it settles, in a public
file whose history is timestamped by someone other than us.

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

That commit is the evidence. Its date is what `verify.py` compares against the
kickoff.

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

The hash alone proves the payload was not altered. What proves the pick existed
before the game is the date of the commit that first put that hash in this
repository.

```sh
HASH=$(jq -r '.picks[0].commitment_hash' ledger/2026/09/2026-09-20.json)
git log --reverse --format='%H %aI %s' -S "$HASH" -- ledger/2026/09/2026-09-20.json
```

The first line is the sealing commit. Its date must be earlier than the pick's
`payload.kickoff`. `verify.py` does the same walk for every pick, reading each
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

`index.json` is every entry in one flat array with the recomputed record, for
anything that would rather not walk the tree. Its `record` object carries the
counts (`opened`, `sealed`, `pre_commitment`, `proven`, `wins`, `losses`,
`voids`, `decided`), `hit_rate` and `roi` as percentage strings, and the money
figures: `stake_usd`, the flat stake every decided pick is counted at
(`"1000"`); `profit_usd`, the signed P&L at that stake; and `staked`, the
total put down. `profit_usd` was named `profit_per_100` until September 22,
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

## What the workflows do, and do not do

Three workflows, all readable in this repository, all guarded so a fork cannot
run them, all with `permissions` denied at the workflow level and granted per
job.

- `seal.yml` appends new commitments. The 0xinsider backend dispatches it the
  moment a pick is sealed, and it also runs every 10 minutes from 11:07 UTC
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

**That every pick we made is in here.** The scheme proves that the picks in the
ledger were sealed before their games. It does not prove the ledger is complete.
Nothing in a commit-and-reveal scheme can prove that, because a pick that is
never published leaves no trace anywhere. What is visible: once a pick is
sealed, it is in a public append-only file, and a sealed entry that never opens
is reported by `verify.py` 72 hours after its kickoff. Suppressing a loss after
the fact is caught. Declining to publish a pick at all is not, by this
repository or by any other commit-and-reveal design.

**That the commit dates are true, on their own.** A git author date is written
by whoever makes the commit. Ours are made by a GitHub Actions runner, and the
independent record is GitHub's, not the date in the object: every commit here
names its Actions run, and the run has GitHub's own start time on it. Compare
the two if the date is load-bearing for you. A clone you took yourself, at a
time you remember, is stronger evidence than either.

**That history was never rewritten.** This is the attack this design has left.
`verify.py` check 2 reads git history, so a force-push that replaced the seal
commits with later ones carrying earlier dates would defeat it and leave the
repository green. Three things make that visible and none of them makes it
impossible: `main` is protected against force-push and deletion, every write
comes from a workflow whose source is in this repository, and any clone anyone
has taken disagrees with the rewrite. If you care about this record, take a
clone. `git fetch` against your own copy is the check, and it costs nothing.

**That a late mirror is not a backdated seal.** If `seal.yml` fails to run and a
hash reaches this repository after the game has started, `verify.py` reports that
pick as PRE-GAME failed -- correctly. From this repository alone, a mirror that
was late and a seal that was backdated look identical. That is why the failure is
treated as a real one and never explained away, and why `seal.yml` runs every ten
minutes against a one-hour window rather than just often enough.

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
