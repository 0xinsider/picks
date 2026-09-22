<!-- CHART:BEGIN -->
<a href="https://0xinsider.com/pick-of-the-day"><img src="record.svg" alt="Cumulative return at 1,000 USD per pick through Sep 21, 2026: +18,736.60 USD on 252,000 USD staked across 252 decided picks, 171W 81L, 67.9% hit rate, +7.4% ROI." width="100%"></a>
<!-- CHART:END -->

# 0xinsider picks

Every [0xinsider Pick of the Day](https://0xinsider.com/pick-of-the-day), up to
6 a day, sealed in this repository as a sha256 hash before its game starts and
opened after the market settles. The chart and the table below are recomputed
from the files in `ledger/` on every run, and `verify.py` checks all of it.

A pick is one Polymarket market, one side, and the price we backed it at. The
backend hashes those fields with a 32-byte nonce, 1 hour before kickoff, and the
hash lands here in a commit that GitHub timestamps, not us. After the market
settles the nonce and the fields are appended, and the hash reopens for anyone
with `sha256sum`.

## Check it yourself

```
git clone https://github.com/0xinsider/picks && cd picks && python3 verify.py
```

Standard library only. No network, no credentials, no dependencies. Exit 0 means
every hash reopened, every sealing commit predates its kickoff, and the record
below matches the raw data. Exit 1 names the pick that failed and why.

Clone the full history. `--depth 1` disables the two checks that read git
history, and those are the ones that catch a backdated record.

## The record

<!-- RECORD:BEGIN -->
Record through 2026-09-21.

| | |
| --- | --- |
| Decided picks | 252 |
| Record | 171W 81L 0V |
| Hit rate | 67.9% |
| $1,000 per pick | +18,736.60 USD on 252,000 staked |
| ROI | +7.4% |
| Sealed, not yet settled | 0 |
| Proven sealed before kickoff | 2 |
| No pre-game proof (pre-commitment) | 250 |

Recomputed from `ledger/` by `.github/scripts/mirror.py`, not typed in.
`python3 verify.py` prints the same numbers from the same data.
<!-- RECORD:END -->

Rank 1 each day is free to any signed-in account. Ranks 2 to 6 are Pro. The
record counts all of them the same way: $1,000 on every pick, a win returns
1,000 divided by the backed price, a loss forfeits the stake, a void refunds
it. The stake was $100 until September 22, 2026 (0xinsider/0xinsider#16389);
the figures above and in `index.json` are recomputed at $1,000 for every pick,
including the ones published before that date, and the units, ROI and hit
rate are the same under either stake.

Sealing started on September 21, 2026. Every pick before that is in the record
with no pre-game proof and is marked `"pre_commitment": true`. The table reports
those separately from the proven set and never folds them together.

## How a pick gets here

1. **Publish, kickoff minus 1 hour.** The pick goes live on the site and the
   backend computes `sha256(canonical_json(payload) || nonce)` in the same pass.
2. **Seal, within minutes.** The backend dispatches `seal.yml`, which fetches the
   ledger endpoint and appends the hash, the seal instant and the kickoff to
   `ledger/<YYYY>/<MM>/<date>.json`. No nonce, no payload, no side.
3. **Open, after settlement.** `reveal.yml` appends the nonce, the payload and
   the outcome. A later correction appends to `revisions` and never overwrites.

A pick that reaches kickoff unsealed stays unsealed forever. It shows up as a
settled pick with no proof, never as a proof written after the fact.

## What this does not prove

- That the picks are good. A fully verified record can be a losing one.
- That every pick we made is in here. A pick that is never published leaves no
  trace, in this repository or in any commit-and-reveal scheme.
- That history was never rewritten. `main` blocks force-pushes, every write
  comes from a workflow whose source is in this repository, and your own clone
  disagrees with any rewrite. Take one.

[VERIFY.md](VERIFY.md) states each of these in full, with the canonical form, a
pinned test vector, and the checks in the order they run.

## Layout

```
record.svg                             the chart above, generated from ledger/
ledger/<YYYY>/<MM>/<YYYY-MM-DD>.json   one file per product day
index.json                             every entry, flat, plus the record
verify.py                              the verifier
VERIFY.md                              the protocol
.github/workflows/seal.yml             appends new commitments
.github/workflows/reveal.yml           opens settled ones
.github/workflows/verify.yml           re-verifies all history, daily
.github/scripts/mirror.py              what those workflows run
```

The workflows fetch, diff, append and commit. They compute no hashes: every hash
here is produced by the backend at seal time and copied byte for byte. A mirror
that derived its own would prove only that it can run sha256.

MIT licensed. See [LICENSE](LICENSE).
