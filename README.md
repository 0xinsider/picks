# 0xinsider picks: the commitment ledger

0xinsider publishes one Pick of the Day and a public record of how those picks
did. This repository is that record at its source: every pick is sealed here as
a hash before its game starts and opened after it settles, so anyone can check
the record for themselves rather than take our word for it.

Every pick is committed to before its game as
`sha256(canonical_json(payload) || nonce)` and appended here while the game is
still ahead of it. After the market settles, the payload and the nonce are
appended too, and anyone can reopen the hash. The commit that carried the hash
is timestamped by GitHub, not by us.

## Check it yourself

```
git clone https://github.com/0xinsider/picks && cd picks && python3 verify.py
```

Standard library only. No network, no credentials, no dependencies. Exit 0 means
every commitment reopened and every one of them was published before its game.
Exit 1 names the pick that failed and why.

Clone the full history. `--depth 1` disables the checks that matter.

## The record

<!-- RECORD:BEGIN -->
Record through 2026-09-20.

| | |
| --- | --- |
| Decided picks | 250 |
| Record | 169W 81L 0V |
| Hit rate | 67.6% |
| $100 per pick | +1747.13 USD on 25000 staked |
| ROI | +7.0% |
| Sealed, not yet settled | 0 |
| Proven sealed before kickoff | 0 |
| No pre-game proof (pre-commitment) | 250 |

Recomputed from `ledger/` by `.github/scripts/mirror.py`, not typed in.
`python3 verify.py` prints the same numbers from the same data.
<!-- RECORD:END -->

## Read next

- [VERIFY.md](VERIFY.md) -- the protocol, the canonical form with a pinned test
  vector, how to reopen a commitment with `sha256sum`, and what this scheme does
  not prove.
- [verify.py](verify.py) -- the checks, in the order they run.
- [The picks themselves](https://0xinsider.com/pick-of-the-day).

## Layout

```
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
