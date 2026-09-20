# 0xinsider picks: the commitment ledger

0xinsider publishes one Pick of the Day and a public record of how those picks
did. This repository is the part that makes the record checkable by someone who
assumes we are lying.

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
Nothing is mirrored yet. This table fills in with the first sealed pick.

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
