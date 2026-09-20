#!/usr/bin/env python3
"""Verify the 0xinsider Pick of the Day commitment ledger.

Run it yourself. It talks to nothing, needs no credentials, and imports only the
Python standard library, so there is no dependency tree between you and the
answer:

    git clone https://github.com/0xinsider/picks && cd picks && python3 verify.py

Exit 0 means every check below passed. Exit 1 means at least one failed, and the
output names which pick and why. A check that cannot be evaluated is reported as
SKIP and never silently counted as a pass.

What is being checked
---------------------
Each pick is committed BEFORE its game starts as

    sha256(canonical_json(payload) || nonce)

which is appended here at that time and reveals nothing: the nonce is 256 bits
of CSPRNG output, so the low-entropy payload behind it cannot be recovered by
brute force. After the game settles, the payload and the nonce are appended, and
the hash can be reopened by anyone.

  1. HASH        recompute sha256(canonical_json(payload)||nonce) == committed hash
  2. PRE-GAME    the commit that FIRST introduced that hash predates the kickoff
                 recorded in the payload
  3. IMMUTABLE   the payload never changed across the file's history
  4. GAPS        no sealed pick stays unopened long past its kickoff
  5. RECORD      wins, losses, hit rate and $100/pick P&L recomputed from raw data
  6. CORRECTIONS every outcome this pick has held across the file's history
                 appears in its `revisions`, in the same order; `revisions` only
                 ever grew; `commitment_hash` is the same at every point

Check 2 is the one that matters, and the only one that catches a backdated
record. A repository of settled picks with no pre-game commitment would pass 1,
3 and 5 while proving nothing at all.

Check 6 is the one that catches an outcome edited in place. Nothing else here
looks at `outcome` at all: the commitment is taken over the pick and never over
the result, so changing a settled `"loss"` to `"win"` leaves checks 1, 2 and 3
green. An outcome CAN legitimately change, because the backend reconciles
settlements in both directions and a corrected market re-maps an already-settled
pick. What is not legitimate is changing it silently, so check 6 does not ask
whether the outcome moved. It asks whether the move was disclosed.

What this does NOT prove
------------------------
That the picks are good. A verified record can still be a losing one.

That picks published before this ledger existed were made when they claim.
Those carry `"pre_commitment": true` and are excluded from checks 1 and 2 by
construction -- they are counted in the record and reported separately, never
mixed into the proven set.

That history was never rewritten. Check 2 reads git history, so a force-push
that replaced the seal commits would defeat it. `main` is branch-protected
against force-push and every commit here is authored by a workflow whose source
is in this repository, but the honest statement is that this design's remaining
attack is a rewritten history, and your clone's reflog plus any third-party
mirror is what makes that visible. See VERIFY.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

LEDGER_DIR = Path("ledger")

# The eight fields the commitment is taken over, and nothing else. An extra or
# missing key is a failure, not something to tolerate: the hash is only
# meaningful if both sides agree on exactly what went into it.
PAYLOAD_KEYS = frozenset(
    {
        "pick_date",
        "pick_rank",
        "condition_id",
        "platform",
        "pick_outcome_index",
        "pick_outcome_label",
        "backed_price",
        "kickoff",
    }
)

COMMITMENT_ALGO = "sha256(canonical_json(payload)||nonce)"

# Pinned against the backend's own implementation
# (backend/crates/pick-of-day/src/pick_of_day/commitment.rs). If this vector
# stops matching, this script and the sealer have diverged and every result
# below is suspect -- so it is checked before anything else and is fatal.
VECTOR_CANONICAL = (
    '{"backed_price":"0.545000","condition_id":"0xabc",'
    '"kickoff":"2026-09-20T23:05:00Z","pick_date":"2026-09-20",'
    '"pick_outcome_index":1,"pick_outcome_label":"Lakers","pick_rank":1,'
    '"platform":"polymarket"}'
)
VECTOR_PAYLOAD = {
    "pick_date": "2026-09-20",
    "pick_rank": 1,
    "condition_id": "0xabc",
    "platform": "polymarket",
    "pick_outcome_index": 1,
    "pick_outcome_label": "Lakers",
    "backed_price": "0.545000",
    "kickoff": "2026-09-20T23:05:00Z",
}
VECTOR_NONCE = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
VECTOR_HASH = "44d18fa5e2aa3a2bf3c971dcc9317c8ccbdfd5480a4773b6d8ffd5fbeeea84dc"

# How long after kickoff a sealed pick may stay unopened before it is reported.
# Generous on purpose: a market can settle slowly, and this check exists to
# catch picks that quietly never resolve, not to flag slow ones.
SETTLEMENT_GRACE = timedelta(hours=72)


class Failure(Exception):
    """A check that did not pass, with the reason a reader needs."""


def canonical_json(payload: dict) -> str:
    """Reproduce the backend's canonical form byte for byte.

    Sorted keys, no insignificant whitespace, non-ASCII left raw. `backed_price`
    arrives as a STRING and stays one: rendering it as a float here would round
    it, and the hash would miss for exactly the picks whose price does not sit
    on a binary fraction. `pick_outcome_index` and `pick_rank` are JSON numbers.
    """
    missing = PAYLOAD_KEYS - payload.keys()
    extra = payload.keys() - PAYLOAD_KEYS
    if missing or extra:
        raise Failure(
            f"payload key mismatch (missing={sorted(missing)}, unexpected={sorted(extra)})"
        )
    if not isinstance(payload["backed_price"], str):
        raise Failure("backed_price must be a JSON string to survive round-tripping")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def seal(payload: dict, nonce_hex: str) -> str:
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as exc:
        raise Failure(f"nonce is not hex: {exc}") from None
    if len(nonce) != 32:
        raise Failure(f"nonce must be 32 bytes, got {len(nonce)}")
    return hashlib.sha256(canonical_json(payload).encode("utf-8") + nonce).hexdigest()


def self_test() -> None:
    """Fail loudly if this script and the sealer have drifted apart."""
    if canonical_json(VECTOR_PAYLOAD) != VECTOR_CANONICAL:
        raise SystemExit(
            "FATAL: canonical_json does not reproduce the pinned vector.\n"
            "  This script no longer matches the sealer. Every result below "
            "would be meaningless, so nothing was checked."
        )
    if seal(VECTOR_PAYLOAD, VECTOR_NONCE) != VECTOR_HASH:
        raise SystemExit("FATAL: seal() does not reproduce the pinned vector hash.")


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise Failure(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def parse_ts(value: str, what: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Failure(f"{what} is not a valid timestamp: {value!r}") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def first_commit_introducing(path: Path, needle: str) -> tuple[str, datetime]:
    """The oldest commit whose version of `path` contains `needle`.

    Walked oldest-first and returns on the first hit, so a hash that was
    reintroduced later cannot masquerade as an earlier commitment. `--follow`
    is deliberately NOT used: a rename would let an unrelated file's history
    supply an earlier date.
    """
    log = git("log", "--reverse", "--format=%H %aI", "--", str(path)).strip()
    if not log:
        raise Failure(f"no git history for {path}")
    for line in log.splitlines():
        sha, _, iso = line.partition(" ")
        blob = subprocess.run(
            ["git", "show", f"{sha}:{path}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if blob.returncode == 0 and needle in blob.stdout:
            return sha, parse_ts(iso, "commit date")
    raise Failure(f"{needle[:16]}... never appears in the history of {path}")


def pick_history(path: Path, rank: int) -> list[dict]:
    """Every committed version of one pick in this file, oldest first.

    One `git show` per commit that touched the file. Checks 3 and 6 both read
    this, so the history is walked once per pick rather than once per check.
    A commit whose version of the file does not parse, or does not contain this
    rank, contributes nothing and is skipped rather than guessed at.
    """
    versions: list[dict] = []
    for sha in git("log", "--reverse", "--format=%H", "--", str(path)).split():
        blob = subprocess.run(
            ["git", "show", f"{sha}:{path}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if blob.returncode != 0:
            continue
        try:
            day = json.loads(blob.stdout)
        except json.JSONDecodeError:
            continue
        for pick in day.get("picks", []):
            if pick.get("pick_rank") == rank:
                versions.append({"commit": sha, "pick": pick})
                break
    return versions


def payload_versions(history: list[dict]) -> list[str]:
    """Every distinct canonical payload this pick has ever had in this file."""
    seen: list[str] = []
    for version in history:
        pick = version["pick"]
        if "payload" not in pick:
            continue
        try:
            form = canonical_json(pick["payload"])
        except Failure:
            form = json.dumps(pick["payload"], sort_keys=True)
        if form not in seen:
            seen.append(form)
    return seen


def collapse(values: list) -> list:
    """Drop consecutive repeats. [a, a, b, a] -> [a, b, a].

    A commit that rewrites a day file for one rank leaves every other rank
    byte-identical, so the same outcome appears again and again without anything
    having changed. Only a value DIFFERENT from the one before it is a change.
    """
    out: list = []
    for value in values:
        if not out or out[-1] != value:
            out.append(value)
    return out


def correction_failures(who: str, history: list[dict], current: dict) -> list[str]:
    """Check 6. An outcome that moved must say so in `revisions`.

    Three assertions, and the first is the one with teeth:

    1. The sequence of outcomes this pick has held, with consecutive repeats
       collapsed, must match the outcomes its final `revisions` array records.
       An outcome edited from `loss` to `win` with no revision appended leaves a
       two-step history against a one-entry array, and fails here.
    2. `revisions` only ever grew: each committed version of the array must be a
       prefix of the next. A shortened or rewritten array fails, which is the
       same edit made one level up.
    3. `commitment_hash` is identical at every point. A correction that moves
       the hash is not a correction, because the commitment is over the pick and
       the pick did not change.

    Note that a legitimate correction PASSES all three. This check does not
    object to an outcome changing. It objects to an outcome changing quietly.
    """
    failures: list[str] = []

    observed = collapse([v["pick"]["outcome"] for v in history if v["pick"].get("outcome")])
    recorded = collapse(
        [entry.get("outcome") for entry in current.get("revisions") or [] if isinstance(entry, dict)]
    )
    if observed and recorded != observed:
        arrow = " -> ".join(observed)
        if len(recorded) < len(observed):
            failures.append(
                f"CORRECTIONS {who}: outcome went {arrow} across history but revisions "
                f"records only {len(recorded)} entry"
                f"{'' if len(recorded) == 1 else ' entries'}"
            )
        else:
            failures.append(
                f"CORRECTIONS {who}: outcome went {arrow} across history but revisions "
                f"records {' -> '.join(str(value) for value in recorded)}"
            )

    previous: list | None = None
    for version in history:
        revisions = version["pick"].get("revisions")
        if revisions is None:
            continue
        if previous is not None and revisions[: len(previous)] != previous:
            failures.append(
                f"CORRECTIONS {who}: revisions was rewritten in {version['commit'][:10]}. "
                f"It held {len(previous)} entry/entries and must only ever be appended to."
            )
            break
        previous = revisions

    hashes = collapse([v["pick"].get("commitment_hash") for v in history])
    hashes = [value for value in hashes if value]
    if len(set(hashes)) > 1:
        failures.append(
            f"CORRECTIONS {who}: commitment_hash changed across history "
            f"({' -> '.join(value[:16] + '...' for value in hashes)}). "
            f"The commitment is over the pick, never over the outcome."
        )
    return failures


def return_per_100(outcome: str, price: Decimal) -> Decimal | None:
    """What a $100 stake returned. Mirrors the site's own arithmetic.

    A win pays 100/price, a loss forfeits the stake, a void refunds it. A
    decided pick with no usable price is excluded from money totals rather
    than guessed at, and is still counted in the hit rate.
    """
    if outcome == "win":
        return None if price <= 0 else Decimal(100) / price
    if outcome == "loss":
        return Decimal(0)
    if outcome == "void":
        return Decimal(100)
    return None


def load_ledger() -> list[tuple[Path, dict]]:
    if not LEDGER_DIR.is_dir():
        raise SystemExit(f"no {LEDGER_DIR}/ directory -- run this from the repository root")
    days = []
    for path in sorted(LEDGER_DIR.rglob("*.json")):
        try:
            days.append((path, json.loads(path.read_text())))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}: not valid JSON: {exc}")
    return days


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--skip-git",
        action="store_true",
        help="skip the history checks (2, 3 and 6). They need a full clone, not a shallow one.",
    )
    args = parser.parse_args()

    self_test()
    print(f"self-test OK  algo={COMMITMENT_ALGO}\n")

    days = load_ledger()
    if not days:
        print("ledger is empty: nothing to verify, and nothing is claimed.")
        return 0

    failures: list[str] = []
    skips: list[str] = []
    opened = sealed = pre_commitment = 0
    wins = losses = voids = 0
    profit = Decimal(0)
    staked = Decimal(0)
    now = datetime.now(timezone.utc)

    for path, day in days:
        for pick in day.get("picks", []):
            rank = pick.get("pick_rank")
            who = f"{day.get('pick_date')} rank {rank}"
            state = pick.get("state")

            if state == "sealed":
                sealed += 1
                kickoff_raw = pick.get("kickoff")
                if kickoff_raw:
                    try:
                        if parse_ts(kickoff_raw, "kickoff") + SETTLEMENT_GRACE < now:
                            failures.append(
                                f"GAPS     {who}: sealed, still unopened "
                                f"{SETTLEMENT_GRACE} after kickoff. A suppressed "
                                f"loss would look exactly like this."
                            )
                    except Failure as exc:
                        failures.append(f"GAPS     {who}: {exc}")
                continue

            if state != "opened":
                failures.append(f"STATE    {who}: unknown state {state!r}")
                continue

            opened += 1
            outcome = pick.get("outcome")
            if outcome == "win":
                wins += 1
            elif outcome == "loss":
                losses += 1
            elif outcome == "void":
                voids += 1
            else:
                failures.append(f"STATE    {who}: unknown outcome {outcome!r}")

            # Walked once here and read by checks 3 and 6. Check 6 covers EVERY
            # opened pick, `pre_commitment` ones included: those carry no hash
            # to verify, but their outcome can be edited in place exactly like
            # any other, and that edit is what check 6 is for.
            history: list[dict] | None = None
            if not args.skip_git:
                try:
                    history = pick_history(path, rank)
                except Failure as exc:
                    skips.append(f"HISTORY  {who}: {exc}")

            if pick.get("pre_commitment"):
                pre_commitment += 1
            else:
                # 1. HASH
                try:
                    payload = pick["payload"]
                    recomputed = seal(payload, pick["commitment_nonce"])
                    if recomputed != pick["commitment_hash"]:
                        failures.append(
                            f"HASH     {who}: recomputed {recomputed[:16]}... "
                            f"but the ledger committed {pick['commitment_hash'][:16]}..."
                        )
                    elif not args.skip_git:
                        # 2. PRE-GAME
                        try:
                            sha, when = first_commit_introducing(
                                path, pick["commitment_hash"]
                            )
                            kickoff = parse_ts(payload["kickoff"], "kickoff")
                            if when >= kickoff:
                                failures.append(
                                    f"PRE-GAME {who}: hash first committed {when.isoformat()} "
                                    f"in {sha[:10]}, at or AFTER kickoff {kickoff.isoformat()}. "
                                    f"This pick is not proven to predate its game."
                                )
                        except Failure as exc:
                            failures.append(f"PRE-GAME {who}: {exc}")
                except KeyError as exc:
                    failures.append(f"HASH     {who}: opened pick missing {exc}")
                except Failure as exc:
                    failures.append(f"HASH     {who}: {exc}")

                # 3. IMMUTABLE
                if history is not None:
                    versions = payload_versions(history)
                    if len(versions) > 1:
                        failures.append(
                            f"IMMUTABLE {who}: payload changed {len(versions)} times "
                            f"in this file's history. It must be written once."
                        )

            # 6. CORRECTIONS
            if history is not None:
                failures.extend(correction_failures(who, history, pick))

            # 5. RECORD
            try:
                price = Decimal(str(pick.get("payload", {}).get("backed_price", "")))
            except (InvalidOperation, ValueError):
                price = Decimal(-1)
            value = return_per_100(outcome, price) if price > 0 else None
            if value is not None and outcome in ("win", "loss"):
                profit += value - Decimal(100)
                staked += Decimal(100)

    decided = wins + losses
    print(f"picks       {opened} opened, {sealed} sealed and pending")
    if pre_commitment:
        print(
            f"            {pre_commitment} of the opened picks predate this ledger "
            f"and carry NO pre-game proof"
        )
    print(f"record      {wins}W {losses}L {voids}V")
    if decided:
        print(f"hit rate    {wins / decided * 100:.1f}%  over {decided} decided")
    if staked > 0:
        print(
            f"$100/pick   {profit:+.2f} USD on {staked:.0f} staked "
            f"({profit / staked * 100:+.1f}% ROI)"
        )
    print("            compare these against https://0xinsider.com/pick-of-the-day\n")

    for note in skips:
        print(f"SKIP {note}")
    if skips:
        print()

    if failures:
        print(f"FAILED  {len(failures)} problem(s):\n")
        for line in failures:
            print(f"  {line}")
        return 1

    proven = opened - pre_commitment
    print(f"PASSED  {proven} pick(s) proven sealed before their game.")
    if args.skip_git:
        print(
            "        History checks were skipped, so nothing here rules out a\n"
            "        backdated seal or an outcome edited in place."
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
