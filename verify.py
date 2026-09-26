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
Picks eligible for pre-game evidence are committed as

    sha256(canonical_json(payload) || nonce)

which is appended here if the mirror reaches it before kickoff and reveals nothing: the nonce is 256 bits
of CSPRNG output, so the low-entropy payload behind it cannot be recovered by
brute force. After the game settles, the payload and the nonce are appended, and
the hash can be reopened by anyone.

  1. HASH        recompute sha256(canonical_json(payload)||nonce) == committed hash
  2. PRE-GAME    the first hash-bearing commit's git author date predates kickoff,
                 or a late entry has a checked outage or reviewed incident marker
  3. IMMUTABLE   the payload never changed across the file's history
  4. GAPS        no sealed pick stays unopened long past its kickoff
  5. RECORD      wins, losses, hit rate and $1,000/pick P&L recomputed from raw data
  6. CORRECTIONS every outcome this pick has held across the file's history
                 appears in its `revisions`, in the same order; `revisions` only
                 ever grew; `commitment_hash` is the same at every point

Check 2 catches a late hash under the repository's current git history. Git
author dates are writer-controlled; it cannot alone prove when GitHub received
the commit. A repository of settled picks with no pre-game commitment would
pass 1, 3 and 5 while proving nothing about publication time.

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

That a reviewed late commitment was public before kickoff. Those retain their
hashes and outcomes with `late_unproven: true`; each known first hash commit is
pinned in this script, and an unreviewed new late commitment still fails.

That a pick whose game started while this mirror was down was sealed on time.
A pick can be in one of three states with respect to proof, and the data says
which: `pre_commitment`, there was no mirror to be late (or the pick was never
sealed at all); `outage`, the mirror existed and could not read the ledger, in
a window committed to this repository BEFORE the hash landed; and neither, in
which case a newly late hash is a PRE-GAME failure. An `outage`
pick is reported as OUTAGE, counted, and subtracted from the proven set. The
window explains the gap. It does not close it, and it is believed only because
git can show it was written before the thing it explains.

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

# Committed mirror-outage windows, one file per outage. See `load_outages`.
OUTAGE_DIR = Path("outages")

# The end of an outage window that has not closed yet. A window is opened by the
# mirror at its first failed fetch, when nobody knows when the ledger will come
# back, so `end` is null until a run reads the ledger again. Only the "did this
# kickoff fall inside the window" test reads this value; every other check on a
# window is the same whether it is open or closed.
FOREVER = datetime.max.replace(tzinfo=timezone.utc)

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

# Public commitments first written after kickoff during the 2026-09-22 to
# 2026-09-24 ledger API outage. These are disclosures, never proofs. Pin the
# first hash-bearing commit so adding a marker to another late pick cannot
# quietly turn a new verification failure green. See 0xinsider/picks#9.
KNOWN_LATE_COMMITS = {
    ("2026-09-22", rank): "67c9070d9347d6cfb8f8efeaf0e503b4c4a935fc"
    for rank in (1, 4, 5, 6)
} | {
    ("2026-09-23", rank): "67c9070d9347d6cfb8f8efeaf0e503b4c4a935fc"
    for rank in (1, 2, 3, 5)
} | {
    ("2026-09-23", 4): "110a506ebd36e1388b64d710a5d423c045022d2f"
}

# The flat stake the site's record puts on every pick: $100 until 2026-09-22 and
# $1,000 since (0xinsider/0xinsider#16389). The ledger stores only the backed
# price and the outcome, so every money figure is recomputed at this stake, the
# picks before that date included. The site's own arithmetic uses the same
# number (`oxinsider_core::constants::PICK_STAKE_USD`); units, ROI and hit rate
# are the same under either stake.
STAKE_USD = Decimal(1000)
# The most picks one product day can carry: ranks run 1 to this. Mirrors the
# source's `pick_of_day::MAX_DAILY_PICKS`, which moved from 6 to 10 on
# September 24, 2026; a rank above the old bound made every day since read as a
# broken ledger.
MAX_DAILY_PICKS = 10


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


def utc(moment: datetime) -> str:
    """One instant, in one form, so two of them can be compared by eye.

    A commit date carries the committer's own offset, and every timestamp in
    the ledger is written as UTC with a literal Z. A message that prints a
    `+03:00` commit date beside a `Z` kickoff invites a reader to conclude the
    opposite of what it says, so everything printed here is moved to UTC first.
    """
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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


def load_outages() -> list[dict]:
    """Every committed mirror-outage window, one JSON file each under outages/.

    A window records a period in which this repository could not copy a hash out
    of the ledger endpoint: the mirror existed and was down. It carries an `id`
    matching its filename, a `start` and `end` in the same RFC 3339 whole-second
    form as a kickoff, a `cause`, and a `reference` to where the incident is
    written up.

    `end` is null while the window is OPEN. The mirror writes the window itself,
    in the run that first fails to read the ledger, and at that moment the end of
    the outage is not a fact anyone has: it is set by the first run that reads
    the ledger again. An open window is treated as running to FOREVER for the one
    test that reads its end -- whether a kickoff fell inside it -- and is
    otherwise an ordinary window.

    A window is not a proof and it upgrades nothing. A pick whose kickoff falls
    inside one still has no pre-game commitment in this repository; it is
    reported as OUTAGE and subtracted from the proven set, exactly as
    `pre_commitment` is. All the window does is name which gap a late hash
    belongs to, so a reader can tell a broken proof from a broken mirror.

    What makes it believable is ordering, which git checks without trusting
    anyone: the window's own commit must predate the commit that first
    introduced the hash it covers (`window_commit`). A window written afterwards
    is an excuse composed once the problem was known, which is the backdated
    record this whole repository exists to rule out. Writing the window at the
    moment of failure, rather than remembering to write one later, is what makes
    that ordering hold by construction instead of by anyone's diligence.

    A malformed file stops the run. A window is a claim about history, and one
    nobody can parse is not a claim worth reading past.
    """
    windows: list[dict] = []
    if not OUTAGE_DIR.is_dir():
        return windows
    for path in sorted(OUTAGE_DIR.glob("*.json")):
        text = path.read_text()
        try:
            window = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}: not valid JSON: {exc}")
        if not isinstance(window, dict):
            raise SystemExit(f"{path}: an outage window must be a JSON object")
        missing = sorted({"id", "start", "end", "cause", "reference"} - window.keys())
        if missing:
            raise SystemExit(f"{path}: outage window is missing {missing}")
        if window["id"] != path.stem:
            raise SystemExit(
                f"{path}: id is {window['id']!r} but the file is named {path.stem!r}. "
                f"A pick names a window by id, so the two must be the same string."
            )
        for field in ("start", "end"):
            value = window[field]
            if field == "end" and value is None:
                # Open: the outage has not ended yet. `start` is never null --
                # a window with no beginning names no period at all.
                continue
            if not (isinstance(value, str) and len(value) == 20 and value.endswith("Z")):
                allowed = " (or null, while the window is open)" if field == "end" else ""
                raise SystemExit(
                    f"{path}: {field} must be RFC 3339 whole seconds with a literal Z"
                    f"{allowed}, got {value!r}"
                )
            # `window_commit` dates this window by searching the file's history
            # for its exact quoted `start`. A value that also appears elsewhere
            # in the file could match a line nobody meant to pin, and the window
            # would be dated by that line instead of by its own bound.
            occurrences = text.count(f'"{value}"')
            if occurrences != 1:
                raise SystemExit(
                    f"{path}: {value} appears {occurrences} times in quotes in this file. "
                    f"A window's start and end must each appear exactly once, so the "
                    f"commit that set them can be found. Reword the other mention."
                )
        try:
            window["start_at"] = parse_ts(window["start"], f"{path} start")
            window["end_at"] = (
                FOREVER
                if window["end"] is None
                else parse_ts(window["end"], f"{path} end")
            )
        except Failure as exc:
            raise SystemExit(f"{path}: {exc}")
        # An open window passes this by construction: nothing is after FOREVER.
        if window["start_at"] >= window["end_at"]:
            raise SystemExit(
                f"{path}: start {window['start']} is not before end {window['end']}"
            )
        window["open"] = window["end"] is None
        window["path"] = path
        windows.append(window)
    return windows


def window_covering(kickoff: datetime, windows: list[dict]) -> dict | None:
    """The committed outage window a kickoff falls inside, if any."""
    for window in windows:
        if window["start_at"] <= kickoff <= window["end_at"]:
            return window
    return None


def window_bounds(window: dict) -> str:
    """The window's span, in the form a message prints it."""
    if window["end"] is None:
        return f"{window['start']} to still open"
    return f"{window['start']} to {window['end']}"


def window_commit(window: dict) -> tuple[str, datetime]:
    """When this window was FIRST written here, and in which commit.

    The commit that introduced the window's `start`, which is the commit that
    created the file: the mirror writes `start` when it opens the window and
    never rewrites it. That instant is the window's claim -- "the mirror could
    not read the ledger from here" -- and it is what has to predate the hashes
    the window covers.

    Deliberately NOT the later of `start` and `end`. A window is opened with
    `end: null` at the first failed fetch and closed by the first successful
    one, and closing it is bookkeeping about a gap that was already recorded,
    not a new claim. Dating the window by its close would move its timestamp
    forward to the same run -- often the same SECOND, since the close and the
    backlog commit follow each other by milliseconds -- and the record the
    mirror made in real time would read as an excuse written afterwards.

    What this gives up is narrow, and the rest of check 2 covers it. Moving
    `start` earlier after the fact still carries its own late first commit and
    still fails here. Pushing `end` out later no longer does, but a wider `end`
    only reaches kickoffs the mirror was up for, and a pick marked `outage`
    whose hash landed before its kickoff is already reported as a marker
    claiming a gap that did not happen to it.
    """
    return first_commit_introducing(window["path"], f'"{window["start"]}"')


def pre_game_check(
    who: str, path: Path, pick: dict, payload: dict, windows: dict[str, dict]
) -> tuple[list[str], str | None, str | None]:
    """Check 2 for one pick. Returns (failures, notice, unproven class).

    The commit that FIRST introduced this pick's hash must predate its kickoff.
    When it does not, there is exactly one thing that turns the failure into a
    reported gap instead, and every part of it is checked here:

      * the pick names an `outage` window that is committed under outages/;
      * this pick's kickoff falls inside that window;
      * the window's own commit predates the commit that introduced the hash.

    The last one is the one with teeth. It is why a window cannot be written to
    excuse a hash that has already landed, and when it fails the pick stays a
    PRE-GAME failure and the output says why the window did not apply.

    A notice is never a pass. The caller counts it and takes the pick OUT of the
    proven set; it means "this pick has no pre-game proof here, and this is the
    committed outage that is why".
    """
    failures: list[str] = []
    kickoff = parse_ts(payload["kickoff"], "kickoff")
    sha, when = first_commit_introducing(path, pick["commitment_hash"])
    marker = pick.get("outage")
    late_marker = pick.get("late_unproven")

    if late_marker is not None and late_marker is not True:
        return [f"PRE-GAME {who}: late_unproven must be true"], None, None
    if marker is not None and late_marker:
        return [f"PRE-GAME {who}: outage and late_unproven cannot coexist"], None, None

    if when < kickoff:
        if late_marker:
            failures.append(
                f"PRE-GAME {who}: late_unproven marker on a hash first committed "
                f"{utc(when)}, before kickoff {utc(kickoff)}"
            )
        if marker is not None:
            failures.append(
                f"OUTAGE   {who}: carries an outage marker ({marker}) but its hash was "
                f"first committed {utc(when)}, BEFORE kickoff {utc(kickoff)}. "
                f"This pick is proven; the marker claims a gap that did not happen to it."
            )
        return failures, None, None

    late = (
        f"PRE-GAME {who}: hash first committed {utc(when)} in {sha[:10]}, "
        f"at or AFTER kickoff {utc(kickoff)}. "
        f"This pick is not proven to predate its game."
    )
    if marker is None:
        if late_marker:
            expected = KNOWN_LATE_COMMITS.get((payload["pick_date"], payload["pick_rank"]))
            if sha == expected:
                return [], (
                    f"UNPROVEN {who}: hash first appeared {utc(when)} in {sha[:10]}, "
                    f"after kickoff {utc(kickoff)}. This historical incident is "
                    "disclosed, not counted as pre-game proof."
                ), "late"
            return [late, f"PRE-GAME {who}: late_unproven is not a reviewed incident "
                    f"at this first commit ({sha[:10]})"], None, None
        return [late], None, None

    window = windows.get(marker)
    if window is None:
        return [
            late,
            f"OUTAGE   {who}: names outage window {marker!r}, which is not committed "
            f"under {OUTAGE_DIR}/. A window that is not in this repository explains "
            f"nothing and was ignored.",
        ], None, None

    if not (window["start_at"] <= kickoff <= window["end_at"]):
        return [
            late,
            f"OUTAGE   {who}: kickoff {utc(kickoff)} is outside window {marker} "
            f"({window_bounds(window)}). A window covers the games that "
            f"started while the mirror was down, and no others. Ignored.",
        ], None, None

    window_sha, window_when = window_commit(window)
    if window_when >= when:
        return [
            late,
            f"OUTAGE   {who}: window {marker} was itself committed {utc(window_when)} "
            f"in {window_sha[:10]}, at or AFTER the hash it covers ({utc(when)} in "
            f"{sha[:10]}). A window written once the hash had landed is an excuse, not a "
            f"record, and was ignored.",
        ], None, None

    return failures, (
        f"OUTAGE   {who}: kickoff {utc(kickoff)} fell inside {marker} "
        f"({window_bounds(window)}, committed {utc(window_when)} in "
        f"{window_sha[:10]}). The hash first reached this repository {utc(when)}, "
        f"after the game, because the mirror could not read the ledger before it. "
        f"NOT proven, and not counted as proven. See {window['path']}."
    ), "outage"


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


def stake_return(outcome: str, price: Decimal) -> Decimal | None:
    """What a flat STAKE_USD stake returned. Mirrors the site's own arithmetic.

    A win pays STAKE_USD/price, a loss forfeits the stake, a void refunds it.
    A decided pick with no usable price is excluded from money totals rather
    than guessed at, and is still counted in the hit rate.
    """
    if outcome == "win":
        return None if price <= 0 else STAKE_USD / price
    if outcome == "loss":
        return Decimal(0)
    if outcome == "void":
        return STAKE_USD
    return None


def load_ledger() -> list[tuple[Path, dict]]:
    if not LEDGER_DIR.is_dir():
        raise SystemExit(f"no {LEDGER_DIR}/ directory -- run this from the repository root")
    days = []
    for path in sorted(LEDGER_DIR.rglob("*.json")):
        try:
            day = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}: not valid JSON: {exc}")
        pick_date = day.get("pick_date")
        if not isinstance(pick_date, str) or path != LEDGER_DIR / pick_date[:4] / pick_date[5:7] / f"{pick_date}.json":
            raise SystemExit(f"{path}: filename does not match pick_date {pick_date!r}")
        seen: set[int] = set()
        for pick in day.get("picks", []):
            rank = pick.get("pick_rank")
            if not isinstance(rank, int) or isinstance(rank, bool) or not 1 <= rank <= MAX_DAILY_PICKS or rank in seen:
                raise SystemExit(f"{path}: invalid or repeated rank {rank!r}")
            seen.add(rank)
            payload = pick.get("payload")
            if isinstance(payload, dict) and (
                payload.get("pick_date") != pick_date or payload.get("pick_rank") != rank
            ):
                raise SystemExit(f"{path}: rank {rank} payload identity disagrees with its ledger row")
        days.append((path, day))
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

    windows = {window["id"]: window for window in load_outages()}

    failures: list[str] = []
    skips: list[str] = []
    outage_notes: list[str] = []
    late_notes: list[str] = []
    opened = sealed = pre_commitment = outage = late_unproven = 0
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
                            problems, notice, unproven_class = pre_game_check(
                                who, path, pick, payload, windows
                            )
                            failures.extend(problems)
                            if unproven_class == "outage" and notice is not None:
                                outage_notes.append(notice)
                                outage += 1
                            elif unproven_class == "late" and notice is not None:
                                late_notes.append(notice)
                                late_unproven += 1
                        except Failure as exc:
                            failures.append(f"PRE-GAME {who}: {exc}")
                    elif pick.get("outage"):
                        # History was not walked, so the ordering that is the
                        # only reason to believe a window cannot be checked. The
                        # marker is counted so the totals have the same shape
                        # either way, and the skip notice at the end says what
                        # that count is worth here.
                        outage += 1
                    elif pick.get("late_unproven"):
                        late_unproven += 1
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
            value = stake_return(outcome, price) if price > 0 else None
            if value is not None and outcome in ("win", "loss"):
                profit += value - STAKE_USD
                staked += STAKE_USD

    decided = wins + losses
    print(f"picks       {opened} opened, {sealed} sealed and pending")
    if pre_commitment:
        print(
            f"            {pre_commitment} of the opened picks predate this ledger "
            f"and carry NO pre-game proof"
        )
    if outage:
        print(
            f"            {outage} kicked off during a committed mirror outage and "
            f"carry NO pre-game proof either"
        )
    if late_unproven:
        print(
            f"            {late_unproven} hashes first appeared after kickoff "
            f"and carry NO pre-game proof"
        )
    print(f"record      {wins}W {losses}L {voids}V")
    if decided:
        print(f"hit rate    {wins / decided * 100:.1f}%  over {decided} decided")
    if staked > 0:
        label = f"${STAKE_USD:,.0f}/pick"
        print(
            f"profit at {label}: {profit:+,.2f} USD on {staked:,.0f} "
            f"staked, before fees ({profit / staked * 100:+.1f}% ROI)"
        )
    print("            compare these against https://0xinsider.com/pick-of-the-day\n")

    for note in outage_notes + late_notes:
        print(f"  {note}")
    if outage_notes or late_notes:
        print()

    for note in skips:
        print(f"SKIP {note}")
    if skips:
        print()

    if failures:
        print(f"FAILED  {len(failures)} problem(s):\n")
        for line in failures:
            print(f"  {line}")
        return 1

    proven = opened - pre_commitment - outage - late_unproven
    if args.skip_git:
        print(f"PASSED  arithmetic and available hashes; {proven} pick(s) are unverified by this run.")
    else:
        print(f"PASSED  {proven} pick(s) have a git author date before kickoff.")
        print("        Author dates alone do not prove when GitHub received a hash.")
    if outage:
        print(
            f"        {outage} more reached kickoff during a committed mirror outage\n"
            f"        and are reported above. They are NOT proven by this repository."
        )
    if args.skip_git:
        print(
            "        History checks were skipped, so nothing here rules out a\n"
            "        backdated seal, an outcome edited in place, or an outage\n"
            "        window written after the hash it claims to explain."
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
