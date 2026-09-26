#!/usr/bin/env python3
"""Mirror the 0xinsider pick commitment ledger into this repository.

Run by `.github/workflows/seal.yml` and `.github/workflows/reveal.yml`. Standard
library only, same as `verify.py`, so a reader auditing the automation has one
file to read and no dependency tree to audit with it.

WHAT THIS SCRIPT MUST NEVER DO
------------------------------
Compute a commitment hash. Every hash in `ledger/` is produced by the backend at
seal time and copied here byte for byte. A mirror that derived its own hash
would be proving only that it can run sha256, and the first disagreement between
two serializations would read to a stranger as a falsified record rather than as
the formatting bug it is. The single owner of the canonical form is
`pick_of_day::commitment` in the backend; `verify.py` reimplements it on purpose,
because an independent check is the point there. This script does not.

It also must never write the nonce or payload of a pick the endpoint reports as
`sealed`. The endpoint is supposed to make that impossible by serving two
response shapes. This is the second lock: a sealed entry carrying a nonce, a
payload, or the backed side fails the run and writes nothing.

HOW IT DECIDES WHAT TO WRITE
----------------------------
There is no cursor and no state file. The repository is the cursor. Each run
fetches the whole ledger, compares it against what is committed, and appends the
difference. A missed run costs nothing; the next one catches up.

Appends only. An entry already in a day file is never rewritten, with one
exception the format is built for: a `sealed` entry becomes `opened` when the
pick settles, which adds the nonce and payload and never touches the hash. A
later outcome change appends to `revisions` and updates `outcome` in place so the
current truth is readable at the top; the previous value stays in `revisions`, so
the change is visible in the file as well as in the diff.

PICKS WITH NO PRE-GAME PROOF
----------------------------
The endpoint serves a pick that was never sealed as `uncommitted`: every pick
published before sealing existed, and any pick that reached kickoff unsealed.
Once it settles, `reveal` records it as an opened entry marked
`"pre_commitment": true`, with the market, side and price under `payload` and
no hash, because none was ever taken. A still-pending one is skipped until it
settles.

A pick the backend DID seal, but whose game started before this repository
recorded its first sealed commitment, is recorded the same way. Its hash never
reached a public ledger before its game, so publishing it now would be exactly
the after-the-fact proof this repository refuses to present as one. Once the
first seal has landed here, that exception closes: a hash that reaches this
repository after its kickoff is written as it is, and `verify.py` fails it.

There is a third case, and it is the one this script had no vocabulary for
until 0xinsider/0xinsider#16526: the mirror existed and was DOWN. On 2026-09-22
the ledger endpoint answered 401 to every run for nearly four hours, and two
picks reached kickoff with no hash mirrored here. Those picks are not
`pre_commitment` -- they were sealed, on time, by a backend that was working --
and they are not proven either, because nothing public carried the hash before
the game. They are recorded with an `outage` marker naming a window committed
under `outages/`, and `verify.py` reports them as OUTAGE: counted, printed,
subtracted from the proven set, and not a failure. The marker upgrades nothing.
It is honoured only when the window's own commit PREDATES the commit that
introduces the hash, which git can check and nobody can fake, so an outage can
never be written to excuse a hash that has already landed late.

This script writes that window itself. The run that first fails to read the
ledger commits an open window before it exits, and the first run that reads the
ledger again closes it and commits that before it appends any hash. See the
"Outage windows" section below for why the alternative -- remembering to commit
one by hand, in the middle of an incident, before the fix serves -- cost eight
picks their pre-game proof on 2026-09-22.

MODES
-----
  seal        fetch, append commitments not yet committed, regenerate
  reveal      fetch, open settled commitments, append revisions, regenerate
  regenerate  no network: rebuild index.json, record.svg and the README record
              from ledger/
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LEDGER_DIR = REPO_ROOT / "ledger"
OUTAGE_DIR = REPO_ROOT / "outages"
INDEX_PATH = REPO_ROOT / "index.json"
README_PATH = REPO_ROOT / "README.md"
CHART_PATH = REPO_ROOT / "record.svg"

# The money arithmetic lives in verify.py and is imported rather than copied.
# Two implementations of the same sum is how a README quietly stops matching the
# ledger it claims to summarize.
sys.path.insert(0, str(REPO_ROOT))
import verify  # noqa: E402

DEFAULT_URL = "https://api.0xinsider.com/api/v1/pick-of-the-day/ledger"
PERMALINK_BASE = "https://0xinsider.com/pick-of-the-day"

# The window this script opens when it cannot read the ledger. One slug, because
# every outage it can observe by itself is the same observation: the run asked
# the endpoint for the ledger and did not get one. WHY it could not read it is
# the `cause` field, which carries the status line or the transport error.
OUTAGE_SLUG = "ledger-unreachable"
OUTAGE_REFERENCE = (
    "https://github.com/0xinsider/picks/blob/main/VERIFY.md"
    "#picks-whose-game-started-while-the-mirror-was-down"
)

# The committer for every write this script makes.
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"

RECORD_BEGIN = "<!-- RECORD:BEGIN -->"
RECORD_END = "<!-- RECORD:END -->"
CHART_BEGIN = "<!-- CHART:BEGIN -->"
CHART_END = "<!-- CHART:END -->"

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

OUTCOMES = ("win", "loss", "void")
STATES = ("sealed", "opened", "uncommitted")

# Fields that disclose the backed side. None of them may appear on an entry the
# endpoint reports as sealed, and the run fails if one does. The value is never
# printed, by this script or by the workflow that calls it.
SEALED_FORBIDDEN = (
    "commitment_nonce",
    "payload",
    "backed_price",
    "condition_id",
    "pick_outcome_index",
    "pick_outcome_label",
    "outcome",
)

# Written verbatim from the endpoint, in this order. Anything the endpoint sends
# that is not on one of these lists is reported and dropped, never copied
# through: an unannounced field is a contract change to read before it lands in
# an append-only file.
SEALED_FIELDS = (
    "pick_rank",
    "state",
    "commitment_hash",
    "commitment_algo",
    "sealed_at",
    "kickoff",
    "permalink",
)
OPENED_FIELDS = (
    "pick_rank",
    "state",
    "pre_commitment",
    "commitment_hash",
    "commitment_nonce",
    "commitment_algo",
    "sealed_at",
    "kickoff",
    "resolved_at",
    "outcome",
    "payload",
    "matchup",
    "category",
    "permalink",
    "revisions",
)
KNOWN_FIELDS = frozenset(SEALED_FIELDS) | frozenset(OPENED_FIELDS) | {"pick_date"}

# The order an opened record is written in. `outage` is computed HERE, from the
# windows committed under outages/, and is deliberately absent from
# OPENED_FIELDS and KNOWN_FIELDS: the endpoint does not send it, and an endpoint
# that starts sending a field by that name is reported and dropped like any
# other unannounced field rather than being copied onto a proof surface.
RECORD_FIELDS = (
    "pick_rank",
    "state",
    "pre_commitment",
    "outage",
    "late_unproven",
    "commitment_hash",
    "commitment_nonce",
    "commitment_algo",
    "sealed_at",
    "kickoff",
    "resolved_at",
    "outcome",
    "payload",
    "matchup",
    "category",
    "permalink",
    "revisions",
)


class MirrorError(Exception):
    """The run stops and writes nothing."""


def log(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------


def fetch_entries(url: str) -> list[dict]:
    # NO CREDENTIAL. The ledger endpoint is public (0xinsider/0xinsider#16459).
    # It was API-key gated until 2026-09-22, when the key held in the repository
    # secret OXINSIDER_API_KEY was revoked by a routine key rotation on the
    # account that owned it -- one active key per user -- and every Seal and
    # Reveal run failed 401 from 14:51Z. A pick that reaches kickoff without a
    # mirrored hash can never be proven by any later run, so a public record
    # cannot depend on one person's key surviving a rotation. Sending a key here
    # again would reintroduce exactly that failure, and the endpoint gains
    # nothing from it: what withholds a live pick's nonce and side is the
    # backend's own state machine, never the caller's credential.
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "0xinsider-picks-mirror (+https://github.com/0xinsider/picks)",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        # The body can carry an error reason and never carries a credential.
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise MirrorError(f"GET {url} answered {exc.code}: {detail}") from None
    except urllib.error.URLError as exc:
        raise MirrorError(f"GET {url} failed: {exc.reason}") from None

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise MirrorError(f"GET {url} did not return JSON: {exc}") from None

    # The v1 envelope: {"object": "pick_of_the_day_ledger", "data": {"entries":
    # [...], "entry_count": ...}, "meta": {...}}. Unwrapped first, and the object
    # name checked, so a different endpoint behind a misconfigured URL fails
    # here instead of being read as a ledger.
    if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict):
        name = parsed.get("object")
        if name is not None and name != "pick_of_the_day_ledger":
            raise MirrorError(f"GET {url} returned object {name!r}, not pick_of_the_day_ledger")
        parsed = parsed["data"]

    # Past the envelope, accept a bare array or a single list-valued member, and
    # fail loudly on anything else rather than silently mirroring nothing.
    if isinstance(parsed, list):
        entries = parsed
    elif isinstance(parsed, dict):
        found = [key for key in ("entries", "picks", "ledger", "data") if isinstance(parsed.get(key), list)]
        if len(found) != 1:
            raise MirrorError(
                f"GET {url} returned an object with no single list member "
                f"(top-level keys: {sorted(parsed)})"
            )
        entries = parsed[found[0]]
    else:
        raise MirrorError(f"GET {url} returned {type(parsed).__name__}, not a ledger")

    if not all(isinstance(entry, dict) for entry in entries):
        raise MirrorError("the ledger contains an entry that is not an object")
    log(f"fetched {len(entries)} entry/entries from {url}")
    return entries


# --------------------------------------------------------------------------
# Outage windows
# --------------------------------------------------------------------------
#
# WHY THIS SCRIPT WRITES ITS OWN OUTAGE RECORD
#
# A window under `outages/` is honoured by `verify.py` only when the window's
# own commit PREDATES the commit that first introduced the hash it covers. That
# ordering is the whole value of the record: a window written once the late hash
# has landed is an excuse composed after the fact, and is ignored.
#
# Until 0xinsider/0xinsider#17192, nothing produced that commit. It depended on a
# person noticing the mirror was failing and committing a window by hand BEFORE
# the ledger came back. On 2026-09-22 the ledger endpoint answered 500 from about
# 21:40Z until 2026-09-24T01:05Z; the backlog landed here at 01:08:29Z; no window
# had been committed; and eight picks whose games started in that gap are
# permanently PRE-GAME failures. The backend had sealed every one of them on
# time. Only the public copy was late, and no commit made afterwards can fix it.
#
# So the mirror records the outage itself, at the only moment when the record is
# not an excuse: the run that fails. The first failing run commits an OPEN window
# (`end: null`) before it exits non-zero. The first run that reads the ledger
# again closes that window -- `end` and `first_recovery` -- and commits THAT
# before it appends a single hash. The window's commit therefore predates every
# hash it could ever cover, by construction rather than by anyone's diligence.
#
# `verify.py` dates a window by the commit that introduced its `start`, which is
# the commit that opened it, so closing a window later never moves its timestamp
# forward past the backlog it explains.


def stamp(moment: datetime) -> str:
    """One instant in the RFC 3339 whole-second form the ledger uses."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_windows() -> list[tuple[Path, dict]]:
    """Every file under outages/, parsed, sorted by name.

    Parsed here rather than through `verify.load_outages` on purpose: this runs
    on the failure path, and `load_outages` exits the process on a malformed
    window. A window this script cannot read still has to stop it from opening a
    second one, so a broken file raises and the run fails with that reason
    instead of quietly starting a duplicate record.
    """
    if not OUTAGE_DIR.is_dir():
        return []
    found: list[tuple[Path, dict]] = []
    for path in sorted(OUTAGE_DIR.glob("*.json")):
        try:
            window = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise MirrorError(f"{path}: not valid JSON: {exc}") from None
        if not isinstance(window, dict):
            raise MirrorError(f"{path}: an outage window must be a JSON object")
        found.append((path, window))
    return found


def open_window() -> tuple[Path, dict] | None:
    """The one window that has not closed yet, if there is one.

    At most one is ever open: an outage is a state of this mirror, not of a
    workflow, and Seal and Reveal share a concurrency group precisely so the two
    of them take turns writing here.
    """
    for path, window in read_windows():
        if window.get("end") is None:
            return path, window
    return None


def write_window(path: Path, window: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(window, indent=2, ensure_ascii=False) + "\n")


def next_window_path(day: str) -> Path:
    """`outages/<UTC date>-ledger-unreachable.json`, with a suffix if taken.

    The id is the filename and `verify.py` requires the two to match, so a second
    outage on one day gets `-2`, `-3`, and so on rather than reopening a window
    that already closed.
    """
    path = OUTAGE_DIR / f"{day}-{OUTAGE_SLUG}.json"
    ordinal = 2
    while path.exists():
        path = OUTAGE_DIR / f"{day}-{OUTAGE_SLUG}-{ordinal}.json"
        ordinal += 1
    return path


def sync_main() -> None:
    """Throw the local tree away and take origin's, dropping our own commit."""
    git("fetch", "origin", "main")
    git("reset", "--hard", "origin/main")


def commit_window(path: Path, subject: str, body: str) -> bool:
    """Commit and push one window file, and nothing else."""
    git("add", "--", str(path.relative_to(REPO_ROOT)))
    if not git("diff", "--cached", "--quiet", check=False).returncode:
        log(f"{path.name}: nothing to commit")
        return True
    git(
        "-c",
        f"user.name={BOT_NAME}",
        "-c",
        f"user.email={BOT_EMAIL}",
        "commit",
        "-m",
        f"{subject}\n\n{body}",
    )
    pushed = git("push", "origin", "HEAD:main", check=False)
    if pushed.returncode == 0:
        log(f"pushed {head()[:10]}  {subject}")
        return True
    log(f"push rejected: {pushed.stderr.strip()}")
    return False


def record_outage(cause: str) -> None:
    """Open and push a window, now, because the ledger did not answer.

    Idempotent against a racing run the same way the ledger writes are: on a
    rejected push the local commit is dropped, origin is re-read, and the
    decision is made again on that tree. If a peer opened a window in the
    meantime, this sees it and writes nothing -- one outage, one record.

    A failure to record does NOT become the run's error. The caller is already
    failing on the fetch, which is the thing to report; this is logged and the
    next failing run tries again.
    """
    for attempt in range(1, 4):
        already = open_window()
        if already is not None:
            log(f"outage window {already[0].name} is already open; not opening a second")
            return
        started = datetime.now(timezone.utc)
        path = next_window_path(started.strftime("%Y-%m-%d"))
        window = {
            "id": path.stem,
            "start": stamp(started),
            "end": None,
            "cause": cause,
            "reference": OUTAGE_REFERENCE,
            "first_failure": run_url(),
            "first_recovery": None,
            "notes": (
                "Opened by the mirror itself, in the run that first failed to read the "
                "ledger, and committed before that run exited. end is null until a run "
                "reads the ledger again and closes this window, which it does before it "
                "appends any hash. A pick whose kickoff falls inside this window and "
                "whose hash therefore reached this repository late is recorded with an "
                "outage marker naming this id, and stays unproven: the window explains "
                "the gap, it does not close it."
            ),
        }
        write_window(path, window)
        subject = f"outage: {path.stem} opened, the ledger did not answer"
        body = (
            f"{cause}\n\n"
            f"Committed before this run exits, so the record of the gap predates any "
            f"hash that lands late because of it. Closed by the first run that reads "
            f"the ledger again.\n"
            f"run: {run_url()}\n"
        )
        if commit_window(path, subject, body):
            log(f"recorded outage window {path.name}, open from {window['start']}")
            return
        log(f"retrying the outage window on a fresh main (attempt {attempt} of 3)")
        sync_main()
    log("could not push the outage window after 3 attempts; the next failing run retries")


def close_outage(recovered: datetime) -> None:
    """Close the open window, if any, and push it BEFORE anything else.

    Raises rather than continuing if it cannot. Appending hashes under a window
    that is still open would produce exactly the ordering this mechanism exists
    to prevent -- the backlog first, the record of why it was late afterwards --
    and the next run recovers both, in the right order, at no cost.
    """
    for attempt in range(1, 4):
        found = open_window()
        if found is None:
            return
        path, window = found
        window["end"] = stamp(recovered)
        window["first_recovery"] = run_url()
        write_window(path, window)
        subject = f"outage: {path.stem} closed, the ledger answered again"
        body = (
            f"The mirror read the ledger at {window['end']}, after failing from "
            f"{window['start']}. Committed before the backlog this run is about to "
            f"append, so the window predates every hash it covers.\n"
            f"run: {run_url()}\n"
        )
        if commit_window(path, subject, body):
            log(f"closed outage window {path.name} at {window['end']}")
            return
        log(f"retrying the outage close on a fresh main (attempt {attempt} of 3)")
        sync_main()
    raise MirrorError(
        "could not push the outage window's close after 3 attempts. Nothing was "
        "appended: a hash must never land before the window that explains it. The "
        "next run closes the window and appends the backlog behind it."
    )


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def require(condition: bool, message: str) -> None:
    if not condition:
        raise MirrorError(message)


def check_canonical_timestamp(entry: dict, field: str, who: str) -> None:
    """For `kickoff` only, which is hashed.

    The canonical form is whole seconds with a literal `Z` at a FIXED precision,
    so a verifier never has to reproduce a shortest-lossless heuristic. Anything
    else here would be a different string from the one the backend hashed.
    """
    value = entry.get(field)
    require(
        isinstance(value, str) and TS_RE.match(value) is not None,
        f"{who}: {field} is not RFC 3339 whole seconds with a literal Z: {value!r}",
    )


def check_timestamp(entry: dict, field: str, who: str, nullable: bool = False) -> None:
    """For `sealed_at`, `resolved_at` and an unhashed kickoff.

    Stored verbatim and checked only for being a real instant. Their precision
    is the endpoint's business: refusing a microsecond here would stop the mirror
    over a field that no proof depends on. `nullable` is for the fields the
    endpoint documents as `null` when unknown: `resolved_at` on a pick settled
    before the backend stamped it, and the kickoff of a pick published before
    kickoffs were frozen.
    """
    value = entry.get(field)
    if value is None and nullable:
        return
    require(isinstance(value, str), f"{who}: {field} is missing")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise MirrorError(f"{who}: {field} is not a valid timestamp: {value!r}") from None


def validate(entry: dict) -> tuple[str, int, str]:
    """Check one endpoint entry. Returns (pick_date, pick_rank, state)."""
    pick_date = entry.get("pick_date")
    require(
        isinstance(pick_date, str) and DATE_RE.match(pick_date) is not None,
        f"entry has no usable pick_date: {pick_date!r}",
    )
    rank = entry.get("pick_rank")
    require(
        isinstance(rank, int) and not isinstance(rank, bool) and rank >= 1,
        f"{pick_date}: pick_rank is not a positive integer: {rank!r}",
    )
    who = f"{pick_date} rank {rank}"
    state = entry.get("state")
    require(state in STATES, f"{who}: unknown state {state!r}")

    unknown = sorted(set(entry) - KNOWN_FIELDS)
    if unknown:
        log(f"NOTICE {who}: endpoint sent unknown field(s) {unknown}; not mirrored")

    if state == "sealed":
        leaked = [f for f in SEALED_FORBIDDEN if entry.get(f) is not None]
        if leaked:
            # The value is deliberately not printed. This is the failure the
            # second lock exists for, and it must not be the thing that leaks.
            raise MirrorError(
                f"{who}: the endpoint served {leaked} on a SEALED pick. That is the "
                f"backed side of a live pick. Nothing was written. Fix the endpoint "
                f"(0xinsider/0xinsider#15704) before running this again."
            )
        require(
            isinstance(entry.get("commitment_hash"), str)
            and HEX64_RE.match(entry["commitment_hash"]) is not None,
            f"{who}: commitment_hash is not 64 lowercase hex characters",
        )
        require(
            entry.get("commitment_algo") == verify.COMMITMENT_ALGO,
            f"{who}: commitment_algo is {entry.get('commitment_algo')!r}, "
            f"expected {verify.COMMITMENT_ALGO!r}",
        )
        check_timestamp(entry, "sealed_at", who)
        # Strict: this is the same instant the payload will carry when the pick
        # opens, so it has to be written in the same canonical form. A sealed
        # kickoff in another precision would silently disagree with the payload
        # it is supposed to match.
        check_canonical_timestamp(entry, "kickoff", who)
        return pick_date, rank, state

    if state == "uncommitted":
        validate_uncommitted(entry, pick_date, rank, who)
        return pick_date, rank, state

    require(entry.get("outcome") in OUTCOMES, f"{who}: unknown outcome {entry.get('outcome')!r}")
    check_timestamp(entry, "resolved_at", who, nullable=True)

    payload = entry.get("payload")
    require(isinstance(payload, dict), f"{who}: opened entry has no payload object")
    check_payload(payload, pick_date, rank, who)
    check_canonical_timestamp(payload, "kickoff", f"{who} payload")
    if entry.get("kickoff") is not None:
        require(
            entry["kickoff"] == payload["kickoff"],
            f"{who}: entry kickoff {entry['kickoff']} disagrees with payload "
            f"kickoff {payload['kickoff']}",
        )

    if is_pre_commitment(entry):
        require(
            not entry.get("commitment_nonce"),
            f"{who}: marked pre_commitment but carries a nonce",
        )
        return pick_date, rank, state

    require(
        isinstance(entry.get("commitment_hash"), str)
        and HEX64_RE.match(entry["commitment_hash"]) is not None,
        f"{who}: commitment_hash is not 64 lowercase hex characters",
    )
    require(
        isinstance(entry.get("commitment_nonce"), str)
        and HEX64_RE.match(entry["commitment_nonce"]) is not None,
        f"{who}: commitment_nonce is not 64 lowercase hex characters (32 bytes)",
    )
    require(
        entry.get("commitment_algo") == verify.COMMITMENT_ALGO,
        f"{who}: commitment_algo is {entry.get('commitment_algo')!r}, "
        f"expected {verify.COMMITMENT_ALGO!r}",
    )
    check_timestamp(entry, "sealed_at", who)
    return pick_date, rank, state


def check_payload(payload: dict, pick_date: str, rank: int, who: str) -> None:
    """The eight payload fields, hashed or not. Kickoff form is the caller's."""
    missing = verify.PAYLOAD_KEYS - payload.keys()
    extra = payload.keys() - verify.PAYLOAD_KEYS
    require(
        not missing and not extra,
        f"{who}: payload key mismatch (missing={sorted(missing)}, unexpected={sorted(extra)})",
    )
    require(
        isinstance(payload["backed_price"], str),
        f"{who}: backed_price must be a JSON string at full stored precision, "
        f"got {type(payload['backed_price']).__name__}",
    )
    require(
        payload["pick_date"] == pick_date and payload["pick_rank"] == rank,
        f"{who}: payload identifies {payload['pick_date']} rank {payload['pick_rank']}",
    )


def validate_uncommitted(entry: dict, pick_date: str, rank: int, who: str) -> None:
    """A pick with no commitment: nothing to open, and nothing to leak while live.

    While it is pending it must carry no side and no price, exactly like a
    sealed entry, and the run fails without writing if it does. Once settled
    it may carry `payload`, the pick's market, side and price, which nothing
    was hashed over.
    """
    require(entry.get("pre_commitment") is True, f"{who}: uncommitted entry is not marked pre_commitment")
    carried = [f for f in ("commitment_hash", "commitment_nonce") if entry.get(f) is not None]
    require(not carried, f"{who}: uncommitted entry carries {carried}")
    outcome = entry.get("outcome")
    require(outcome in OUTCOMES + ("pending",), f"{who}: unknown outcome {outcome!r}")

    if outcome == "pending":
        leaked = [f for f in SEALED_FORBIDDEN if f != "outcome" and entry.get(f) is not None]
        if leaked:
            raise MirrorError(
                f"{who}: the endpoint served {leaked} on a PENDING uncommitted pick. "
                f"That is the backed side of a live pick. Nothing was written. Fix "
                f"the endpoint (0xinsider/0xinsider#15892) before running this again."
            )
        return

    check_timestamp(entry, "resolved_at", who, nullable=True)
    payload = entry.get("payload")
    if payload is None:
        return
    require(isinstance(payload, dict), f"{who}: payload is not an object")
    check_payload(payload, pick_date, rank, who)
    check_timestamp(payload, "kickoff", f"{who} payload", nullable=True)


def is_pre_commitment(entry: dict) -> bool:
    """A settled pick with no commitment predates the scheme.

    Either the endpoint says so outright, or it serves an opened entry with no
    hash, which can only be a pick published before sealing existed. Marking it
    in the data is the honest move: `verify.py` excludes these from the hash and
    pre-game checks by construction, counts them in the record, and reports them
    separately. Quietly mixing them into the proven set is the failure this flag
    exists to prevent.
    """
    if entry.get("pre_commitment") is True or entry.get("state") == "uncommitted":
        return True
    return entry.get("state") == "opened" and not entry.get("commitment_hash")


def first_mirrored_seal() -> datetime | None:
    """When this repository first recorded a sealed commitment, or `None`.

    The date of the oldest commit that introduced a `"state": "sealed"` entry
    under ledger/: the moment a public pre-game proof first became possible
    here. It is the same commit-date evidence `verify.py` check 2 reads, not the
    backend's `sealed_at`, which can be hours earlier than any mirror run.

    Needs full history, which both writing workflows fetch. A shallow clone
    would return its one commit and silently move the cutoff later, widening
    the exemption `predates_mirror` grants, so it is refused instead.
    """
    shallow = git("rev-parse", "--is-shallow-repository").stdout.strip()
    require(
        shallow == "false",
        "this clone is shallow, so the first sealed commit cannot be found. "
        "Check out with fetch-depth: 0.",
    )
    dates = git(
        "log", "--reverse", "--format=%aI", "-S", '"state": "sealed"', "--", "ledger"
    ).stdout.split()
    if not dates:
        return None
    return datetime.fromisoformat(dates[0].replace("Z", "+00:00"))


def predates_mirror(entry: dict, cutoff: datetime | None) -> bool:
    """A hashed pick whose game started before this repository sealed anything.

    Its hash never reached a public ledger before kickoff, so there is no
    pre-game proof to present. It is recorded as `pre_commitment`, which is the
    truth, rather than as a PRE-GAME failure, which would describe a mirror that
    was late when in fact it did not exist yet. After the first seal lands here
    this returns False for every later game, so a genuinely late mirror still
    fails `verify.py`, loudly.
    """
    if not entry.get("commitment_hash"):
        return False
    kickoff = (entry.get("payload") or {}).get("kickoff") or entry.get("kickoff")
    if not isinstance(kickoff, str):
        return False
    if cutoff is None:
        return True
    return datetime.fromisoformat(kickoff.replace("Z", "+00:00")) < cutoff


def outage_window(entry: dict, windows: list[dict]) -> str | None:
    """The committed outage window this pick's kickoff fell inside, or None.

    Stamped on a pick whose hash this repository is recording for the first time
    AFTER its game because the mirror could not read the ledger while the pick
    was live. It changes nothing about the pick's proof: the hash still arrives
    late, `verify.py` still refuses to count it among the proven, and the marker
    only says which committed gap it belongs to.

    Stamping one can never launder a late hash. `verify.py` honours a window
    only if the window's own commit predates the commit introducing the hash,
    so a window that does not already exist when this runs is worth nothing,
    however this script labels the pick.

    The windows are loaded by `verify.load_outages`, which validates them, and
    read here rather than reimplemented for the same reason the money
    arithmetic is: two readers of one format drift apart quietly.

    An OPEN window is not consulted. Reaching this line means the ledger was
    read, and any window that was open when the run started has already been
    closed and committed by `close_outage`, so an open window here can only
    belong to a `--no-push` dry run. Its end is unknown, which `verify.py` reads
    as running forever, and stamping a pick against it would claim a gap whose
    extent nobody knows yet.
    """
    if not entry.get("commitment_hash"):
        return None
    kickoff = (entry.get("payload") or {}).get("kickoff") or entry.get("kickoff")
    if not isinstance(kickoff, str):
        return None
    window = verify.window_covering(
        datetime.fromisoformat(kickoff.replace("Z", "+00:00")),
        [found for found in windows if found.get("end") is not None],
    )
    return window["id"] if window else None


# --------------------------------------------------------------------------
# Day files
# --------------------------------------------------------------------------


def day_path(pick_date: str) -> Path:
    year, month, _ = pick_date.split("-")
    return LEDGER_DIR / year / month / f"{pick_date}.json"


def load_day(pick_date: str) -> dict:
    path = day_path(pick_date)
    if not path.exists():
        return {"pick_date": pick_date, "picks": []}
    day = json.loads(path.read_text())
    require(
        day.get("pick_date") == pick_date,
        f"{path}: pick_date is {day.get('pick_date')!r}, expected {pick_date!r}",
    )
    return day


def write_day(day: dict) -> None:
    path = day_path(day["pick_date"])
    path.parent.mkdir(parents=True, exist_ok=True)
    day["picks"].sort(key=lambda pick: pick["pick_rank"])
    path.write_text(json.dumps(day, indent=2, ensure_ascii=False) + "\n")


def ordered(entry: dict, fields: tuple[str, ...]) -> dict:
    return {field: entry[field] for field in fields if entry.get(field) is not None}


def read_all_days() -> list[tuple[Path, dict]]:
    days = []
    for path in sorted(LEDGER_DIR.rglob("*.json")):
        days.append((path, json.loads(path.read_text())))
    return days


# --------------------------------------------------------------------------
# seal
# --------------------------------------------------------------------------


def apply_seal(entries: list[dict]) -> list[str]:
    """Append commitments this repository has not recorded yet.

    Sealed entries only. An entry that arrives already settled belongs to
    `reveal`, which records it with everything it knows -- including that its
    hash reached this repository after the game, which `verify.py` reports.
    """
    changes: list[str] = []
    by_date: dict[str, list[dict]] = {}
    now = datetime.now(timezone.utc)
    for entry in entries:
        pick_date, rank, state = validate(entry)
        if state != "sealed":
            continue
        # A hash committed after kickoff can never be a pre-game proof. Writing
        # it here as `sealed` would only guarantee a PRE-GAME failure later, so
        # it is left to `reveal`, which records it with everything it knows.
        if datetime.fromisoformat(entry["kickoff"].replace("Z", "+00:00")) <= now:
            log(f"NOTICE {pick_date} rank {rank}: kickoff has passed; not sealing it late")
            continue
        by_date.setdefault(pick_date, []).append(entry)

    for pick_date in sorted(by_date):
        day = load_day(pick_date)
        known = {pick["pick_rank"] for pick in day["picks"]}
        added = 0
        for entry in sorted(by_date[pick_date], key=lambda item: item["pick_rank"]):
            if entry["pick_rank"] in known:
                continue
            record = ordered(entry, SEALED_FIELDS)
            record.setdefault("permalink", f"{PERMALINK_BASE}/{pick_date}/{entry['pick_rank']}")
            day["picks"].append(record)
            added += 1
        if added:
            write_day(day)
            changes.append(f"{pick_date}: sealed {added}")
    return changes


# --------------------------------------------------------------------------
# reveal
# --------------------------------------------------------------------------


def revision(entry: dict, context: dict) -> dict:
    """One append-only line of the outcome history.

    `parent_commit` is the repository head this revision was written on top of.
    The commit that carries the revision cannot name its own hash, so the pair
    (parent_commit, run) is what pins the write: the parent fixes its place in
    history, and the run is GitHub's own timestamped record of the job that made
    it. VERIFY.md gives the command that finds the commit itself.
    """
    return {
        "outcome": entry["outcome"],
        "resolved_at": entry.get("resolved_at"),
        "parent_commit": context["parent_commit"],
        "run": context["run"],
    }


def apply_reveal(entries: list[dict], context: dict) -> list[str]:
    changes: list[str] = []
    by_date: dict[str, list[dict]] = {}
    still_pending = 0
    for entry in entries:
        pick_date, _, state = validate(entry)
        if state == "opened":
            by_date.setdefault(pick_date, []).append(entry)
        elif state == "uncommitted":
            if entry["outcome"] == "pending":
                still_pending += 1
                continue
            # An endpoint older than 0xinsider/0xinsider#15892 omits `payload`
            # entirely; a current one always sends it, `null` included. Writing
            # a settled pick without its side would be permanent, because this
            # ledger only appends, so the run stops instead.
            require(
                "payload" in entry,
                f"{pick_date} rank {entry['pick_rank']}: the endpoint serves settled "
                f"uncommitted picks without a payload field. It predates "
                f"0xinsider/0xinsider#15892; nothing was written.",
            )
            by_date.setdefault(pick_date, []).append(entry)
    if still_pending:
        log(f"NOTICE {still_pending} uncommitted pick(s) still pending; recorded once they settle")

    cutoff = first_mirrored_seal()
    windows = verify.load_outages()

    for pick_date in sorted(by_date):
        day = load_day(pick_date)
        existing = {pick["pick_rank"]: pick for pick in day["picks"]}
        touched: list[str] = []

        for entry in sorted(by_date[pick_date], key=lambda item: item["pick_rank"]):
            rank = entry["pick_rank"]
            who = f"{pick_date} rank {rank}"
            prior = existing.get(rank)

            if prior is None:
                # Never mirrored while it was sealed. Recorded in full, with no
                # attempt to make it look otherwise: if it carries a hash, that
                # hash reaches this repository after kickoff and verify.py
                # reports it as PRE-GAME. A gap in the mirror is not a proof.
                # The one exception is a game that started before this
                # repository sealed anything (`predates_mirror`): there was no
                # mirror to be late, and it is recorded as pre_commitment.
                #
                # A game that started inside a committed outage window is
                # marked, not excused: the hash is written exactly as it is, the
                # pick stays out of the proven set, and `outage` names the gap
                # so a reader can tell a mirror that was down from a proof that
                # is broken. pre_commitment wins if both somehow apply, because
                # "there was no mirror" is the stronger statement of the two.
                pre = predates_mirror(entry, cutoff)
                window = None if pre else outage_window(entry, windows)
                record = build_opened(
                    entry,
                    context,
                    prior_revisions=[],
                    pre_commitment=pre,
                    outage=window,
                    late_unproven=(
                        not pre
                        and window is None
                        and not is_pre_commitment(entry)
                        and verify.parse_ts(entry["payload"]["kickoff"], "kickoff")
                        <= datetime.now(timezone.utc)
                    ),
                )
                day["picks"].append(record)
                existing[rank] = record
                if record.get("pre_commitment"):
                    touched.append(f"rank {rank} opened (pre-commitment)")
                elif window:
                    touched.append(f"rank {rank} opened, mirror was down ({window})")
                elif record.get("late_unproven"):
                    touched.append(f"rank {rank} opened after kickoff, no public pre-game proof")
                else:
                    touched.append(f"rank {rank} opened, never sealed here")
                continue

            if prior.get("state") == "sealed":
                # A pick sealed here opens with that same hash or not at all.
                # Recording it as pre_commitment instead would drop a committed
                # pick out of the proven set with nothing failing, which is the
                # quiet version of suppressing a loss.
                require(
                    not is_pre_commitment(entry)
                    and prior["commitment_hash"] == entry.get("commitment_hash"),
                    f"{who}: this repository sealed {prior['commitment_hash']} but the "
                    f"endpoint now serves it as {entry.get('state')} with commitment_hash "
                    f"{entry.get('commitment_hash')}. A commitment is never rewritten or "
                    f"withdrawn. Nothing was written.",
                )
                require(
                    prior.get("kickoff") == entry["payload"]["kickoff"],
                    f"{who}: sealed against kickoff {prior.get('kickoff')} but the "
                    f"opened payload says {entry['payload']['kickoff']}. The pick that "
                    f"was committed to is not the pick being opened.",
                )
                record = build_opened(entry, context, prior_revisions=[], sealed=prior)
                day["picks"][day["picks"].index(prior)] = record
                existing[rank] = record
                touched.append(f"rank {rank} opened")
                continue

            # Already opened. The only thing that may move is the outcome, and
            # it moves by appending. A pre_commitment record carries no hash to
            # compare, including one recorded without the hash the endpoint
            # serves because its game predates the mirror.
            if not prior.get("pre_commitment"):
                require(
                    prior.get("commitment_hash") == entry.get("commitment_hash"),
                    f"{who}: commitment_hash changed after the pick was opened. "
                    f"The commitment is over the pick, never over the outcome. "
                    f"Nothing was written.",
                )
            # The endpoint serves `payload: null` for a settled uncommitted pick
            # whose row lacks a column. Once it serves the payload, the record
            # gains it: a field that was absent is added, never rewritten, and
            # a pre_commitment record has no hash for it to disagree with.
            if (
                prior.get("pre_commitment")
                and "payload" not in prior
                and isinstance(entry.get("payload"), dict)
            ):
                prior["payload"] = entry["payload"]
                touched.append(f"rank {rank} gained its payload")
            if prior.get("outcome") == entry["outcome"] and prior.get("resolved_at") == entry.get("resolved_at"):
                continue
            prior.setdefault("revisions", []).append(revision(entry, context))
            prior["outcome"] = entry["outcome"]
            if entry.get("resolved_at") is None:
                prior.pop("resolved_at", None)
            else:
                prior["resolved_at"] = entry["resolved_at"]
            touched.append(f"rank {rank} corrected to {entry['outcome']}")

        if touched:
            write_day(day)
            changes.append(f"{pick_date}: " + ", ".join(touched))

    # An entry that disappears from the endpoint is kept, and said out loud. If
    # it never opens, verify.py's GAPS check reports it 72 hours after kickoff,
    # which is the shape a suppressed loss would take.
    served = {(entry["pick_date"], entry["pick_rank"]) for entry in entries}
    for _, day in read_all_days():
        for pick in day.get("picks", []):
            if (day["pick_date"], pick["pick_rank"]) not in served:
                log(
                    f"NOTICE {day['pick_date']} rank {pick['pick_rank']} is committed here "
                    f"but the endpoint no longer serves it. Kept: this ledger only appends."
                )
    return changes


def build_opened(
    entry: dict,
    context: dict,
    prior_revisions: list,
    sealed: dict | None = None,
    pre_commitment: bool = False,
    outage: str | None = None,
    late_unproven: bool = False,
) -> dict:
    record = ordered(entry, OPENED_FIELDS)
    # Every settled pick is an opened entry here, whatever the endpoint called
    # it. `pre_commitment` is what says whether it carries a proof.
    record["state"] = "opened"
    if pre_commitment or is_pre_commitment(entry):
        record["pre_commitment"] = True
        for field in ("commitment_hash", "commitment_nonce", "commitment_algo", "sealed_at"):
            record.pop(field, None)
    elif outage:
        # A pick with a hash, written late because the mirror could not reach
        # the ledger before its game. The hash stays, exactly as the backend
        # produced it. The marker says which committed outage that gap is, and
        # it is set only from `outages/`, never from anything the endpoint sent.
        record["outage"] = outage
    elif late_unproven:
        record["late_unproven"] = True
    if sealed is not None:
        # The sealed entry's own values win for anything written before the
        # game. They are what this repository committed to.
        for field in ("commitment_hash", "commitment_algo", "sealed_at", "kickoff", "permalink"):
            if field in sealed:
                record[field] = sealed[field]
    payload_kickoff = (entry.get("payload") or {}).get("kickoff")
    if payload_kickoff is not None:
        record.setdefault("kickoff", payload_kickoff)
    record.setdefault(
        "permalink", f"{PERMALINK_BASE}/{entry['pick_date']}/{entry['pick_rank']}"
    )
    record["revisions"] = list(prior_revisions) + [revision(entry, context)]
    return {field: record[field] for field in RECORD_FIELDS if field in record}


# --------------------------------------------------------------------------
# regenerate
# --------------------------------------------------------------------------


def tally() -> dict:
    """Recompute the record from ledger/, using verify.py's arithmetic."""
    opened = sealed = pre_commitment = outage = late_unproven = 0
    wins = losses = voids = 0
    profit = Decimal(0)
    staked = Decimal(0)
    proven_wins = proven_losses = 0
    proven_profit = Decimal(0)
    proven_staked = Decimal(0)
    last_date = None
    flat: list[dict] = []

    for _, day in read_all_days():
        pick_date = day["pick_date"]
        for pick in day.get("picks", []):
            flat.append({"pick_date": pick_date, **pick})
            if pick.get("state") == "sealed":
                sealed += 1
                continue
            opened += 1
            last_date = pick_date if last_date is None else max(last_date, pick_date)
            if pick.get("pre_commitment"):
                pre_commitment += 1
            elif pick.get("outage"):
                outage += 1
            elif pick.get("late_unproven"):
                late_unproven += 1
            proven = not any(
                pick.get(field) for field in ("pre_commitment", "outage", "late_unproven")
            )
            outcome = pick.get("outcome")
            if outcome == "win":
                wins += 1
            elif outcome == "loss":
                losses += 1
            elif outcome == "void":
                voids += 1
            price = Decimal(str(pick.get("payload", {}).get("backed_price", "0")))
            value = verify.stake_return(outcome, price) if price > 0 else None
            if value is not None and outcome in ("win", "loss"):
                profit += value - verify.STAKE_USD
                staked += verify.STAKE_USD
                if proven:
                    proven_profit += value - verify.STAKE_USD
                    proven_staked += verify.STAKE_USD
                    proven_wins += outcome == "win"
                    proven_losses += outcome == "loss"

    decided = wins + losses
    return {
        "opened": opened,
        "sealed": sealed,
        "pre_commitment": pre_commitment,
        # Picks whose game started inside a committed mirror outage. They carry
        # a hash and are NOT pre_commitment, and they are not proven either, so
        # they come out of `proven` the same way. `verify.py` prints each one.
        "outage": outage,
        "late_unproven": late_unproven,
        "proven": opened - pre_commitment - outage - late_unproven,
        "proven_record": {
            "wins": proven_wins,
            "losses": proven_losses,
            "decided": proven_wins + proven_losses,
            "hit_rate": (
                f"{proven_wins / (proven_wins + proven_losses) * 100:.1f}"
                if proven_wins + proven_losses else None
            ),
            "profit_usd": f"{proven_profit:.2f}" if proven_staked else None,
            "staked": f"{proven_staked:.0f}" if proven_staked else None,
            "roi": f"{proven_profit / proven_staked * 100:.1f}" if proven_staked else None,
        },
        "wins": wins,
        "losses": losses,
        "voids": voids,
        "decided": decided,
        "hit_rate": f"{wins / decided * 100:.1f}" if decided else None,
        # The stake every money figure below is computed at. Stated in the
        # record so a reader of index.json alone can tell which basis it is on:
        # $100 until 2026-09-22, $1,000 since (0xinsider/0xinsider#16389).
        "stake_usd": f"{verify.STAKE_USD:.0f}",
        "profit_usd": f"{profit:.2f}" if staked else None,
        "staked": f"{staked:.0f}" if staked else None,
        "roi": f"{profit / staked * 100:.1f}" if staked else None,
        "through": last_date,
        "picks": flat,
    }


def regenerate() -> list[str]:
    """Rewrite index.json and the README record span from ledger/.

    Deterministic: same ledger, same bytes, no timestamp anywhere. The generation
    time is the commit date, which is a fact git already records and nobody has
    to take our word for. `verify.yml` re-runs this and fails on any diff, so the
    published record cannot drift from the data under it.
    """
    stats = tally()
    picks = stats.pop("picks")
    changes: list[str] = []

    index = {
        "commitment_algo": verify.COMMITMENT_ALGO,
        "verify": "https://github.com/0xinsider/picks/blob/main/VERIFY.md",
        "record": stats,
        "picks": picks,
    }
    rendered = json.dumps(index, indent=2, ensure_ascii=False) + "\n"
    if not INDEX_PATH.exists() or INDEX_PATH.read_text() != rendered:
        INDEX_PATH.write_text(rendered)
        changes.append("index.json")

    chart = render_chart(stats, picks)
    if not CHART_PATH.exists() or CHART_PATH.read_text() != chart:
        CHART_PATH.write_text(chart)
        changes.append("record.svg")

    readme = README_PATH.read_text()
    body = replace_span(readme, RECORD_BEGIN, RECORD_END, render_record(stats))
    body = replace_span(body, CHART_BEGIN, CHART_END, render_chart_embed(stats))
    if body != readme:
        README_PATH.write_text(body)
        changes.append("README.md")
    return changes


def replace_span(text: str, begin: str, end: str, body: str) -> str:
    start = text.find(begin)
    stop = text.find(end)
    require(start != -1 and stop > start, f"README.md is missing the {begin} / {end} fences")
    return text[: start + len(begin)] + body + text[stop:]


def render_record(stats: dict) -> str:
    if stats["opened"] == 0 and stats["sealed"] == 0:
        return "\nNothing is mirrored yet. This table fills in with the first sealed pick.\n\n"

    rows = [
        ("Decided picks", str(stats["decided"])),
        ("Record", f"{stats['wins']}W {stats['losses']}L {stats['voids']}V"),
        ("Hit rate", f"{stats['hit_rate']}%" if stats["hit_rate"] else "not yet"),
        (
            f"Profit at ${verify.STAKE_USD:,.0f} per pick, before fees",
            # Signed on purpose. An unsigned P&L reads as a gain by default.
            f"{Decimal(stats['profit_usd']):+,.2f} USD on {Decimal(stats['staked']):,.0f} staked"
            if stats["profit_usd"] is not None
            else "not yet",
        ),
        ("ROI before fees", f"{Decimal(stats['roi']):+.1f}%" if stats["roi"] is not None else "not yet"),
        ("Sealed, not yet settled", str(stats["sealed"])),
        ("Git-dated before kickoff", str(stats["proven"])),
        ("No pre-game proof (pre-commitment)", str(stats["pre_commitment"])),
    ]
    # Only once it has happened. A row that reads 0 forever teaches a reader to
    # skip it, which is the opposite of what it is for.
    if stats["outage"]:
        rows.append(("No pre-game proof (mirror outage)", str(stats["outage"])))
    if stats["late_unproven"]:
        rows.append(("No pre-game proof (late public hash)", str(stats["late_unproven"])))
    proof = stats["proven_record"]
    rows.append(("Git-dated cohort record", f"{proof['wins']}W {proof['losses']}L"))
    rows.append(("Git-dated cohort ROI before fees", f"{Decimal(proof['roi']):+.1f}%" if proof["roi"] is not None else "not yet"))
    lines = ["", f"Record through {stats['through'] or 'no settled pick yet'}.", "", "| | |", "| --- | --- |"]
    lines += [f"| {label} | {value} |" for label, value in rows]
    lines += [
        "",
        "Recomputed from `ledger/` by `.github/scripts/mirror.py`, not typed in.",
        "Profit and ROI count a flat $1,000 stake at the frozen price on each decided pick, before fees.",
        "They do not establish fills, actual wagers, or subscriber profit.",
        "`python3 verify.py` checks the same data and public git history.",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# chart
# --------------------------------------------------------------------------
#
# record.svg is the first thing README.md shows: the cumulative return of the
# flat stake (verify.STAKE_USD) on every decided pick, in the order the picks
# were made. It is generated from ledger/ by the same regenerate pass that
# writes index.json and the README table, so verify.yml's drift check covers
# it too: a chart that disagrees with the ledger fails the repository the same
# way a wrong hit rate would.
#
# Deterministic on purpose. No timestamp, no random id, fixed-precision
# coordinates. Same ledger, same bytes.
#
# Palette is the site's (DESIGN.md in 0xinsider/0xinsider): near-black surface,
# profit green and loss red for the line, white and #8f8f8f ink for text. The
# brand neon never encodes P&L, so it is not on this chart.

CHART_W = 1200
CHART_H = 480
CHART_PAD_L = 92
CHART_PAD_R = 220
CHART_PAD_T = 112
CHART_PAD_B = 60
CHART_FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
SURFACE = "#0b0b0b"
INK = "#ffffff"
INK_MUTED = "#8f8f8f"
PROFIT = "#42d68c"
LOSS = "#ff6467"
HAIRLINE = "0.06"
ZERO_LINE = "0.22"
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def long_date(iso: str) -> str:
    year, month, day = (int(part) for part in iso.split("-"))
    return f"{MONTHS[month - 1]} {day}, {year}"


def cumulative_series(picks: list[dict]) -> list[tuple[float, Decimal, bool]]:
    """One point per decided pick with a usable price: (x, running profit, proven).

    x is the pick's date as an ordinal day plus the pick's share of that day,
    so a day with six picks reads as six steps across the day rather than a
    vertical spike. The money arithmetic is verify.stake_return at
    verify.STAKE_USD, the same function the record table and the RECORD check
    use.
    """
    decided = []
    for pick in sorted(picks, key=lambda item: (item["pick_date"], item["pick_rank"])):
        if pick.get("state") != "opened" or pick.get("outcome") not in ("win", "loss"):
            continue
        price = Decimal(str(pick.get("payload", {}).get("backed_price", "0")))
        value = verify.stake_return(pick["outcome"], price) if price > 0 else None
        if value is None:
            continue
        decided.append((pick["pick_date"], value - verify.STAKE_USD, not any(
            pick.get(field) for field in ("pre_commitment", "outage", "late_unproven")
        )))

    per_day: dict[str, int] = {}
    for pick_date, _, _ in decided:
        per_day[pick_date] = per_day.get(pick_date, 0) + 1

    points = []
    running = Decimal(0)
    seen: dict[str, int] = {}
    for pick_date, delta, proven in decided:
        running += delta
        index = seen.get(pick_date, 0)
        seen[pick_date] = index + 1
        ordinal = datetime.strptime(pick_date, "%Y-%m-%d").toordinal()
        points.append((ordinal + (index + 0.5) / per_day[pick_date], running, proven))
    return points


def nice_step(span: float, target_ticks: int = 5) -> int:
    raw = span / target_ticks
    for step in (50, 100, 200, 250, 500, 1000, 2000, 2500, 5000, 10000, 20000, 25000, 50000):
        if step >= raw:
            return step
    return 100000


def month_starts(first_ordinal: int, last_ordinal: int) -> list[tuple[int, str]]:
    ticks = []
    cursor = datetime.fromordinal(first_ordinal).date().replace(day=1)
    while cursor.toordinal() <= last_ordinal:
        if cursor.toordinal() >= first_ordinal:
            ticks.append((cursor.toordinal(), MONTHS[cursor.month - 1]))
        cursor = (cursor.replace(day=28) + timedelta(days=4)).replace(day=1)
    return ticks


def render_chart(stats: dict, picks: list[dict]) -> str:
    """The cumulative-return line, as a self-contained SVG."""
    head = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {CHART_W} {CHART_H}" '
        f'width="{CHART_W}" height="{CHART_H}" role="img" aria-labelledby="title desc" '
        f'font-family="{CHART_FONT}">\n'
    )
    out = [head]
    points = cumulative_series(picks)
    title = f"Profit at ${verify.STAKE_USD:,.0f} per pick, before fees"
    if not points:
        out.append(f"<title id=\"title\">{esc(title)}</title>\n")
        out.append('<desc id="desc">No settled pick with a price yet.</desc>\n')
        out.append(f'<rect width="{CHART_W}" height="{CHART_H}" rx="6" fill="{SURFACE}"/>\n')
        out.append(
            f'<text x="32" y="64" fill="{INK}" font-size="28" font-weight="600">{esc(title)}</text>\n'
        )
        out.append(
            f'<text x="32" y="100" fill="{INK_MUTED}" font-size="18">No settled pick yet. '
            f"This chart draws itself from ledger/ when the first one opens.</text>\n"
        )
        out.append("</svg>\n")
        return "".join(out)

    first_date = min(pick["pick_date"] for pick in picks if pick.get("state") == "opened")
    subtitle = (
        f"{stats['decided']} decided picks since {long_date(first_date)}. "
        f"{stats['wins']}W {stats['losses']}L, {stats['hit_rate']}% hit rate, "
        f"{Decimal(stats['roi']):+.1f}% ROI on {Decimal(stats['staked']):,.0f} USD staked."
    )
    final = points[-1][1]
    desc = (
        f"Cumulative profit before fees at {verify.STAKE_USD:,.0f} USD per pick from {long_date(first_date)} to "
        f"{long_date(stats['through'])}: {final:+,.2f} USD. {subtitle}"
    )
    out.append(f'<title id="title">{esc(title)}</title>\n')
    out.append(f'<desc id="desc">{esc(desc)}</desc>\n')
    out.append(f'<rect width="{CHART_W}" height="{CHART_H}" rx="6" fill="{SURFACE}"/>\n')
    out.append(f'<text x="32" y="52" fill="{INK}" font-size="28" font-weight="600">{esc(title)}</text>\n')
    out.append(f'<text x="32" y="84" fill="{INK_MUTED}" font-size="17">{esc(subtitle)}</text>\n')

    # Scales. y always includes zero, because the sign is the story.
    x0 = CHART_PAD_L
    x1 = CHART_W - CHART_PAD_R
    y0 = CHART_PAD_T
    y1 = CHART_H - CHART_PAD_B
    first_x = int(points[0][0])
    last_x = int(points[-1][0]) + 1
    lo = min(Decimal(0), min(value for _, value, _ in points))
    hi = max(Decimal(0), max(value for _, value, _ in points))
    # A span of zero (every decided pick returned exactly its stake) falls back
    # to one stake's worth of axis so the chart still has a scale.
    step = nice_step(float(hi - lo) or float(verify.STAKE_USD))
    y_min = (int(lo) // step) * step if lo < 0 else 0
    y_max = ((int(hi) // step) + 1) * step if hi > 0 else 0
    if y_max == y_min:
        y_max = y_min + step

    def sx(x: float) -> float:
        return x0 + (x - first_x) / (last_x - first_x) * (x1 - x0)

    def sy(value: float) -> float:
        return y1 - (value - y_min) / (y_max - y_min) * (y1 - y0)

    # Gridlines and y ticks. Hairlines, recessive, one per nice step.
    tick = y_min
    while tick <= y_max:
        y = sy(tick)
        opacity = ZERO_LINE if tick == 0 else HAIRLINE
        out.append(
            f'<line x1="{x0}" y1="{y:.1f}" x2="{x1}" y2="{y:.1f}" stroke="{INK}" '
            f'stroke-opacity="{opacity}" stroke-width="1"/>\n'
        )
        out.append(
            f'<text x="{x0 - 12}" y="{y + 5:.1f}" fill="{INK_MUTED}" font-size="15" '
            f'text-anchor="end">{tick:,}</text>\n'
        )
        tick += step

    # x ticks at month starts.
    for ordinal, label in month_starts(first_x, last_x):
        x = sx(ordinal)
        out.append(
            f'<line x1="{x:.1f}" y1="{y1}" x2="{x:.1f}" y2="{y1 + 6}" stroke="{INK}" '
            f'stroke-opacity="{ZERO_LINE}" stroke-width="1"/>\n'
        )
        out.append(
            f'<text x="{x:.1f}" y="{y1 + 26}" fill="{INK_MUTED}" font-size="15" text-anchor="middle">{label}</text>\n'
        )

    # The line, drawn twice under two clips so the part above zero is profit
    # green and the part below is loss red. The wash under it is the same hue
    # at 10%.
    coords = [(sx(x), sy(float(value))) for x, value, _ in points]
    start = (sx(first_x), sy(0.0))
    path = " ".join(f"{x:.1f},{y:.1f}" for x, y in [start, *coords])
    zero_y = sy(0.0)
    area = f"M{start[0]:.1f},{zero_y:.1f} L" + " L".join(f"{x:.1f},{y:.1f}" for x, y in coords) + f" L{coords[-1][0]:.1f},{zero_y:.1f} Z"
    out.append("<defs>\n")
    out.append(f'<clipPath id="above"><rect x="0" y="0" width="{CHART_W}" height="{zero_y:.1f}"/></clipPath>\n')
    out.append(f'<clipPath id="below"><rect x="0" y="{zero_y:.1f}" width="{CHART_W}" height="{CHART_H - zero_y:.1f}"/></clipPath>\n')
    out.append("</defs>\n")
    for clip, color in (("above", PROFIT), ("below", LOSS)):
        out.append(f'<path d="{area}" fill="{color}" fill-opacity="0.1" clip-path="url(#{clip})"/>\n')
        out.append(
            f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="2" '
            f'stroke-linejoin="round" stroke-linecap="round" clip-path="url(#{clip})"/>\n'
        )

    # Where sealing begins: the first pick whose hash was on a public ledger
    # before its game. Drawn only once such a pick has settled.
    proven = [x for x, _, is_proven in points if is_proven]
    if proven:
        x = sx(proven[0])
        out.append(
            f'<line x1="{x:.1f}" y1="{y0}" x2="{x:.1f}" y2="{y1}" stroke="{INK}" '
            f'stroke-opacity="{ZERO_LINE}" stroke-width="1" stroke-dasharray="2 4"/>\n'
        )
        out.append(
            f'<text x="{x - 8:.1f}" y="{y0 + 16}" fill="{INK_MUTED}" font-size="14" text-anchor="end">'
            f"sealed before kickoff from here</text>\n"
        )

    # End marker: >= 8px dot with a 2px surface ring, and the one number the
    # chart is read for beside it, in ink rather than in the series color.
    end_x, end_y = coords[-1]
    color = PROFIT if final >= 0 else LOSS
    out.append(f'<circle cx="{end_x:.1f}" cy="{end_y:.1f}" r="6" fill="{color}" stroke="{SURFACE}" stroke-width="2"/>\n')
    out.append(
        f'<text x="{end_x + 14:.1f}" y="{end_y + 7:.1f}" fill="{INK}" font-size="20" font-weight="600">'
        f"{final:+,.2f} USD</text>\n"
    )
    out.append(
        f'<text x="{CHART_W - 32}" y="{CHART_H - 20}" fill="{INK_MUTED}" font-size="14" text-anchor="end">'
        f"0xinsider.com/pick-of-the-day</text>\n"
    )
    out.append("</svg>\n")
    return "".join(out)


def render_chart_embed(stats: dict) -> str:
    """The README's first element: the chart, linked to the record, with the
    numbers in its alt text so a screen reader gets the same figures."""
    if stats["opened"] == 0:
        alt = "Cumulative return chart. No settled pick yet."
    else:
        alt = (
            f"Cumulative profit before fees at {verify.STAKE_USD:,.0f} USD per pick through {long_date(stats['through'])}: "
            f"{Decimal(stats['profit_usd']):+,.2f} USD on {Decimal(stats['staked']):,.0f} USD staked across "
            f"{stats['decided']} decided picks, {stats['wins']}W {stats['losses']}L, "
            f"{stats['hit_rate']}% hit rate, {Decimal(stats['roi']):+.1f}% ROI."
        )
    return (
        '\n<a href="https://0xinsider.com/pick-of-the-day">'
        f'<img src="record.svg" alt="{esc(alt)}" width="100%"></a>\n'
    )


# --------------------------------------------------------------------------
# git
# --------------------------------------------------------------------------


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args], capture_output=True, text=True, check=False
    )
    if check and result.returncode != 0:
        raise MirrorError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def head() -> str:
    return git("rev-parse", "HEAD").stdout.strip()


def run_url() -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not repo or not run_id:
        return "local"
    return f"{server}/{repo}/actions/runs/{run_id}"


def commit_and_push(mode: str, changes: list[str]) -> bool:
    git("add", "-A", "ledger", "index.json", "README.md", "record.svg")
    if not git("diff", "--cached", "--quiet", check=False).returncode:
        log("nothing to commit")
        return True

    summary = "; ".join(changes)[:72] or f"{mode} update"
    message = (
        f"{mode}: {summary}\n\n"
        f"Mirrored from the 0xinsider commitment ledger endpoint. Hashes are "
        f"copied verbatim; this workflow computes none.\n"
        f"run: {run_url()}\n"
    )
    git(
        "-c",
        f"user.name={BOT_NAME}",
        "-c",
        f"user.email={BOT_EMAIL}",
        "commit",
        "-m",
        message,
    )
    pushed = git("push", "origin", "HEAD:main", check=False)
    if pushed.returncode == 0:
        log(f"pushed {head()[:10]}")
        return True
    log(f"push rejected: {pushed.stderr.strip()}")
    return False


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def run_once(mode: str, entries: list[dict]) -> list[str]:
    context = {"parent_commit": head(), "run": run_url()}
    if mode == "seal":
        changes = apply_seal(entries)
    else:
        changes = apply_reveal(entries, context)
    reconcile_identities(entries, mode)
    # Both modes regenerate, so the record on display never lags the ledger by
    # more than one run: a seal changes the "sealed, not yet settled" count, and
    # a push that lands between a seal and the next reveal would otherwise fail
    # verify.yml's drift check on a README that nobody edited.
    return changes + regenerate()


def reconcile_identities(entries: list[dict], mode: str) -> None:
    """Refuse a successful source read that this mirror represented incompletely.

    The seal lane only owns future sealed entries. Reveal owns every published
    pick except an uncommitted one still pending, whose side cannot be exposed.
    An offline verifier cannot discover identities absent from both source and
    mirror; this comparison is made while the source response is in hand.
    """
    now = datetime.now(timezone.utc)
    source: set[tuple[str, int]] = set()
    all_source: set[tuple[str, int]] = set()
    for entry in entries:
        pick_date, rank, state = validate(entry)
        identity = (pick_date, rank)
        require(identity not in all_source, f"source repeats {pick_date} rank {rank}")
        all_source.add(identity)
        if mode == "seal":
            if state == "sealed" and verify.parse_ts(entry["kickoff"], "kickoff") > now:
                source.add(identity)
        elif not (state == "uncommitted" and entry.get("outcome") == "pending"):
            source.add(identity)

    mirrored: set[tuple[str, int]] = set()
    for _, day in read_all_days():
        for pick in day.get("picks", []):
            identity = (day["pick_date"], pick["pick_rank"])
            require(identity not in mirrored, f"mirror repeats {identity[0]} rank {identity[1]}")
            mirrored.add(identity)

    missing = source - mirrored
    extra = mirrored - all_source if mode == "reveal" else set()
    require(not missing, f"{mode} omitted source identities: {sorted(missing)}")
    require(not extra, f"mirror has identities absent from source: {sorted(extra)}")
    log(f"reconciled {len(source)} eligible source identities against ledger/")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--mode", required=True, choices=("seal", "reveal", "regenerate"))
    parser.add_argument("--url", default=os.environ.get("OXINSIDER_LEDGER_URL", DEFAULT_URL))
    parser.add_argument(
        "--no-push",
        action="store_true",
        help="apply the changes to the working tree and stop, for a dispatch dry run",
    )
    args = parser.parse_args()

    LEDGER_DIR.mkdir(parents=True, exist_ok=True)

    if args.mode == "regenerate":
        changes = regenerate()
        log("regenerated: " + (", ".join(changes) if changes else "no change"))
        if args.no_push:
            return 0
        return 0 if commit_and_push("chore", changes or ["regenerate"]) else 1

    # No credential guard, and nothing to restore if one goes missing: the
    # endpoint is public (0xinsider/0xinsider#16459), so this run depends on
    # nothing that a key rotation elsewhere can revoke. The guard this replaces
    # existed to tell "the key was never stored" apart from "the key stopped
    # working", and on 2026-09-22 it did its job -- it failed every run, loudly,
    # for three hours -- while picks reached kickoff unmirrored anyway, because
    # no amount of loudness recovers a proof that missed its game. The failure
    # modes that remain all fail the run below: an error response, an unexpected
    # shape, or a sealed pick carrying a nonce.
    try:
        entries = fetch_entries(args.url)
    except MirrorError as exc:
        # The window goes in NOW, in its own commit, while the failure is the
        # only thing that has happened. A record written later cannot be told
        # apart from an excuse, and `verify.py` refuses to tell them apart.
        if args.no_push:
            log("dry run: not recording an outage window")
        else:
            cause = " ".join(str(exc).split())[:400]
            try:
                record_outage(cause)
            except MirrorError as inner:
                log(f"FAILED  could not record the outage window: {inner}")
        raise
    read_at = datetime.now(timezone.utc)

    # The ledger answered, so any window that was open is over. Closing it is
    # pushed before a single hash is appended, which is what keeps a window's
    # commit ahead of the backlog it explains.
    if not args.no_push:
        close_outage(read_at)

    # Cursor-free, so a losing race costs one refetch of the local tree and a
    # replay, never a reconciliation. The endpoint is read once.
    for attempt in range(1, 4):
        if attempt > 1:
            git("fetch", "origin", "main")
            git("reset", "--hard", "origin/main")
        changes = run_once(args.mode, entries)
        if not changes:
            log("no change")
            return 0
        log("changed: " + "; ".join(changes))
        if args.no_push:
            return 0
        if commit_and_push(args.mode, changes):
            return 0
        log(f"retrying on a fresh main (attempt {attempt} of 3)")
    raise MirrorError("could not push after 3 attempts; the next scheduled run retries")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except MirrorError as exc:
        print(f"FAILED  {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
