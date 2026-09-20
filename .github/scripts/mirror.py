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

MODES
-----
  seal        fetch, append commitments not yet committed
  reveal      fetch, open settled commitments, append revisions, regenerate
  regenerate  no network: rebuild index.json and the README record from ledger/
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
from datetime import datetime
from decimal import Decimal
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LEDGER_DIR = REPO_ROOT / "ledger"
INDEX_PATH = REPO_ROOT / "index.json"
README_PATH = REPO_ROOT / "README.md"

# The money arithmetic lives in verify.py and is imported rather than copied.
# Two implementations of the same sum is how a README quietly stops matching the
# ledger it claims to summarize.
sys.path.insert(0, str(REPO_ROOT))
import verify  # noqa: E402

DEFAULT_URL = "https://api.0xinsider.com/api/v1/pick-of-the-day/ledger"
PERMALINK_BASE = "https://0xinsider.com/pick-of-the-day"

RECORD_BEGIN = "<!-- RECORD:BEGIN -->"
RECORD_END = "<!-- RECORD:END -->"

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

OUTCOMES = ("win", "loss", "void")

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


class MirrorError(Exception):
    """The run stops and writes nothing."""


def log(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------


def fetch_entries(url: str, token: str) -> list[dict]:
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
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

    # The endpoint contract (0xinsider/0xinsider#15704) fixes the entry shape but
    # not the container. Accept a bare array or a single list-valued member, and
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


def check_timestamp(entry: dict, field: str, who: str) -> None:
    """For `sealed_at` and `resolved_at`, which are not hashed.

    Stored verbatim and checked only for being a real instant. Their precision
    is the endpoint's business: refusing a microsecond here would stop the mirror
    over a field that no proof depends on.
    """
    value = entry.get(field)
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
    require(state in ("sealed", "opened"), f"{who}: unknown state {state!r}")

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

    require(entry.get("outcome") in OUTCOMES, f"{who}: unknown outcome {entry.get('outcome')!r}")
    check_timestamp(entry, "resolved_at", who)

    payload = entry.get("payload")
    require(isinstance(payload, dict), f"{who}: opened entry has no payload object")
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


def is_pre_commitment(entry: dict) -> bool:
    """A settled pick with no commitment predates the scheme.

    Either the endpoint says so outright, or it serves an opened entry with no
    hash, which can only be a pick published before sealing existed. Marking it
    in the data is the honest move: `verify.py` excludes these from the hash and
    pre-game checks by construction, counts them in the record, and reports them
    separately. Quietly mixing them into the proven set is the failure this flag
    exists to prevent.
    """
    if entry.get("pre_commitment") is True:
        return True
    return entry.get("state") == "opened" and not entry.get("commitment_hash")


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
    for entry in entries:
        pick_date, _, state = validate(entry)
        if state == "sealed":
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
        "resolved_at": entry["resolved_at"],
        "parent_commit": context["parent_commit"],
        "run": context["run"],
    }


def apply_reveal(entries: list[dict], context: dict) -> list[str]:
    changes: list[str] = []
    by_date: dict[str, list[dict]] = {}
    for entry in entries:
        pick_date, _, state = validate(entry)
        if state == "opened":
            by_date.setdefault(pick_date, []).append(entry)

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
                record = build_opened(entry, context, prior_revisions=[])
                day["picks"].append(record)
                existing[rank] = record
                touched.append(
                    f"rank {rank} opened (pre-commitment)"
                    if record.get("pre_commitment")
                    else f"rank {rank} opened, never sealed here"
                )
                continue

            if prior.get("state") == "sealed":
                require(
                    is_pre_commitment(entry)
                    or prior["commitment_hash"] == entry["commitment_hash"],
                    f"{who}: the endpoint serves commitment_hash "
                    f"{entry.get('commitment_hash')} but this repository sealed "
                    f"{prior['commitment_hash']}. A commitment is never rewritten. "
                    f"Nothing was written.",
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
            # it moves by appending.
            require(
                prior.get("commitment_hash") == entry.get("commitment_hash"),
                f"{who}: commitment_hash changed after the pick was opened. "
                f"The commitment is over the pick, never over the outcome. "
                f"Nothing was written.",
            )
            if prior.get("outcome") == entry["outcome"] and prior.get("resolved_at") == entry["resolved_at"]:
                continue
            prior.setdefault("revisions", []).append(revision(entry, context))
            prior["outcome"] = entry["outcome"]
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


def build_opened(entry: dict, context: dict, prior_revisions: list, sealed: dict | None = None) -> dict:
    record = ordered(entry, OPENED_FIELDS)
    if is_pre_commitment(entry):
        record["pre_commitment"] = True
        for field in ("commitment_hash", "commitment_nonce", "commitment_algo", "sealed_at"):
            record.pop(field, None)
    if sealed is not None:
        # The sealed entry's own values win for anything written before the
        # game. They are what this repository committed to.
        for field in ("commitment_hash", "commitment_algo", "sealed_at", "kickoff", "permalink"):
            if field in sealed:
                record[field] = sealed[field]
    record.setdefault("kickoff", entry["payload"]["kickoff"])
    record.setdefault(
        "permalink", f"{PERMALINK_BASE}/{entry['pick_date']}/{entry['pick_rank']}"
    )
    record["revisions"] = list(prior_revisions) + [revision(entry, context)]
    return {field: record[field] for field in OPENED_FIELDS if field in record}


# --------------------------------------------------------------------------
# regenerate
# --------------------------------------------------------------------------


def tally() -> dict:
    """Recompute the record from ledger/, using verify.py's arithmetic."""
    opened = sealed = pre_commitment = 0
    wins = losses = voids = 0
    profit = Decimal(0)
    staked = Decimal(0)
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
            outcome = pick.get("outcome")
            if outcome == "win":
                wins += 1
            elif outcome == "loss":
                losses += 1
            elif outcome == "void":
                voids += 1
            price = Decimal(str(pick.get("payload", {}).get("backed_price", "0")))
            value = verify.return_per_100(outcome, price) if price > 0 else None
            if value is not None and outcome in ("win", "loss"):
                profit += value - Decimal(100)
                staked += Decimal(100)

    decided = wins + losses
    return {
        "opened": opened,
        "sealed": sealed,
        "pre_commitment": pre_commitment,
        "proven": opened - pre_commitment,
        "wins": wins,
        "losses": losses,
        "voids": voids,
        "decided": decided,
        "hit_rate": f"{wins / decided * 100:.1f}" if decided else None,
        "profit_per_100": f"{profit:.2f}" if staked else None,
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

    readme = README_PATH.read_text()
    start = readme.find(RECORD_BEGIN)
    end = readme.find(RECORD_END)
    require(
        start != -1 and end > start,
        f"README.md is missing the {RECORD_BEGIN} / {RECORD_END} fences",
    )
    body = readme[: start + len(RECORD_BEGIN)] + render_record(stats) + readme[end:]
    if body != readme:
        README_PATH.write_text(body)
        changes.append("README.md")
    return changes


def render_record(stats: dict) -> str:
    if stats["opened"] == 0 and stats["sealed"] == 0:
        return "\nNothing is mirrored yet. This table fills in with the first sealed pick.\n\n"

    rows = [
        ("Decided picks", str(stats["decided"])),
        ("Record", f"{stats['wins']}W {stats['losses']}L {stats['voids']}V"),
        ("Hit rate", f"{stats['hit_rate']}%" if stats["hit_rate"] else "not yet"),
        (
            "$100 per pick",
            # Signed on purpose. An unsigned P&L reads as a gain by default.
            f"{Decimal(stats['profit_per_100']):+.2f} USD on {stats['staked']} staked"
            if stats["profit_per_100"] is not None
            else "not yet",
        ),
        ("ROI", f"{Decimal(stats['roi']):+.1f}%" if stats["roi"] is not None else "not yet"),
        ("Sealed, not yet settled", str(stats["sealed"])),
        ("Proven sealed before kickoff", str(stats["proven"])),
        ("No pre-game proof (pre-commitment)", str(stats["pre_commitment"])),
    ]
    lines = ["", f"Record through {stats['through'] or 'no settled pick yet'}.", "", "| | |", "| --- | --- |"]
    lines += [f"| {label} | {value} |" for label, value in rows]
    lines += [
        "",
        "Recomputed from `ledger/` by `.github/scripts/mirror.py`, not typed in.",
        "`python3 verify.py` prints the same numbers from the same data.",
        "",
    ]
    return "\n".join(lines)


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
    git("add", "-A", "ledger", "index.json", "README.md")
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
        "user.name=github-actions[bot]",
        "-c",
        "user.email=41898282+github-actions[bot]@users.noreply.github.com",
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
        return apply_seal(entries)
    changes = apply_reveal(entries, context)
    return changes + regenerate()


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

    # A missing credential means one of two opposite things, and which one it is
    # depends on whether this mirror has ever worked. DO NOT SIMPLIFY THIS BACK
    # TO AN UNCONDITIONAL PASS.
    #
    # Empty ledger: the endpoint has not shipped and the read-only key has not
    # been stored yet. Failing several dozen times a day over a state nobody has
    # reached would teach everyone to ignore a red run, and red here is supposed
    # to mean a broken proof. So it passes, and says so.
    #
    # Non-empty ledger: the mirror demonstrably worked, and the key has since
    # been removed, rotated or expired. Passing green there would let
    # commitments stop being recorded with nothing anywhere saying so, which is
    # a far worse failure than the noise the empty case avoids -- a pick sealed
    # while the key is dead never reaches this repository before its kickoff,
    # and no later run can repair that. So it fails.
    token = os.environ.get("OXINSIDER_API_KEY", "").strip()
    if not token:
        committed = sum(len(day.get("picks", [])) for _, day in read_all_days())
        if committed == 0:
            log(
                "OXINSIDER_API_KEY is not configured and the ledger is empty. "
                "Nothing was fetched and nothing was written. Set the repository "
                "secret once the ledger endpoint is live "
                "(0xinsider/0xinsider#15704)."
            )
            return 0
        raise MirrorError(
            f"OXINSIDER_API_KEY is not configured, but this ledger already holds "
            f"{committed} entry/entries. The mirror worked before and has stopped, "
            f"so commitments are going unrecorded right now. Restore the repository "
            f"secret. A pick sealed while the key is missing cannot be mirrored "
            f"before its kickoff by any later run."
        )
    entries = fetch_entries(args.url, token)

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
