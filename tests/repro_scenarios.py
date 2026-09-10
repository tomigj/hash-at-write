#!/usr/bin/env python3
"""
repro_scenarios -- fixture builders for the reproduced attacks and failures.

Each builder writes a (log, chain) pair to a temporary directory and returns the
paths, so the verifier can be run against a known-bad shape without needing a
live agent, a live ledger or a real outage. Run this file directly to build every
scenario and report what the verifier says about each.

These are regression fixtures, not the verifier's own unit tests: they assert
nothing themselves. They exist so that a change to detection logic can be checked
against every failure mode already found, rather than only the one being worked
on. Expected verdicts are recorded next to each builder.

Written by the Claude session on `tg` (primary) during review of commits
cff0e5e..0aed299, and verified there against 0aed299 (6/6).

Two changes were made when committing it on `daddy` (ledger):

  - `legitimate_outage_recovery` originally expected BACKDATED, which is what
    the code did at 0aed299 rather than what it should do; the author flagged it
    as a fixture deliberately encoding a bug so the fix would show as a failing
    test. The bug was fixed in 93bc9f7, so the expectation is now
    OUTAGE RECOVERY. The behaviour it documents did change, and this is the
    record of it.
  - `write_pair` set `prev_chain` to the new head rather than the previous one.
    The verifier recomputes from GENESIS and never reads that field, so the
    fixtures were valid either way, but the author flagged it as a trap for
    anyone who later makes the verifier check it. Corrected here.
"""

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.canonical import (GENESIS, HEARTBEAT_EVENT, compute_digest,  # noqa: E402
                              next_chain_hash)

VERIFIER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "ledger", "verifier.py")


def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def write_pair(outdir, name, records, received):
    """Write a log and a correctly-chained ledger for `records`.

    `received` maps seq -> ledger receipt time, so a scenario can separate when a
    record claims to have been written from when its digest actually arrived.
    That separation is the whole point of several of these fixtures.
    """
    log_path = os.path.join(outdir, f"{name}.log")
    chain_path = os.path.join(outdir, f"{name}.jsonl")
    head = GENESIS
    with open(log_path, "w", encoding="utf-8") as lf, \
         open(chain_path, "w", encoding="utf-8") as cf:
        for rec in records:
            digest = compute_digest(rec)
            lf.write(json.dumps({"record": rec, "digest": digest},
                                sort_keys=True, separators=(",", ":")) + "\n")
            prev_chain = head
            head = next_chain_hash(digest, head)
            cf.write(json.dumps({"seq": rec["seq"], "digest": digest,
                                 "prev_chain": prev_chain, "chain_hash": head,
                                 "received": received[rec["seq"]]},
                                sort_keys=True, separators=(",", ":")) + "\n")
    return log_path, chain_path


# --- scenarios ------------------------------------------------------------
# Each returns (log_path, chain_path, verifier_args, expected_alert_kinds).

def agent_dead_now(outdir):
    """Agent stopped an hour ago and never came back. Expect SILENCE.

    The gap is open-ended: it is between the last chain entry and now, not
    between two entries. A verifier that only walks consecutive pairs reports
    CLEAN here, which is how this was originally missed.
    """
    start = datetime.now(timezone.utc) - timedelta(hours=1)
    recs, recv = [], {}
    for seq in range(1, 11):
        t = start + timedelta(seconds=5 * (seq - 1))
        recs.append({"seq": seq, "ts": fmt(t), "event": HEARTBEAT_EVENT})
        recv[seq] = fmt(t)
    log, chain = write_pair(outdir, "agent_dead_now", recs, recv)
    return log, chain, ["--max-silence", "60"], ["SILENCE"]


def interior_silence_gap(outdir):
    """Agent stopped for 600s mid-run, then resumed. Expect SILENCE."""
    start = datetime.now(timezone.utc) - timedelta(seconds=60)
    recs, recv = [], {}
    t = start
    for seq in range(1, 11):
        if seq == 6:
            t += timedelta(seconds=600)
        recs.append({"seq": seq, "ts": fmt(t), "event": HEARTBEAT_EVENT})
        recv[seq] = fmt(t)
        t += timedelta(seconds=5)
    log, chain = write_pair(outdir, "interior_silence_gap", recs, recv)
    return log, chain, ["--max-silence", "60"], ["SILENCE"]


def backdated_forgery(outdir):
    """A forged record claiming to be six years old. Expect BACKDATED.

    The forgery is otherwise perfect: correct digest, in-order sequence, intact
    chain. Only the ledger's receipt time contradicts it -- and the three prompt
    receipts before it establish that the ledger was reachable and current at
    the moment the record claims to have been written, which is what makes this
    backdating rather than an outage.
    """
    now = datetime.now(timezone.utc)
    recs, recv = [], {}
    for seq in (1, 2, 3):
        recs.append({"seq": seq, "ts": fmt(now - timedelta(seconds=10 - seq)),
                     "event": f"real event {seq}"})
        recv[seq] = fmt(now - timedelta(seconds=10 - seq))
    recs.append({"seq": 4, "ts": "2020-01-01T00:00:00.000Z",
                 "event": "nothing suspicious happened"})
    recv[4] = fmt(now)
    log, chain = write_pair(outdir, "backdated_forgery", recs, recv)
    return log, chain, [], ["BACKDATED"]


def future_dated_record(outdir):
    """A record claiming to be written after its digest arrived. Expect FUTURE DATED.

    Never legitimate beyond clock drift, so the threshold on this direction can
    be much tighter than on backdating.
    """
    now = datetime.now(timezone.utc)
    recs = [{"seq": 1, "ts": fmt(now + timedelta(hours=2)),
             "event": "claims to be from the future"}]
    log, chain = write_pair(outdir, "future_dated_record", recs, {1: fmt(now)})
    return log, chain, [], ["FUTURE DATED"]


def legitimate_outage_recovery(outdir):
    """FALSE POSITIVE FIXTURE -- entirely legitimate traffic.

    Five digests are received promptly. The ledger then goes unreachable for
    about eight minutes; the agent keeps working and spools. When the ledger
    returns, the drainer pushes every held digest at once. Nothing here is an
    attack: every record is genuine and every digest is correct.

    Expect OUTAGE RECOVERY, not BACKDATED. The five prompt receipts before the
    outage are what make the distinction possible: the recovered records all
    postdate the ledger's last prompt receipt, which is consistent with a spool
    delivered late and inconsistent with backdating.
    """
    now = datetime.now(timezone.utc)
    outage_start = now - timedelta(seconds=500)
    recs, recv = [], {}
    for seq in range(1, 11):
        if seq <= 5:
            t = outage_start - timedelta(seconds=(6 - seq) * 10)
            r = t
        else:
            t = outage_start + timedelta(seconds=(seq - 5) * 10)
            r = now - timedelta(seconds=5)
        recs.append({"seq": seq, "ts": fmt(t), "event": f"real event {seq}"})
        recv[seq] = fmt(r)
    log, chain = write_pair(outdir, "legitimate_outage_recovery", recs, recv)
    return log, chain, [], ["OUTAGE RECOVERY"]


def unwitnessed_tail(outdir):
    """Agent stopped, records appended directly to the log, agent restarted.

    Expect UNWITNESSED on the appended sequences. This is the original one-
    directional-verification finding.
    """
    now = datetime.now(timezone.utc) - timedelta(seconds=30)
    recs, recv = [], {}
    for seq in range(1, 11):
        t = now + timedelta(seconds=seq)
        recs.append({"seq": seq, "ts": fmt(t), "event": f"real event {seq}"})
        recv[seq] = fmt(t)
    log, chain = write_pair(outdir, "unwitnessed_tail", recs, recv)
    # Two records appended to the log with no digest ever reaching the ledger.
    with open(log, "a", encoding="utf-8") as f:
        for seq in (11, 12):
            rec = {"seq": seq, "ts": fmt(now + timedelta(seconds=seq)),
                   "event": "inserted without a witness"}
            f.write(json.dumps({"record": rec, "digest": compute_digest(rec)},
                               sort_keys=True, separators=(",", ":")) + "\n")
    return log, chain, [], ["UNWITNESSED"]


SCENARIOS = [agent_dead_now, interior_silence_gap, backdated_forgery,
             future_dated_record, legitimate_outage_recovery, unwitnessed_tail]


def main():
    outdir = tempfile.mkdtemp(prefix="witnessd-repro-")
    print(f"fixtures in {outdir}\n")
    failures = 0
    for build in SCENARIOS:
        log, chain, extra, expected = build(outdir)
        proc = subprocess.run(
            [sys.executable, VERIFIER, "--chain", chain, "--log-file", log,
             "--verify-log", os.path.join(outdir, "verify.log")] + extra,
            capture_output=True, text=True)
        out = proc.stdout
        missing = [k for k in expected if k not in out]
        status = "OK  " if not missing else "FAIL"
        if missing:
            failures += 1
        print(f"{status} {build.__name__}")
        print(f"     expected: {', '.join(expected)}")
        for line in out.splitlines():
            print(f"     {line}")
        if proc.stderr.strip():
            for line in proc.stderr.strip().splitlines():
                print(f"     [stderr] {line}")
        print()
    print(f"{len(SCENARIOS) - failures}/{len(SCENARIOS)} scenarios produced their expected alert")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
