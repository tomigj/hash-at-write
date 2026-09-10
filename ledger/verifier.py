#!/usr/bin/env python3
"""
verifier -- independent verification of the primary's log. Runs on `ledger`.

Pulls the log from the primary over an SSH forced command, then recomputes
everything locally. The primary is never asked what its own digests are or
whether it considers itself intact; under the threat model it may be lying.

Four failure conditions are detected:

  DELETION    a chained digest has no matching record in the log
  TAMPER      a record's recomputed digest does not match the chained one
  CHAIN BREAK the chain does not recompute from genesis
  UNWITNESSED a record exists in the log with no digest in the chain

The fourth is not in the original build spec, and it closes a real hole. The
spec's verification loop iterates the LEDGER and looks up matching log records,
so any record present in the log but absent from the chain is never examined.
Under full root that is the cheapest attack available: stop the agent, append
whatever you like to events.log unwitnessed, restart it. The agent resumes its
sequence from the log's last line, the chain stays internally consistent, and
every original check passes clean. Iterating both directions costs nothing and
removes the blind spot.

Optionally also detects agent silence, using the timestamps the LEDGER recorded
on receipt -- never the timestamps in the log, which the primary controls.

Targets Python 3.12. Standard library only.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.canonical import (GENESIS, HEARTBEAT_EVENT, compute_digest,  # noqa: E402
                              next_chain_hash)


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def parse_ts(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


class Alert:
    def __init__(self, kind, seq, detail):
        self.kind, self.seq, self.detail = kind, seq, detail

    def as_dict(self):
        return {"kind": self.kind, "seq": self.seq, "detail": self.detail}

    def __str__(self):
        return f"{self.kind:<12} seq={self.seq:<8} {self.detail}"


def pull_log(args):
    """Retrieve the primary's log.

    The remote side runs a forced command pinned in authorized_keys, so the
    command sent here is ignored -- 'true' is a placeholder that makes that
    explicit. Note what this restriction does and does not do: it is least
    privilege for the ledger's access INTO the primary. It is not an integrity
    control, because a rooted primary can replace its own authorized_keys and
    serve doctored content. The design survives that: doctored content fails
    against digests that left the primary at write time. The property comes
    from where the digests are, not from this SSH restriction.
    """
    if args.log_file:
        with open(args.log_file, encoding="utf-8") as f:
            return f.read()
    cmd = ["ssh", "-i", args.ssh_key, "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=yes",
           "-o", f"ConnectTimeout={args.ssh_timeout}",
           f"{args.ssh_user}@{args.primary}", "true"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.ssh_timeout + 10)
    if proc.returncode != 0:
        raise RuntimeError(f"log pull failed (rc={proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def load_chain(path):
    entries = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def parse_log(text):
    """Index the pulled log by sequence number.

    A duplicated seq is itself an anomaly, so it is surfaced rather than
    silently overwritten by the later occurrence.
    """
    records, duplicates, malformed = {}, [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            envelope = json.loads(line)
            record = envelope["record"]
            seq = int(record["seq"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            malformed += 1
            continue
        if seq in records:
            duplicates.append(seq)
        records[seq] = record
    return records, duplicates, malformed


def verify(chain, records, duplicates, malformed, max_silence):
    alerts = []

    for seq in sorted(set(duplicates)):
        alerts.append(Alert("DUPLICATE", seq, "sequence number appears more than once in the log"))
    if malformed:
        alerts.append(Alert("MALFORMED", "-", f"{malformed} unparseable line(s) in the pulled log"))

    # --- ledger-driven: deletion and tamper --------------------------------
    computed = GENESIS
    chain_broken_at = None
    for entry in chain:
        seq, digest = int(entry["seq"]), entry["digest"]

        record = records.get(seq)
        if record is None:
            alerts.append(Alert("DELETION", seq, "digest is chained but no record with this sequence exists in the log"))
        else:
            recomputed = compute_digest(record)
            if recomputed != digest:
                alerts.append(Alert("TAMPER", seq,
                                    f"recomputed {recomputed[:16]}... != chained {digest[:16]}..."))

        # --- chain recomputation from genesis ------------------------------
        computed = next_chain_hash(digest, computed)
        if chain_broken_at is None and entry.get("chain_hash") != computed:
            chain_broken_at = seq
            alerts.append(Alert("CHAIN BREAK", seq,
                                f"stored {str(entry.get('chain_hash'))[:16]}... != recomputed {computed[:16]}..."))
            computed = entry.get("chain_hash", computed)

    # --- log-driven: unwitnessed records -----------------------------------
    # The check the original spec's loop cannot make, because it only ever
    # walks the ledger.
    chained_seqs = {int(e["seq"]) for e in chain}
    for seq in sorted(set(records) - chained_seqs):
        alerts.append(Alert("UNWITNESSED", seq,
                            "record is present in the log but no digest for it ever reached the ledger"))

    # --- out-of-order arrival ----------------------------------------------
    # The ledger accepts a digest for a sequence it never chained, because
    # refusing it would make spool recovery impossible. It marks it, and the
    # mark is surfaced here: a legitimate late arrival after an outage and a
    # backfill of a previously unwitnessed record look identical at the chain,
    # and only the receipt time distinguishes them.
    for entry in chain:
        if entry.get("out_of_order"):
            alerts.append(Alert("LATE DIGEST", entry.get("seq"),
                                f"digest arrived after the chain had reached seq "
                                f"{entry.get('chain_head_seq_at_receipt')}; "
                                f"received {entry.get('received')}"))

    # --- agent silence -----------------------------------------------------
    # Uses the ledger's own receipt timestamps throughout. The log's timestamps
    # are written by the primary and are therefore attacker-controlled.
    if max_silence:
        if not chain:
            alerts.append(Alert("SILENCE", "-",
                                "the chain is empty: no digest has ever been received"))
        else:
            # Interior gaps: the agent stopped and was restarted.
            for prev, curr in zip(chain, chain[1:]):
                try:
                    gap = (parse_ts(curr["received"]) - parse_ts(prev["received"])).total_seconds()
                except (KeyError, ValueError):
                    continue
                if gap > max_silence:
                    alerts.append(Alert("SILENCE", f"{prev['seq']}->{curr['seq']}",
                                        f"{gap:.0f}s with no digests received "
                                        f"(threshold {max_silence}s)"))

            # The open interval: the agent stopped and STAYED stopped, so the
            # chain simply ends. Without this check that case reports CLEAN --
            # which is backwards, because an attacker who kills the agent and
            # walks away is both cheaper and likelier than one who politely
            # restarts it afterwards.
            try:
                open_gap = (datetime.now(timezone.utc)
                            - parse_ts(chain[-1]["received"])).total_seconds()
                if open_gap > max_silence:
                    alerts.append(Alert("SILENCE", f"{chain[-1]['seq']}->now",
                                        f"{open_gap:.0f}s since the last digest was "
                                        f"received; the agent may be stopped "
                                        f"(threshold {max_silence}s)"))
            except (KeyError, ValueError, IndexError):
                pass

    return alerts


def run_once(args):
    started = utc_now()
    try:
        text = pull_log(args)
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        # An unreachable primary is not a clean run. Saying so is the point.
        alerts = [Alert("PULL FAILED", "-", str(exc))]
        records, chain = {}, []
    else:
        records, duplicates, malformed = parse_log(text)
        chain = load_chain(args.chain)
        alerts = verify(chain, records, duplicates, malformed, args.max_silence)

    heartbeats = sum(1 for r in records.values() if r.get("event") == HEARTBEAT_EVENT)
    outcome = {
        "ts": started,
        "finished": utc_now(),
        "chain_entries": len(chain),
        "log_records": len(records),
        "heartbeats": heartbeats,
        "alerts": [a.as_dict() for a in alerts],
        "result": "CLEAN" if not alerts else "ALERTS",
    }

    os.makedirs(os.path.dirname(args.verify_log), exist_ok=True)
    with open(args.verify_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(outcome, sort_keys=True, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())

    print(f"[{started}] chain={len(chain)} log={len(records)} "
          f"heartbeats={heartbeats} -> {outcome['result']}")
    for a in alerts:
        print(f"  {a}")
    return 0 if not alerts else 1


def main():
    p = argparse.ArgumentParser(description="independent log verifier")
    p.add_argument("--chain", default="/var/lib/ledger/chain.jsonl")
    p.add_argument("--verify-log", default="/var/log/verifier/verify.log")
    p.add_argument("--primary", default="10.0.0.173")
    p.add_argument("--ssh-user", default="verify")
    p.add_argument("--ssh-key", default=os.path.expanduser("~/.ssh/id_ed25519_verify"))
    p.add_argument("--ssh-timeout", type=int, default=10)
    p.add_argument("--log-file", help="read the log from a local path instead of "
                                      "pulling over SSH (testing only)")
    p.add_argument("--max-silence", type=float, default=0,
                   help="alert if this many seconds pass with no digests received. "
                        "Pair with the agent's --heartbeat-interval; 0 disables.")
    p.add_argument("--interval", type=float, default=0,
                   help="run continuously every N seconds instead of once")
    args = p.parse_args()

    if not args.interval:
        sys.exit(run_once(args))
    while True:
        try:
            run_once(args)
        except Exception as exc:  # keep the timer alive; a crashed verifier is silent
            print(f"[error] verification cycle failed: {exc}", file=sys.stderr)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
