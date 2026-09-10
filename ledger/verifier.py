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


# A record's timestamp may legitimately precede its receipt by the push
# latency, or by a whole outage if it was spooled. It may never meaningfully
# follow it; this allows only for clock drift between the two hosts.
CLOCK_TOLERANCE = 60.0


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def fmt_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def human(seconds):
    """Render a duration at a sensible scale.

    Rendering everything in days prints a seven-minute skew as "0.0 days",
    which next to "2444.1 days" on the following line reads as a broken
    formatter and invites a reader to distrust every number on the page.
    """
    seconds = abs(seconds)
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


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


def verify(chain, records, duplicates, malformed, max_silence, max_skew):
    alerts = []
    max_log_seq = max(records) if records else None

    for seq in sorted(set(duplicates)):
        alerts.append(Alert("DUPLICATE", seq, "sequence number appears more than once in the log"))
    if malformed:
        alerts.append(Alert("MALFORMED", "-", f"{malformed} unparseable line(s) in the pulled log"))

    # --- ledger-driven: deletion and tamper --------------------------------
    computed = GENESIS
    chain_broken_at = None
    # The last receipt whose own record arrived promptly -- i.e. the last
    # moment this ledger is known to have been reachable AND current. Entries
    # in a recovery batch all arrive within milliseconds of each other, so the
    # immediately preceding entry is useless as a reference point: it is a
    # batch-mate, not evidence of liveness at the time the record was written.
    last_healthy_received = None

    # Receipt gaps large enough to be reported as SILENCE, computed before the
    # main loop so that the skew check can say whether the quiet window it is
    # about to accept as an explanation is itself already flagged. The two facts
    # are in the same pass; leaving a reader to connect them across two
    # unrelated-looking lines is how a laundered forgery gets read as an outage.
    silence_intervals = []
    if max_silence:
        for a, b in zip(chain, chain[1:]):
            try:
                ta, tb = parse_ts(a["received"]), parse_ts(b["received"])
            except (KeyError, ValueError):
                continue
            if (tb - ta).total_seconds() > max_silence:
                silence_intervals.append((ta, tb))

    for entry in chain:
        seq, digest = int(entry["seq"]), entry["digest"]

        record = records.get(seq)
        if record is None:
            detail = "digest is chained but no record with this sequence exists in the log"
            if max_log_seq is not None and seq > max_log_seq:
                # Beyond the log's highest sequence this is ambiguous between a
                # truncated tail and a digest for a record that never existed.
                # Say so rather than asserting the stronger claim.
                detail += (f" (beyond the log's highest sequence {max_log_seq}: "
                           f"either the tail was truncated or this digest was "
                           f"submitted for a record that never existed)")
            alerts.append(Alert("DELETION", seq, detail))
        else:
            recomputed = compute_digest(record)
            if recomputed != digest:
                alerts.append(Alert("TAMPER", seq,
                                    f"recomputed {recomputed[:16]}... != chained {digest[:16]}..."))

            # A record asserts when it happened; the ledger records when its
            # digest arrived. The first is written by the primary and is
            # attacker-controlled, the second is not. They sit in two files read
            # on the same pass, and comparing them costs nothing.
            #
            # This matters for what an audit trail is FOR. Detecting that a
            # record was not altered is only half the question; the other half
            # is when it happened. A forged record witnessed normally at the
            # next sequence verifies clean on every other check -- backdating it
            # is free unless this comparison is made.
            try:
                claimed, received = parse_ts(record["ts"]), parse_ts(entry["received"])
            except (KeyError, ValueError):
                pass
            else:
                skew = (received - claimed).total_seconds()
                if skew > max_skew:
                    # Lateness alone does not imply forgery. A digest spooled
                    # while this host was unreachable arrives late for an
                    # entirely legitimate reason, and the ledger's own receipt
                    # times say when that was: if the record claims to have been
                    # written AFTER the last digest this ledger successfully
                    # received, the ledger may well have been down since then
                    # and the delay is explained.
                    #
                    # A record claiming to predate a moment when the ledger was
                    # demonstrably receiving normally has no such explanation.
                    # That is the suspicious one, and separating the two is what
                    # keeps a real outage from being reported in the same terms
                    # as a forgery -- which would reintroduce, in the alerting,
                    # exactly the ambiguity this project exists to remove.
                    # The ledger cannot tell "I was unreachable" from "the
                    # primary chose not to speak" -- from its seat those are the
                    # same observation. Under full root the primary can go quiet
                    # deliberately, manufacturing a window, and then backdate a
                    # forged record into it to earn this softer label. So the
                    # wording below claims only what was observed, never that an
                    # outage occurred, and it points at the corroborating
                    # SILENCE alert when one exists.
                    in_flagged_gap = any(a <= claimed <= b for a, b in silence_intervals)
                    corroboration = (
                        " -- and that quiet window is itself reported as SILENCE "
                        "below, so the explanation rests on the primary's own "
                        "absence" if in_flagged_gap else "")
                    if last_healthy_received is None:
                        # Nothing in the chain predates this, so there is no
                        # evidence either way. Say that, rather than picking a
                        # side: from ledger data alone an outage before the
                        # chain began and a backdated record are identical.
                        alerts.append(Alert("UNCORROBORATED", seq,
                            f"digest arrived {human(skew)} after the record claims "
                            f"to have been written, and no earlier prompt receipt "
                            f"exists to establish that this ledger was reachable at "
                            f"that time -- this lateness cannot be distinguished "
                            f"from a digest withheld and submitted later"
                            + corroboration))
                    elif claimed >= last_healthy_received:
                        alerts.append(Alert("UNCORROBORATED", seq,
                            f"digest arrived {human(skew)} after the record claims "
                            f"to have been written; no digests were received "
                            f"between {fmt_ts(last_healthy_received)} and "
                            f"{entry['received']}, so this lateness cannot be "
                            f"distinguished from a digest withheld and submitted "
                            f"later" + corroboration))
                    else:
                        alerts.append(Alert("BACKDATED", seq,
                            f"record claims {record['ts']} but its digest reached "
                            f"the ledger at {entry['received']} -- {human(skew)} "
                            f"later, and the ledger was receiving normally at the "
                            f"claimed time (threshold {max_skew:.0f}s)"))
                    # deliberately does not update last_healthy_received
                elif -skew > CLOCK_TOLERANCE:
                    # A record cannot legitimately be written after its own
                    # digest was received.
                    alerts.append(Alert("FUTURE DATED", seq,
                        f"record claims {record['ts']}, which is {human(-skew)} "
                        f"AFTER its digest was received at {entry['received']}"))
                else:
                    # Arrived promptly: this receipt is evidence the ledger was
                    # reachable and current at the moment the record was written.
                    last_healthy_received = received

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
                                        f"{human(gap)} with no digests received "
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
                                        f"{human(open_gap)} since the last digest "
                                        f"was received; the agent may be stopped "
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
        alerts = verify(chain, records, duplicates, malformed, args.max_silence,
                        args.max_skew)

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
    p.add_argument("--max-silence", type=float, default=180,
                   help="alert if this many seconds pass with no digests received. "
                        "Must exceed the agent's --heartbeat-interval plus normal "
                        "jitter or every missed beat is a false positive; the "
                        "default is three times the default interval. This value, "
                        "not the interval, is the window an attacker must fit a "
                        "stop inside. 0 disables.")
    p.add_argument("--max-skew", type=float, default=300,
                   help="alert when a record's own timestamp precedes the "
                        "ledger's receipt of its digest by more than this many "
                        "seconds. Recovery after a long ledger outage can exceed "
                        "it legitimately, and should be visible when it does.")
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
