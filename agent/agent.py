#!/usr/bin/env python3
"""
agent -- hash-at-write logging agent. Runs on `primary`.

Listens on a Unix domain socket. For each event received, the sequence number is
assigned, the canonical record built, and the SHA-256 digest computed BEFORE the
record is appended to disk and BEFORE the call returns to the caller.

That ordering is the entire claim. Conventional log signing computes a digest
over a completed file at rotation, leaving an interval in which entries sit on
disk unprotected -- an edit made inside that window is subsequently signed as
genuine. Here there is no window to edit inside: the digest exists before the
write returns, and every handled event writes a timing record proving it.

The digest covers the record object only -- {"seq","ts","event"} -- never the
envelope that carries the digest beside it. Hashing the digest into its own
digest would make the record unverifiable from the log line alone.

Failure handling: an unpushed digest is a hole in the evidence, so it is never
silently dropped. Push failures retry with backoff, then spool to disk, and the
gap is recorded explicitly in the timing log.

Targets Python 3.12 (the floor across both hosts). Standard library only.
"""

import argparse
import json
import os
import signal
import socket
import sys
import threading
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.canonical import HEARTBEAT_EVENT, compute_digest  # noqa: E402

# Inline retry schedule, in seconds, before a digest is spooled for the
# background drainer. Kept short: the caller is blocked while this runs.
PUSH_BACKOFF = (0.05, 0.2, 0.5)


class PermanentRefusal(Exception):
    """The ledger refused a digest in a way that resubmission cannot fix."""


def utc_now():
    """ISO-8601 UTC with milliseconds and an explicit Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Agent:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.last_seq = 0
        self.ledger = None          # live socket to ledgerd, lazily reconnected
        self.stop = threading.Event()

        for path in (args.log, args.state, args.spool, args.timing_log):
            os.makedirs(os.path.dirname(path), exist_ok=True)

        self._recover_seq()
        self.log_fh = open(args.log, "a", encoding="utf-8")
        self.timing_fh = open(args.timing_log, "a", encoding="utf-8")

    # ---------- sequence recovery -------------------------------------------

    def _recover_seq(self):
        """Establish the next sequence number from two independent sources.

        The state file is the fast path. The log's last line is the ground
        truth. They can disagree if the process died between the append and the
        state write, so we take the max -- and record the disagreement, because
        a state file BEHIND the log is normal after a crash while a state file
        AHEAD of the log means log lines went missing, which is exactly the
        condition this system exists to detect.
        """
        from_state = 0
        if os.path.exists(self.args.state):
            try:
                with open(self.args.state, encoding="utf-8") as f:
                    from_state = int(json.load(f).get("last_seq", 0))
            except (ValueError, OSError, json.JSONDecodeError) as exc:
                print(f"[warn] unreadable state file, ignoring: {exc}", file=sys.stderr)

        from_log = 0
        if os.path.exists(self.args.log):
            with open(self.args.log, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        from_log = int(json.loads(line)["record"]["seq"])
                    except (ValueError, KeyError, json.JSONDecodeError):
                        continue

        self.last_seq = max(from_state, from_log)
        if from_state != from_log:
            print(
                f"[warn] seq mismatch on startup: state={from_state} log={from_log} "
                f"-> resuming at {self.last_seq + 1}",
                file=sys.stderr,
            )

    def _persist_seq(self, seq):
        """Atomically record the last assigned sequence number."""
        tmp = self.args.state + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"last_seq": seq, "updated": utc_now()}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.args.state)

    # ---------- the write path ----------------------------------------------

    def handle_event(self, event):
        """Assign, hash, write, push -- in that order, under one lock.

        The lock serialises the whole operation so sequence numbers stay
        monotonic and the log's on-disk order matches the chain's order. For POC
        volumes the contention cost is irrelevant next to the fsync.
        """
        t_recv = time.perf_counter_ns()

        with self.lock:
            seq = self.last_seq + 1
            record = {"seq": seq, "ts": utc_now(), "event": event}

            # --- claim 1: the digest is taken here, before anything reaches disk
            digest = None if self.args.no_hash else compute_digest(record)
            t_digest = time.perf_counter_ns()

            envelope = {"record": record}
            if digest is not None:
                envelope["digest"] = digest
            self.log_fh.write(
                json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n"
            )
            self.log_fh.flush()
            os.fsync(self.log_fh.fileno())
            t_written = time.perf_counter_ns()

            self.last_seq = seq
            self._persist_seq(seq)
            t_state = time.perf_counter_ns()

            pushed = None
            if digest is not None and not self.args.no_push:
                pushed = self._push_with_retry(seq, digest)
            t_done = time.perf_counter_ns()

            self._record_timing(seq, t_recv, t_digest, t_written, t_state,
                                t_done, pushed)

        return {"ok": True, "seq": seq, "digest": digest, "pushed": pushed}

    def _record_timing(self, seq, t_recv, t_digest, t_written, t_state,
                       t_done, pushed):
        """Write the evidence for claim 1.

        digest_before_write_us is the interval between the digest existing and
        the write returning. It is positive by construction; logging it makes
        the ordering auditable rather than merely asserted in a comment.
        """
        self.timing_fh.write(
            json.dumps(
                {
                    "seq": seq,
                    "ts": utc_now(),
                    "hash_us": round((t_digest - t_recv) / 1000, 1),
                    "digest_before_write_us": round((t_written - t_digest) / 1000, 1),
                    "state_us": round((t_state - t_written) / 1000, 1),
                    "push_us": round((t_done - t_state) / 1000, 1),
                    "total_us": round((t_done - t_recv) / 1000, 1),
                    "pushed": pushed,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        self.timing_fh.flush()

    # ---------- ledger push --------------------------------------------------

    def _connect_ledger(self):
        s = socket.create_connection(
            (self.args.ledger_host, self.args.ledger_port), timeout=self.args.push_timeout
        )
        s.settimeout(self.args.push_timeout)
        return s

    def _push_once(self, seq, digest):
        if self.ledger is None:
            self.ledger = self._connect_ledger()
        payload = json.dumps({"seq": seq, "digest": digest}, sort_keys=True,
                             separators=(",", ":")) + "\n"
        self.ledger.sendall(payload.encode("utf-8"))
        # ledgerd acknowledges each digest; a missing ack is treated as a failed
        # push, because "sent" is not "recorded" and only the latter is evidence.
        ack = self.ledger.makefile("r", encoding="utf-8").readline()
        if not ack:
            raise OSError("ledger closed connection without acknowledging")
        resp = json.loads(ack)
        if not resp.get("ok"):
            if resp.get("permanent"):
                # The ledger will refuse this forever -- resubmitting cannot
                # change the answer. Retrying it every interval would bury the
                # audit trail in identical entries and never succeed.
                raise PermanentRefusal(resp.get("error", "refused"))
            raise OSError(f"ledger rejected seq {seq}: {resp}")
        return True

    def _push_with_retry(self, seq, digest):
        for attempt, delay in enumerate((0.0,) + PUSH_BACKOFF):
            if delay:
                time.sleep(delay)
            try:
                return self._push_once(seq, digest)
            except PermanentRefusal as exc:
                self._dead_letter(seq, digest, str(exc))
                return False
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                if self.ledger is not None:
                    try:
                        self.ledger.close()
                    finally:
                        self.ledger = None
                last = exc
        self._spool_gap(seq, digest, str(last))
        return False

    def _spool_gap(self, seq, digest, reason):
        """Record an unpushed digest loudly, on disk, with the reason."""
        with open(self.args.spool, "a", encoding="utf-8") as f:
            f.write(json.dumps({"seq": seq, "digest": digest, "ts": utc_now(),
                                "reason": reason}, sort_keys=True,
                               separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        print(f"[GAP] seq {seq} not pushed to ledger: {reason}", file=sys.stderr)

    def emit_heartbeats(self):
        """Emit a liveness beat on an interval, even with no events.

        Without this, an attacker with root stops the agent, writes what they
        like to the log unwitnessed, and restarts it -- the chain stays
        internally consistent and verifies clean. Beats make the silence
        itself a detectable condition.
        """
        while not self.stop.wait(self.args.heartbeat_interval):
            try:
                self.handle_event(HEARTBEAT_EVENT)
            except Exception as exc:  # never let a beat kill the agent
                print(f"[warn] heartbeat failed: {exc}", file=sys.stderr)

    def _dead_letter(self, seq, digest, reason):
        """Record a digest the ledger will never accept.

        This is a loud condition: either the ledger already holds a different
        digest for this sequence, or something is wrong that retrying cannot
        fix. It is recorded once, not retried.
        """
        with open(self.args.spool + ".rejected", "a", encoding="utf-8") as f:
            f.write(json.dumps({"seq": seq, "digest": digest, "ts": utc_now(),
                                "reason": reason}, sort_keys=True,
                               separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        print(f"[REFUSED] seq {seq} permanently refused by ledger: {reason}",
              file=sys.stderr)

    def drain_spool(self):
        """Background retry of spooled digests.

        Runs until the process stops. Entries leave the spool only once the
        ledger has acknowledged them.
        """
        while not self.stop.wait(self.args.spool_interval):
            if not os.path.exists(self.args.spool):
                continue
            with self.lock:
                with open(self.args.spool, encoding="utf-8") as f:
                    pending = [json.loads(l) for l in f if l.strip()]
                if not pending:
                    continue
                remaining = []
                for item in pending:
                    try:
                        self._push_once(item["seq"], item["digest"])
                        print(f"[recovered] seq {item['seq']} pushed from spool",
                              file=sys.stderr)
                    except PermanentRefusal as exc:
                        # Drop from the spool: it can never be accepted, and
                        # retrying it forever would poison the audit trail.
                        self._dead_letter(item["seq"], item["digest"], str(exc))
                    except (OSError, ValueError, json.JSONDecodeError):
                        if self.ledger is not None:
                            try:
                                self.ledger.close()
                            finally:
                                self.ledger = None
                        remaining.append(item)
                with open(self.args.spool, "w", encoding="utf-8") as f:
                    for item in remaining:
                        f.write(json.dumps(item, sort_keys=True,
                                           separators=(",", ":")) + "\n")

    # ---------- socket server ------------------------------------------------

    def _serve_client(self, conn):
        with conn, conn.makefile("rw", encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)["event"]
                except (ValueError, KeyError, json.JSONDecodeError) as exc:
                    stream.write(json.dumps({"ok": False, "error": str(exc)}) + "\n")
                    stream.flush()
                    continue
                result = self.handle_event(event)
                stream.write(json.dumps(result) + "\n")
                stream.flush()

    def serve(self):
        if os.path.exists(self.args.socket):
            os.unlink(self.args.socket)
        os.makedirs(os.path.dirname(self.args.socket), exist_ok=True)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(self.args.socket)
        os.chmod(self.args.socket, 0o660)
        srv.listen(16)

        # systemd stops services with SIGTERM. Without this the cleanup below
        # never runs and a stale socket file is left behind, which makes the
        # next start look alive to clients while nothing is listening.
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

        threading.Thread(target=self.drain_spool, daemon=True).start()
        if self.args.heartbeat_interval > 0:
            threading.Thread(target=self.emit_heartbeats, daemon=True).start()
            print(f"heartbeat every {self.args.heartbeat_interval}s", file=sys.stderr)
        else:
            # Not a style warning. Without beats, an attacker who stops the
            # agent, appends a record at the next sequence, witnesses it
            # normally and restarts leaves no trace on any other check: the
            # digest is genuine, the chain is intact, the sequence is in order.
            # The receipt gap while the agent was stopped is the only evidence
            # that anything happened, and only silence detection reads it.
            print("[!] heartbeats DISABLED: a stopped agent leaves no detectable "
                  "gap, so a record forged at the next sequence and witnessed "
                  "normally will verify clean. Set --heartbeat-interval and run "
                  "the verifier with --max-silence.", file=sys.stderr)
        print(f"agent listening on {self.args.socket}, resuming at seq "
              f"{self.last_seq + 1}", file=sys.stderr)
        if self.args.no_hash:
            print("[!] --no-hash: running WITHOUT integrity protection "
                  "(T6 baseline only)", file=sys.stderr)

        try:
            while True:
                conn, _ = srv.accept()
                threading.Thread(target=self._serve_client, args=(conn,),
                                 daemon=True).start()
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            self.stop.set()
            srv.close()
            if os.path.exists(self.args.socket):
                os.unlink(self.args.socket)
            self.log_fh.close()
            self.timing_fh.close()
            print("agent stopped cleanly", file=sys.stderr)


def main():
    p = argparse.ArgumentParser(description="hash-at-write logging agent")
    p.add_argument("--socket", default="/run/integrity/agent.sock")
    p.add_argument("--log", default="/var/log/integrity/events.log")
    p.add_argument("--state", default="/var/lib/integrity/agent.state")
    p.add_argument("--spool", default="/var/lib/integrity/pending.jsonl")
    p.add_argument("--timing-log", default="/var/log/integrity/timing.log")
    p.add_argument("--ledger-host", default="10.0.0.212")
    p.add_argument("--ledger-port", type=int, default=9900)
    p.add_argument("--push-timeout", type=float, default=2.0)
    p.add_argument("--spool-interval", type=float, default=10.0)
    p.add_argument("--heartbeat-interval", type=float, default=60,
                   help="emit a liveness beat every N seconds so that a stopped "
                        "agent is detectable as silence. 0 disables, which leaves "
                        "an agent stopped to insert records undetectable; pair "
                        "with the verifier's --max-silence, which cannot be set "
                        "tighter than this interval plus jitter.")
    p.add_argument("--no-push", action="store_true",
                   help="write hashed entries locally without pushing (build step 2)")
    p.add_argument("--no-hash", action="store_true",
                   help="baseline mode for the T6 overhead measurement: no digest, "
                        "no push. Produces an UNPROTECTED log; never use in a "
                        "demonstration run.")
    Agent(p.parse_args()).serve()


if __name__ == "__main__":
    main()
