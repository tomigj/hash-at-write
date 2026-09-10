#!/usr/bin/env python3
"""
run_attack_suite -- the attack scenarios, against a LIVE stack.

Stands up its own agent and ledgerd on loopback with their own paths, runs the
three scenarios that require stopping the agent, and reports what the verifier
says about each. Nothing here touches a production instance.

This is deliberately different from tests/repro_scenarios.py. That builds (log,
chain) pairs directly and checks the verifier's logic against them. This runs the
real agent, the real ledgerd and the real push path, then attacks the files they
produced. Fixtures prove the detection logic is correct; this proves the system
built out of it behaves the same way when something is actually done to it.

Scope, stated because it bounds what the results mean: both processes run on one
host over loopback. That is adequate for these three, which test detection rather
than custody -- but it is NOT a demonstration of split custody, and results from
here must never be presented as though the digests had crossed a network to a
host the attacker could not reach. The production two-host deployment is what
demonstrates that, and it is evidenced separately.

Run from the repository root:  python3 tests/run_attack_suite.py
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common.canonical import compute_digest  # noqa: E402

PORT = 19900 + (os.getpid() % 90)
HEARTBEAT = 5           # short, so silence tests do not take minutes
MAX_SILENCE = 15        # must exceed the beat interval plus jitter


def utc(dt=None):
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Stack:
    """A throwaway agent + ledgerd pair with their own paths."""

    def __init__(self, d):
        self.d = d
        self.agent = None
        self.ledger = None
        self.log = os.path.join(d, "events.log")
        self.chain = os.path.join(d, "chain.jsonl")
        self.sock = os.path.join(d, "agent.sock")

    def start_ledger(self):
        self.ledger = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "ledger", "ledgerd.py"),
             "--bind", "127.0.0.1", "--port", str(PORT),
             "--chain", self.chain,
             "--audit", os.path.join(self.d, "audit.jsonl"),
             "--idle-timeout", "300"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=0.5).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("ledgerd did not come up")

    def start_agent(self):
        self.agent = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "agent", "agent.py"),
             "--socket", self.sock, "--log", self.log,
             "--state", os.path.join(self.d, "agent.state"),
             "--spool", os.path.join(self.d, "pending.jsonl"),
             "--timing-log", os.path.join(self.d, "timing.log"),
             "--ledger-host", "127.0.0.1", "--ledger-port", str(PORT),
             "--heartbeat-interval", str(HEARTBEAT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if os.path.exists(self.sock):
                time.sleep(0.3)
                return
            time.sleep(0.1)
        raise RuntimeError("agent did not come up")

    def stop_agent(self):
        if self.agent:
            self.agent.send_signal(signal.SIGTERM)
            self.agent.wait(timeout=10)
            self.agent = None

    def emit(self, message):
        s = socket.create_connection(("localhost", 0)) if False else None
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(self.sock)
        f = c.makefile("rw")
        f.write(json.dumps({"event": message}) + "\n")
        f.flush()
        reply = json.loads(f.readline())
        c.close()
        return reply

    def push_digest(self, seq, digest):
        """Submit a digest directly, as a compromised primary would."""
        c = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        f = c.makefile("rw")
        f.write(json.dumps({"seq": seq, "digest": digest}) + "\n")
        f.flush()
        reply = json.loads(f.readline())
        c.close()
        return reply

    def append_record(self, record):
        """Write straight to the log, as root on a compromised host would."""
        with open(self.log, "a", encoding="utf-8") as f:
            f.write(json.dumps({"record": record, "digest": compute_digest(record)},
                               sort_keys=True, separators=(",", ":")) + "\n")

    def next_seq(self):
        seqs = [json.loads(l)["record"]["seq"] for l in open(self.log) if l.strip()]
        return max(seqs) + 1 if seqs else 1

    def verify(self, max_silence=0):
        p = subprocess.run(
            [sys.executable, os.path.join(ROOT, "ledger", "verifier.py"),
             "--chain", self.chain, "--log-file", self.log,
             "--verify-log", os.path.join(self.d, "verify.log"),
             "--max-silence", str(max_silence)],
            capture_output=True, text=True)
        return p.stdout.strip(), p.returncode

    def shutdown(self):
        self.stop_agent()
        if self.ledger:
            self.ledger.send_signal(signal.SIGTERM)
            self.ledger.wait(timeout=10)


def scenario(title, expect, body):
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")
    out, rc = body()
    ok = expect(out, rc)
    for line in out.splitlines():
        print(f"    {line}")
    print(f"    exit {rc}")
    print(f"    -> {'OK' if ok else 'UNEXPECTED'}")
    return ok


def fresh_stack(n):
    """A new stack per scenario.

    Each scenario gets its own agent, ledgerd, log and chain. Sharing one stack
    across all three was the first version of this file and it was wrong: the
    alerts raised by an earlier attack persist in the log and chain, so a later
    scenario expecting CLEAN can never produce it. That made T12 report
    UNEXPECTED when the system was behaving perfectly -- a harness defect
    reported as a system finding, which is the failure this project is about.
    """
    global PORT
    PORT += 1
    d = tempfile.mkdtemp(prefix=f"witnessd-attack-{n}-")
    s = Stack(d)
    s.start_ledger()
    s.start_agent()
    for i in range(1, 6):
        s.emit(f"routine event {i}")
    time.sleep(HEARTBEAT + 1)
    return s


def main():
    print(f"heartbeat {HEARTBEAT}s, silence threshold {MAX_SILENCE}s")
    print("each scenario runs on its own agent, ledgerd, log and chain")
    results = {}
    stacks = []
    try:

        # --- T7 ------------------------------------------------------------
        def t7():
            s = fresh_stack("t7"); stacks.append(s)
            s.stop_agent()
            seq = s.next_seq()
            s.append_record({"seq": seq, "ts": utc(),
                             "event": "admin deleted customer record 88214"})
            s.start_agent()
            return s.verify()
        results["T7"] = scenario(
            "T7 — unwitnessed insertion: agent stopped, record appended, restarted",
            lambda o, rc: "UNWITNESSED" in o and rc == 1, t7)

        # --- T8 ------------------------------------------------------------
        def t8():
            s = fresh_stack("t8"); stacks.append(s)
            s.stop_agent()
            seq = s.next_seq()
            old = datetime.now(timezone.utc) - timedelta(days=400)
            rec = {"seq": seq, "ts": utc(old),
                   "event": "sshd: Accepted password for root from 203.0.113.9"}
            s.append_record(rec)
            s.push_digest(seq, compute_digest(rec))
            s.start_agent()
            return s.verify()
        results["T8"] = scenario(
            "T8 — backdating: a witnessed record claiming to be 400 days old",
            lambda o, rc: "BACKDATED" in o and rc == 1, t8)

        # --- T12 -----------------------------------------------------------
        def t12():
            s = fresh_stack("t12"); stacks.append(s)
            s.stop_agent()
            seq = s.next_seq()
            rec = {"seq": seq, "ts": utc(),
                   "event": "sshd: Accepted publickey for root from 10.0.0.1"}
            s.append_record(rec)
            s.push_digest(seq, compute_digest(rec))
            s.start_agent()          # stop is well under MAX_SILENCE
            out, rc = s.verify(max_silence=MAX_SILENCE)
            return out, rc
        results["T12"] = scenario(
            "T12 — fabrication with an honest timestamp, EXPECTED TO VERIFY CLEAN",
            lambda o, rc: "CLEAN" in o and rc == 0, t12)

    finally:
        for s in stacks:
            s.shutdown()
            shutil.rmtree(s.d, ignore_errors=True)

    print(f"\n{'=' * 78}")
    for k, v in results.items():
        print(f"  {k}: {'as expected' if v else 'UNEXPECTED'}")
    print("""
T12 verifying CLEAN is the intended result, not a failure. A record fabricated on
the primary and witnessed through the normal path is byte-identical, in every
property this design checks, to a genuine one. The stop was shorter than the
silence threshold, and both values are printed above because the result depends
entirely on that relationship.""")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
