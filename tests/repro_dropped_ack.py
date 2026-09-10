"""TCP proxy: forwards agent->ledgerd faithfully, but swallows the ack for ONE
submission (default seq 2), simulating a packet lost on the return path AFTER
the ledger has already committed the digest. Nothing malicious; ordinary wifi.

Reproduces the condition that previously caused the agent to resubmit a digest
the ledger already held, be refused as an attempted rewrite, and retry from the
spool forever -- roughly 8,600 REFUSED_REWRITE entries per day from one lost
packet, each reading as an attack in the audit trail.

Usage:
    python3 ledger/ledgerd.py --bind 127.0.0.1 --port 19900 --chain /tmp/c.jsonl \
        --audit /tmp/a.jsonl &
    python3 tests/repro_dropped_ack.py 2 &
    python3 agent/agent.py --ledger-host 127.0.0.1 --ledger-port 19901 ...

Expected after the fix: the resubmission is acknowledged as a duplicate, the
ledger audits DUPLICATE_SUBMISSION, no REFUSED_REWRITE appears, and the spool
empties.

Written by the Claude session on `tg` (primary) during review of cff0e5e..0aed299,
and verified there.
"""
import json, socket, socketserver, sys, threading

LEDGER = ("127.0.0.1", 19900)
DROP_SEQ = int(sys.argv[1]) if len(sys.argv) > 1 else 2
dropped = threading.Event()


class H(socketserver.StreamRequestHandler):
    def handle(self):
        up = socket.create_connection(LEDGER, timeout=10)
        upf = up.makefile("rwb")
        for raw in self.rfile:
            if not raw.strip():
                continue
            try:
                seq = json.loads(raw)["seq"]
            except Exception:
                seq = None
            upf.write(raw); upf.flush()
            ack = upf.readline()
            if seq == DROP_SEQ and not dropped.is_set():
                dropped.set()
                print(f"[proxy] ledger committed seq {seq} and acked "
                      f"{ack.decode().strip()} -- DROPPING that ack", flush=True)
                continue            # agent never hears it
            self.wfile.write(ack); self.wfile.flush()


class S_(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    S_(("127.0.0.1", 19901), H).serve_forever()
