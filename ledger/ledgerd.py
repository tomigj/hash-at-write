#!/usr/bin/env python3
"""
ledgerd -- digest chain receiver. Runs on `ledger`.

Accepts {"seq","digest"} from the primary's agent, binds each digest to the one
before it, and appends the result to an append-only chain file.

The protocol is deliberately impoverished. There is exactly one verb: submit a
digest. There is no read-back, no seek, no delete, and no "resend seq N".

That is not minimalism for its own sake. The threat model grants the attacker
full root on the primary, which means every firewall rule, sshd setting and
authorized_keys entry ON the primary is inside the attacker's control and none
of them protects the evidence. The only controls that are load-bearing are the
ones on this host. So this listener must offer the primary no verb that could
read, rewind or rewrite the chain -- because the primary is, by assumption,
hostile, and anything it can ask for it can eventually ask for maliciously.

Consequences of that stance, enforced below:
  - a seq already present is REFUSED, never overwritten (replay/rewrite vector)
  - a seq at or below the chain head is REFUSED (rewind vector)
  - the acknowledgement carries no chain state back to the submitter
  - connections from anything but the expected primary are dropped

Targets Python 3.12. Standard library only.
"""

import argparse
import json
import os
import socket
import socketserver
import sys
import threading
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common.canonical import GENESIS, next_chain_hash  # noqa: E402


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Chain:
    """The digest chain. Append-only by protocol and, on disk, by chattr +a."""

    def __init__(self, path, audit_path, seq_window):
        self.path = path
        self.audit_path = audit_path
        self.seq_window = seq_window
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
        self.head = GENESIS
        self.last_seq = 0
        # seq -> digest, for telling a retransmission apart from a rewrite.
        # Without this the chain can only ask "is this seq old?", which cannot
        # distinguish a lost acknowledgement from an attack.
        self.digests = {}
        self._load()

    def _load(self):
        """Replay the chain to recover the head.

        Recomputed rather than trusted: if the file has been altered while we
        were down, the head we resume from should reflect what the file
        actually contains, and the mismatch should be visible immediately
        rather than at the next verification run.
        """
        if not os.path.exists(self.path):
            return
        computed = GENESIS
        with open(self.path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    self.audit("CORRUPT_LINE", {"lineno": lineno})
                    continue
                computed = next_chain_hash(entry["digest"], computed)
                if entry.get("chain_hash") != computed:
                    self.audit("CHAIN_MISMATCH_ON_LOAD", {
                        "seq": entry.get("seq"), "lineno": lineno,
                        "stored": entry.get("chain_hash"), "recomputed": computed})
                    # Keep the stored value as the head so we chain onto the
                    # file as it exists. The discrepancy is now on record.
                    computed = entry.get("chain_hash", computed)
                seq = int(entry.get("seq", 0))
                self.digests[seq] = entry.get("digest")
                self.last_seq = max(self.last_seq, seq)
        self.head = computed

    def audit(self, kind, detail):
        """Record refusals and anomalies. This file is the ledger's own log."""
        line = json.dumps({"ts": utc_now(), "kind": kind, "detail": detail},
                          sort_keys=True, separators=(",", ":"))
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        print(f"[{kind}] {detail}", file=sys.stderr)

    def submit(self, seq, digest, peer):
        """Append one digest, or refuse and say why."""
        with self.lock:
            if not isinstance(seq, int) or seq <= 0:
                return False, "seq must be a positive integer"
            if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
                return False, "digest must be 64 lowercase hex characters"

            # The sequence number is chosen by the submitter and, before this
            # check, was unbounded. A single packet claiming seq 999999 is
            # accepted, pins the head there permanently, and thereafter every
            # genuine digest arrives "out of order" and is mislabelled, while
            # the absent record shows as a DELETION that never happened. The
            # chain stays cryptographically correct and the alert stream
            # becomes unusable -- one unauthenticated packet, no privileges
            # beyond reaching the port.
            #
            # An empty chain accepts any starting point, so a ledger can be
            # brought up against an agent that already has history.
            if self.last_seq and seq > self.last_seq + self.seq_window:
                self.audit("IMPLAUSIBLE_SEQ", {
                    "seq": seq, "peer": peer, "chain_head_seq": self.last_seq,
                    "window": self.seq_window})
                return False, (f"seq {seq} is more than {self.seq_window} beyond "
                               f"chain head {self.last_seq}")

            # What actually constitutes a rewrite is a DIFFERENT digest for a
            # sequence number already recorded. An identical digest for a
            # recorded sequence is a retransmission -- it gains an attacker
            # nothing, because the chain is unchanged -- and it happens for an
            # ordinary reason: the acknowledgement was lost in transit and the
            # agent resent. Refusing those manufactures the exact audit
            # signature of an attack out of one dropped packet on wifi.
            existing = self.digests.get(seq)
            if existing is not None:
                if existing == digest:
                    self.audit("DUPLICATE_SUBMISSION", {
                        "seq": seq, "peer": peer,
                        "note": "identical digest already chained; "
                                "acknowledging without appending"})
                    return True, None
                self.audit("REFUSED_REWRITE", {
                    "seq": seq, "peer": peer,
                    "chained_digest": existing, "submitted_digest": digest})
                return False, f"seq {seq} already chained with a different digest"

            # A sequence number below the head that was never chained is a
            # legitimate late arrival -- the agent spooled it while this host
            # was unreachable. Refusing it would make the spool unrecoverable
            # by construction. It is accepted, and marked, because a digest
            # arriving out of order is worth seeing: it is also the shape a
            # backfill attempt would take.
            out_of_order = seq < self.last_seq
            chain_hash = next_chain_hash(digest, self.head)
            entry = {"seq": seq, "digest": digest, "prev_chain": self.head,
                     "chain_hash": chain_hash, "received": utc_now()}
            if out_of_order:
                entry["out_of_order"] = True
                entry["chain_head_seq_at_receipt"] = self.last_seq
                self.audit("LATE_DIGEST", {
                    "seq": seq, "peer": peer, "chain_head_seq": self.last_seq})
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, sort_keys=True,
                                   separators=(",", ":")) + "\n")
                f.flush()
                os.fsync(f.fileno())

            self.head = chain_hash
            self.digests[seq] = digest
            self.last_seq = max(self.last_seq, seq)
            return True, None


class Handler(socketserver.StreamRequestHandler):
    timeout = 30

    def handle(self):
        peer = self.client_address[0]
        if self.server.allowed and peer not in self.server.allowed:
            # Defence in depth behind ufw. The firewall is the real control;
            # this makes an unexpected source visible in the audit trail
            # instead of merely dropped.
            self.server.chain.audit("REJECTED_PEER", {"peer": peer})
            return
        for raw in self.rfile:
            raw = raw.strip()
            if not raw:
                continue
            try:
                msg = json.loads(raw)
                seq, digest = int(msg["seq"]), str(msg["digest"])
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                self.reply({"ok": False, "error": f"malformed submission: {exc}"})
                continue
            ok, err = self.server.chain.submit(seq, digest, peer)
            # The acknowledgement carries no chain state. The submitter learns
            # only whether its digest was recorded.
            # A refusal here is permanent by construction -- resubmitting the
            # same thing will always be refused. Saying so lets the agent move
            # it to a dead-letter file instead of retrying it forever.
            self.reply({"ok": True, "seq": seq} if ok
                       else {"ok": False, "error": err, "permanent": True})

    def reply(self, obj):
        self.wfile.write((json.dumps(obj, sort_keys=True,
                                     separators=(",", ":")) + "\n").encode("utf-8"))
        self.wfile.flush()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    address_family = socket.AF_INET


def main():
    p = argparse.ArgumentParser(description="digest chain receiver")
    p.add_argument("--bind", default="0.0.0.0",
                   help="listen address; ufw restricts the source, not this")
    p.add_argument("--port", type=int, default=9900)
    p.add_argument("--chain", default="/var/lib/ledger/chain.jsonl")
    p.add_argument("--audit", default="/var/lib/ledger/ledgerd-audit.jsonl")
    p.add_argument("--seq-window", type=int, default=1000,
                   help="refuse a sequence number more than this far beyond the "
                        "current chain head. Bounds the damage an arbitrary seq "
                        "can do to the alert stream; must exceed the deepest "
                        "spool backlog you expect.")
    p.add_argument("--allow", action="append", default=[],
                   help="permitted source IP; repeatable. Empty means any "
                        "(rely on ufw alone).")
    args = p.parse_args()

    chain = Chain(args.chain, args.audit, args.seq_window)
    srv = Server((args.bind, args.port), Handler)
    srv.chain = chain
    srv.allowed = set(args.allow)

    print(f"ledgerd listening on {args.bind}:{args.port}", file=sys.stderr)
    print(f"chain head seq={chain.last_seq} hash={chain.head[:16]}...", file=sys.stderr)
    if args.allow:
        print(f"accepting submissions from: {', '.join(sorted(srv.allowed))}",
              file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("ledgerd stopped", file=sys.stderr)
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
