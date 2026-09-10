#!/usr/bin/env python3
"""
emitter -- event source for the hash-at-write agent. Runs on `primary`.

Stands in for an application producing auditable events. Three modes:

  --message   one event, useful for smoke tests
  --count     N synthetic events, used for T1 volume and T6 timing
  --tail      follow a real log and forward genuine events

The --tail mode matters for the test protocol. T4 is the false-positive check:
real SSH authentications, produced by actually logging in, must flow through the
same path as synthetic ones and produce no alerts. Synthetic events alone would
not demonstrate that, because they never exercise a real event source.

Targets Python 3.12 (the floor across both hosts). Standard library only.
"""

import argparse
import json
import os
import socket
import sys
import time

# Lines worth treating as auditable authentication events.
#
# This is NOT SSH-only, and describing it that way would misstate what gets
# captured. "session opened for user" and "session closed for user" are PAM
# messages, so they match sudo, cron and systemd-user sessions as well as sshd.
# In practice a single SSH connection produces five matching lines: the
# accepted-publickey line, the sshd session opening and closing, and the
# systemd-user session opening and closing.
#
# The breadth is kept deliberately. An audit trail that recorded only SSH would
# miss privilege escalation via sudo and anything scheduled through cron, and
# those are exactly the events an investigation cares about. But the write-up
# must describe the captured set as authentication and session events, of which
# SSH is a subset -- not as "SSH logins".
AUTH_MARKERS = (
    "Accepted password",
    "Accepted publickey",
    "Failed password",
    "Invalid user",
    "session opened for user",
    "session closed for user",
    "authentication failure",
)


class Emitter:
    def __init__(self, sock_path, quiet=False):
        self.sock_path = sock_path
        self.quiet = quiet
        self.conn = None
        self.stream = None

    def connect(self):
        self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.conn.connect(self.sock_path)
        self.stream = self.conn.makefile("rw", encoding="utf-8")

    def send(self, event):
        """Send one event and return the agent's reply.

        The reply carries the digest the agent computed, so the emitter can see
        that hashing happened in-band rather than assuming it.
        """
        self.stream.write(json.dumps({"event": event}) + "\n")
        self.stream.flush()
        reply = self.stream.readline()
        if not reply:
            raise OSError("agent closed the connection")
        result = json.loads(reply)
        if not self.quiet:
            if result.get("ok"):
                digest = result.get("digest")
                short = (digest[:16] + "...") if digest else "NO DIGEST (--no-hash)"
                pushed = result.get("pushed")
                mark = {True: "pushed", False: "SPOOLED", None: "local"}[pushed]
                print(f"seq {result['seq']:>6}  {short}  {mark}")
            else:
                print(f"[error] {result}", file=sys.stderr)
        return result

    def close(self):
        if self.stream:
            self.stream.close()
        if self.conn:
            self.conn.close()


def follow(path):
    """Yield new lines appended to `path`, surviving log rotation.

    Rotation is detected by comparing the inode of the open handle against the
    inode currently at the path. Without this the emitter would silently stop
    producing events after logrotate runs -- which would look exactly like "no
    authentications happened", the ambiguity this whole project is about.
    """
    fh = open(path, encoding="utf-8", errors="replace")
    fh.seek(0, os.SEEK_END)
    inode = os.fstat(fh.fileno()).st_ino
    try:
        while True:
            line = fh.readline()
            if line:
                yield line.rstrip("\n")
                continue
            time.sleep(0.25)
            try:
                if os.stat(path).st_ino != inode:
                    fh.close()
                    fh = open(path, encoding="utf-8", errors="replace")
                    inode = os.fstat(fh.fileno()).st_ino
                    print(f"[info] {path} rotated, reopened", file=sys.stderr)
            except FileNotFoundError:
                time.sleep(1.0)
    finally:
        fh.close()


def main():
    p = argparse.ArgumentParser(description="event source for the hash-at-write agent")
    p.add_argument("--socket", default="/run/integrity/agent.sock")
    p.add_argument("--message", help="send a single event and exit")
    p.add_argument("--count", type=int, help="send N synthetic events")
    p.add_argument("--interval", type=float, default=0.0,
                   help="seconds between synthetic events (default: as fast as possible)")
    p.add_argument("--prefix", default="synthetic event",
                   help="text prefix for synthetic events")
    p.add_argument("--tail", metavar="PATH",
                   help="follow a log file and forward authentication events "
                        "(typically /var/log/auth.log)")
    p.add_argument("--all-lines", action="store_true",
                   help="with --tail, forward every line rather than only "
                        "authentication events")
    p.add_argument("--quiet", action="store_true", help="suppress per-event output")
    p.add_argument("--time", action="store_true",
                   help="report elapsed time and events/sec on exit (T6)")
    args = p.parse_args()

    if not any((args.message, args.count, args.tail)):
        p.error("choose one of --message, --count or --tail")

    em = Emitter(args.socket, quiet=args.quiet)
    em.connect()
    started = time.perf_counter()
    sent = 0

    try:
        if args.message:
            em.send(args.message)
            sent = 1

        elif args.count:
            for i in range(1, args.count + 1):
                em.send(f"{args.prefix} {i}/{args.count}")
                sent += 1
                if args.interval:
                    time.sleep(args.interval)

        elif args.tail:
            print(f"following {args.tail} -- generate SSH logins to produce events",
                  file=sys.stderr)
            for line in follow(args.tail):
                if args.all_lines or any(m in line for m in AUTH_MARKERS):
                    em.send(line.strip())
                    sent += 1

    except KeyboardInterrupt:
        pass
    finally:
        elapsed = time.perf_counter() - started
        em.close()
        if args.time and sent:
            print(f"\n{sent} events in {elapsed:.3f}s "
                  f"({sent / elapsed:.1f} events/sec, "
                  f"{elapsed / sent * 1000:.3f} ms/event)", file=sys.stderr)


if __name__ == "__main__":
    main()
