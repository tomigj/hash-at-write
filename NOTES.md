# Build notes

Working notes kept as the work happens: design decisions, things that broke, and
findings that changed the design. Written contemporaneously and not tidied up
afterwards. Where something was wrong, the note says so rather than being edited
to look like it was always right.

---

## 2026-09-10 — Environment

Two physical hosts, both laptops belonging to the same user:

| role | host | address | OS | Python |
|---|---|---|---|---|
| `primary` | `tg` (Samsung 940Z5L) | 10.0.0.173 | Ubuntu 24.04.4 LTS | 3.12.3 |
| `ledger` | `daddy` | 10.0.0.212 | Ubuntu | 3.14.4 |

**The two hosts run different Python minor versions.** All code is written to
the 3.12 floor, standard library only, so the same source runs unmodified on
both. Recorded because a version split is exactly the kind of thing that
produces an unreproducible result months later.

**Both hosts are on one flat /24 over wifi**, same DHCP router at 10.0.0.1, both
administered by the same person. The README's threat model assumes "a separately
administered host on a different network segment"; this lab does not instantiate
that. Segmentation is enforced by ufw rules and SSH configuration only. Neither
laptop has a wired NIC (`tg` has no ethernet PCI device at all — confirmed via
`lspci`, `/sys/class/net` and `lsusb`), so a direct private-/30 link was not
available at build time. USB-ethernet adapters are being obtained; the network
step will be redone and its evidence re-captured once they arrive.

`sudo` on `tg` requires a password, so no step involving firewall rules, sshd or
account creation can be run unattended there.

---

## 2026-09-10 — Deviation from the spec's file layout

Added `common/canonical.py`, which is not in the spec's §5 layout.

The digest must be recomputed byte-identically on the ledger host. The spec
handles this by instructing both programs to use the same `json.dumps`
arguments. Two copies of that line can drift; the failure mode is a phantom
TAMPER alert on an untouched record, which is a genuinely nasty thing to debug.
Defining the serialisation once and importing it from both sides removes the
possibility rather than relying on discipline.

---

## 2026-09-10 — Two bugs in the agent, found by smoke test

1. **`push_us` in the timing log silently included the state-file fsync**, so it
   overstated the cost of the ledger push. Caught when the number looked too
   large in `--no-push` mode, where the push cost should have been ~0. Split
   into `state_us` and `push_us`. A mislabelled figure in an exhibit is worse
   than no figure.

2. **No SIGTERM handler**, so the agent left a stale Unix socket behind when
   stopped. A leftover socket file makes the next start look alive to clients
   while nothing is listening — clients get `ECONNREFUSED` against a socket that
   exists. Would have recurred on every `systemctl restart`. Added a handler
   that unlinks on the way out.

Observed while measuring: **the atomic sequence-persist fsync costs more per
event than the hashing does** — roughly 140–300µs versus 7–140µs, and most of
the latter is Python interpreter overhead rather than SHA-256, which is
sub-microsecond on a ~100-byte record. If the T6 overhead figure comes out high,
this is the cause, and it is addressable independently of the hash-at-write
property.

---

## 2026-09-10 — Finding: the spec's verification loop is one-directional

Raised by the second Claude session working on `tg`, checked against the spec
text, and confirmed.

Spec §3.4 defines verification as: for each ledger entry, find the log record
with matching `seq`. That loop only ever walks the ledger, so **a record present
in the log with no corresponding chain entry is never examined.**

Under the stated threat model (full root on `primary`) this is the cheapest
attack available and defeats no cryptography:

    kill the agent  →  append arbitrary records to events.log  →  restart it

The agent recovers its sequence number from the log's last line and continues.
The chain remains internally consistent. Every check in the original spec passes
clean. An attacker can therefore insert fabricated entries — or omit a real
event and insert a benign substitute — with no alert raised. This reproduces,
inside the design, precisely the ambiguity the README exists to eliminate.

**Fix:** iterate both directions. Records in the log with no chained digest now
raise `UNWITNESSED`. Demonstrated: chain=10, log=12, two UNWITNESSED alerts at
seq 11 and 12.

This closes a hole that was in the design before any code was written. It should
be reflected in the claim list and gain its own scenario in the test protocol.

---

## 2026-09-10 — Finding: what the SSH forced command actually protects

Spec §3.4 states "The forced command is what makes claim 4 real." That is
imprecise and the write-up should not repeat it.

The forced command lives in `primary`'s `authorized_keys`, on the host the
threat model assumes is fully compromised. A rooted `primary` can replace it and
serve doctored content to the verifier. The design survives that — doctored
content fails against digests that left the machine at write time — but the
property therefore comes from *where the digests are*, not from the SSH
restriction.

The forced command remains worth having as least privilege for the ledger's
access into the primary. It is not an integrity control.

What is actually load-bearing for claim 4 sits on the ledger: no verb that
reads, rewinds or rewrites the chain, and no inbound SSH path from `primary` at
all. `ledgerd` is built accordingly — a single submit verb, an acknowledgement
that carries no chain state back, and refusal of any `seq` at or below the
current chain head, so replay and rewrite attempts are rejected and audited
rather than accepted.

---

## 2026-09-10 — Heartbeat, added but disabled by default

Consequence of the finding above. Even with `UNWITNESSED` detection, a stopped
agent produces a window in which nothing is witnessed at all. A liveness beat on
a fixed interval makes that silence a detectable condition.

Implemented as a reserved event string, so beats are ordinary records that hash
and chain like any other and the chain format is unchanged. Silence detection
uses **the ledger's own receipt timestamps**, never the log's, because the log's
timestamps are written by the primary and are attacker-controlled.

Off by default (`--heartbeat-interval 0`) pending a decision on the interval.
