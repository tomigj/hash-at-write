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

---

## 2026-09-10 — Three bugs in the first implementation, all found by testing

Two reported by the session on `tg` after reading the pushed code, both with
working reproductions. A third found while confirming them. All three were
reproduced here before any fix was written.

### 1. Silence detection was blind to the case that matters

`verifier.py` measured gaps only *between* consecutive chain entries
(`zip(chain, chain[1:])`). Nothing compared the last entry against the present
moment, so a chain that simply **ends** — agent killed and left dead — passed:

    chain=10 log=10 heartbeats=10 -> CLEAN     (agent dead for one hour)

The same gap placed in the interior alerted correctly. So the check only caught
an attacker who politely restarted the agent afterwards, and missed the one who
killed it and walked away. That is backwards from the risk ordering, and it
meant the heartbeat did not close the hole the previous note claimed it closed.

Fixed by also checking the open interval against now, and by treating an empty
chain as SILENCE rather than as a clean run over zero entries.

### 2. One dropped acknowledgement manufactured the signature of an attack

`_push_once` sends a digest and then blocks reading the acknowledgement. If the
ack was lost *after* the ledger committed — ordinary packet loss, and both hosts
are on wifi — the agent retried, and `ledgerd` refused on `seq <= last_seq` and
audited REFUSED_REWRITE. The agent then spooled the digest and `drain_spool`
retried it every interval **forever**, being refused every time: roughly 8,600
REFUSED_REWRITE entries per day from a single lost packet, each one reading as
"the primary is attempting to rewrite the chain."

The evidence was never affected — verification reported CLEAN throughout. Only
the alerting was poisoned, which is worse in a specific way: the failure is
invisible to the check most likely to be run, and loud in the record a reader
would treat as the intrusion log.

Fixed by distinguishing the two cases, which the chain previously could not do
at all. A rewrite is a *different* digest for a recorded sequence. An identical
digest for a recorded sequence is a retransmission, gains an attacker nothing
because the chain is unchanged, and is now acknowledged without appending. Only
a differing digest raises REFUSED_REWRITE. The audit log can now tell a lost
packet from an attack; before, it could not.

### 3. The spool could never be recovered

Found while reproducing the above. `seq <= self.last_seq` refused *any* sequence
at or below the head — including one that had **never been chained**. But that
is exactly what a legitimate spool recovery looks like: the ledger was briefly
unreachable, seq 2 was spooled, seq 3 got through, and seq 2 arrives afterwards.
Refused permanently, and audited as an attempted rewrite:

    seq 2 -> {"error":"seq 2 is at or below chain head 3","ok":false}

So the spool-and-retry mechanism, which exists precisely so that digests are
never silently dropped, could not deliver anything once a later sequence had
been chained. The design contradicted itself.

Fixed: a sequence never chained is accepted regardless of order, because the
chain binds arrival order and the sequence number is only a label. Such entries
are marked `out_of_order` with the head at receipt, `ledgerd` audits
LATE_DIGEST, and the verifier raises it as an alert.

**This is deliberately not silent, and the reason should be stated in the
write-up.** A legitimate late arrival after an outage and a malicious backfill
of a previously unwitnessed record are indistinguishable at the chain: both are
a digest for a sequence the ledger never saw. What separates them is *when the
digest arrived*, which the ledger records and the primary cannot forge. Accepting
them silently would let an attacker convert an UNWITNESSED alert into a clean
verification; refusing them would break outage recovery. Accepting and marking
them keeps both properties and puts the judgement where the evidence is.

### Also changed

A refusal is now marked `permanent` in the response, and the agent moves such
digests to a dead-letter file instead of retrying them forever. Without this,
even a genuine rewrite refusal would have produced the same unbounded audit
spam as bug 2.

### Noted, not yet acted on

- `handle_event` holds the lock across the ledger push, so with the ledger
  unreachable the write path blocks for up to ~8.75s per event and events
  serialise behind it. The T6 overhead figure will therefore be sharply bimodal
  depending on ledger reachability. The measurement must either pin ledger state
  or report both modes; a single mean would be misleading.
- `digest_before_write_us` is positive by construction. It is honest
  instrumentation of this binary's ordering, but it is not independent proof of
  claim 1, and presenting it as proof would be circular. The write-up should
  present it as a timing measurement and rest claim 1 on the code path itself.

---

## 2026-09-10 — Two more holes, both reproduced

Found by the `tg` session reviewing the fixes above, reproduced here before
being fixed. One of them was made materially worse by the bug 3 fix.

### 4. A record's own timestamp was never checked against the ledger's receipt

The log says when a record claims to have happened. The chain says when its
digest arrived. The first is written by the primary and is attacker-controlled;
the second is not. Both files are read on the same verification pass and nothing
compared them.

So a record forged at the next sequence and witnessed normally — genuine digest,
intact chain, in-order sequence — passed every check while claiming a date six
years in the past:

    record claims:   2020-01-01T00:00:00.000Z
    ledger received: 2026-09-10T02:37:21.296Z
    verifier:        CLEAN (exit 0)

This matters for what an audit trail is for. "Was this record altered" is half
the question; "when did this happen" is the other half, and a
reconstructible-but-backdated timeline is the failure mode the retention rules
in NYDFS 500.06 exist to prevent.

Fixed by comparing the two on every chained entry. Backdating beyond
`--max-skew` raises BACKDATED; a record claiming to be written *after* its own
digest was received raises FUTURE DATED, allowing 60s for clock drift between
the hosts. Legitimate skew is bounded by push latency, or by a whole outage if
the digest was spooled — which is why the threshold is configurable and why
recovery after a long outage should be visible when it happens rather than
suppressed.

### 5. One packet with an arbitrary sequence number poisoned the alert stream

`seq` is chosen by the submitter and was unbounded. A single submission:

    {"seq": 999999, "digest": ...}   ->   {"ok": true, "seq": 999999}

pinned the chain head at 999999 permanently. The result was a false DELETION for
a record that never existed, and **every genuine digest thereafter flagged LATE
DIGEST**, because everything now arrived below the head:

    DELETION     seq=999999
    LATE DIGEST  seq=5    digest arrived after the chain had reached seq 999999
    LATE DIGEST  seq=6    digest arrived after the chain had reached seq 999999

One unauthenticated packet, no privilege beyond reaching the port, and the
verifier never returns a clean run again.

The vector pre-existed — high sequences were always accepted — but before the
bug 3 fix the follow-on digests were refused outright, which was a different and
noisier failure. After it they are chained correctly and every one is
mislabelled. This is the same shape as bug 2 one layer up: the evidence stays
intact and the thing a human reads becomes unusable. A system whose alert stream
can be permanently poisoned by one packet does not produce usable evidence, even
though the cryptography is untouched.

Fixed at the ledger, which is the host that is supposed to be trustworthy: a
sequence more than `--seq-window` (default 1000) beyond the current head is
refused and audited as IMPLAUSIBLE_SEQ. An empty chain still accepts any
starting point, so a ledger can be brought up against an agent that already has
history. The verifier additionally says, when a chained sequence exceeds the
log's maximum, that the case is ambiguous between a truncated tail and a digest
for a record that never existed, rather than asserting the stronger claim.

### The heartbeat decision is load-bearing, not cosmetic

The residual after both fixes: stop the agent, append a record at the *next*
sequence, witness it normally with a plausible timestamp, restart. The digest is
genuine, the chain is intact, the sequence is in order, and the timestamp is
credible. Nothing catches it except the receipt gap while the agent was stopped
— which only silence detection reads, and which only exists if heartbeats are
running.

Heartbeats remain off by default pending a decision on the interval, but the
agent now warns loudly at startup when they are disabled and says what is
exposed. A default that quietly leaves this open would be a trap.

---

## 2026-09-10 — Two more, and a fix that was wrong the first time

### 6. The sequence window was walkable

`--seq-window` bounded the size of a single jump, not where the head ended up.
Five submissions 999 apart, one round trip each, walked it from 1 to 4996 with
zero refusals — after which every genuine digest below the head was mislabelled
LATE DIGEST, which for a low-volume audit trail means months. The previous fix
had converted unbounded poisoning into bounded poisoning that could be trivially
re-applied. Not a closure.

Fixed by bounding the gap between the sequence claimed and the number of digests
actually chained, since that gap *is* the count of sequences this ledger has
never seen. A walk inflates it every step and is refused on the second.

One consequence worth recording, not raised in review: these refusals must be
**retryable**, not permanent. After a long outage a genuine new event can
legitimately arrive far ahead of a spool that has not drained. Marking the
refusal permanent would have sent a real digest to the dead-letter file and lost
evidence — the fix for one problem quietly creating a worse one.

### 7. A legitimate outage was reported as forgery

An outage longer than `--max-skew` raised BACKDATED on every recovered record.
Ten alerts, identical in kind to a forgery, produced by a laptop suspending or
wifi dropping. An operator could separate them only by squinting at magnitudes,
which reintroduces in the alerting layer exactly the ambiguity this project
exists to remove.

The discriminator was already on the trustworthy host. A digest spooled while
the ledger was unreachable is late for a legitimate reason; a record claiming to
predate a moment when the ledger was demonstrably receiving normally is not.

**The first attempt at this fix was wrong**, and the way it was wrong is worth
keeping. Comparing each record against the *immediately preceding* chain entry
looked correct and failed completely: entries in a recovery batch all arrive
within milliseconds of each other, so the preceding entry is a batch-mate, not
evidence of liveness at the time the record was written. Every recovered record
still reported BACKDATED. The reference point has to be the last receipt that
was itself prompt.

Where no prompt receipt precedes the record, the alert now says so. From ledger
data alone, an outage that began before the chain did and a backdated record are
indistinguishable, and naming that is better than picking a side.

### Presentation

Durations rendered everywhere in days, so a seven-minute skew printed as
"0.0 days" directly above "2444.1 days". That reads as a broken formatter and
invites a reader to distrust every number on the page. Now scaled: seconds,
minutes, hours, days.

---

## 2026-09-10 — Regression suite

`tests/repro_scenarios.py` and `tests/repro_dropped_ack.py`, written by the
session on `tg` during review and committed here. Six fixtures covering every
failure mode found so far; the proxy reproduces the dropped-acknowledgement
condition against a live ledger.

The suite shells out to the verifier rather than importing it, deliberately: it
exercises the entry point an operator actually runs, so a regression in argument
handling or exit codes shows up too.

Current state: 6/6 produce their expected alert.

Seven reproduced failure modes with scripts is a materially stronger evidence
package than the four scenarios the build spec originally called for, and every
one of them was found by testing rather than by inspection.

---

## 2026-09-10 — The soft label was attacker-inducible

Raised by the `tg` session in answer to a question put to it: is
OUTAGE RECOVERY the useful label, or only the honest one?

Neither, as it stood. From the ledger's position, "I was unreachable" and "the
primary chose not to speak" are the same observation. Under full root the
primary can go quiet deliberately, manufacture the window, and date a forged
record into it — earning the softer label precisely because it created the
condition that excuses it. Demonstrated with five prompt receipts, forty minutes
of deliberate quiet while the ledger stayed up, and a forged "admin login by
nobody in particular" dated inside the attacker's own window.

Two changes:

**The wording asserted more than the ledger knows.** "Consistent with a digest
spooled during an outage" states that an outage occurred. The ledger only knows
it heard nothing. The alert now says no digests were received between two
timestamps and that the lateness cannot be distinguished from a digest withheld
and submitted later. In a filing that is the difference between a finding and an
inference. The alert kind changed from OUTAGE RECOVERY to UNCORROBORATED for the
same reason: the old name asserted the benign reading in the label itself.

**The corroborating fact was in the same pass and went unmentioned.** If the
quiet window excusing a late digest is itself large enough to be reported as
SILENCE, the excuse rests on the primary's own absence. The verifier now says so
inline rather than leaving a reader to connect two unrelated-looking lines.

This is the third finding to land on the heartbeat decision. The exposure is no
longer only the in-order forgery: without heartbeats, the softer alert labels
become attacker-controllable. Heartbeats should be treated as a prerequisite for
any run that produces evidence, not as a tuning parameter.

## 2026-09-10 — Walk: bounded to linear cost, not closed

The gap bound stops the free walk but not one paid for. Filling seqs 2..1000
with real submissions inflates the chained count, after which the jump to 1999
is accepted. Cost rises from one packet per 999 sequences to about a thousand.

Not fixing further. The attack is now self-alerting — every filler digest is for
a record that does not exist, so a 1000-step walk produces 1000 DELETION alerts
— and more machinery would buy little. The honest framing for the write-up is
"raised the cost to linear", not "bounded", and the limitation that the ledger
accepts submissions from whatever can reach the port is now stated in the
README.
