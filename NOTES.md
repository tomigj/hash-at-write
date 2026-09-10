# Build notes

Working notes kept as the work happens: design decisions, things that broke, and
findings that changed the design. Written contemporaneously and not tidied up
afterwards. Where something was wrong, the note says so rather than being edited
to look like it was always right.

---

## Environment

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

## Deviation from the spec's file layout

Added `common/canonical.py`, which is not in the spec's §5 layout.

The digest must be recomputed byte-identically on the ledger host. The spec
handles this by instructing both programs to use the same `json.dumps`
arguments. Two copies of that line can drift; the failure mode is a phantom
TAMPER alert on an untouched record, which is a genuinely nasty thing to debug.
Defining the serialisation once and importing it from both sides removes the
possibility rather than relying on discipline.

---

## Two bugs in the agent, found by smoke test

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

## Finding: the spec's verification loop is one-directional

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

## Finding: what the SSH forced command actually protects

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

## Heartbeat, added but disabled by default

Consequence of the finding above. Even with `UNWITNESSED` detection, a stopped
agent produces a window in which nothing is witnessed at all. A liveness beat on
a fixed interval makes that silence a detectable condition.

Implemented as a reserved event string, so beats are ordinary records that hash
and chain like any other and the chain format is unchanged. Silence detection
uses **the ledger's own receipt timestamps**, never the log's, because the log's
timestamps are written by the primary and are attacker-controlled.

Off by default (`--heartbeat-interval 0`) pending a decision on the interval.

---

## Three bugs in the first implementation, all found by testing

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

## Two more holes, both reproduced

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

## Two more, and a fix that was wrong the first time

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

## Regression suite

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

## The soft label was attacker-inducible

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

## Walk: bounded to linear cost, not closed

The gap bound stops the free walk but not one paid for. Filling seqs 2..1000
with real submissions inflates the chained count, after which the jump to 1999
is accepted. Cost rises from one packet per 999 sequences to about a thousand.

Not fixing further. The attack is now self-alerting — every filler digest is for
a record that does not exist, so a 1000-step walk produces 1000 DELETION alerts
— and more machinery would buy little. The honest framing for the write-up is
"raised the cost to linear", not "bounded", and the limitation that the ledger
accepts submissions from whatever can reach the port is now stated in the
README.

---

## The design boundary: fabrication is not detectable

Raised by the `tg` session, reproduced here against the live stack rather than a
fixture — real agent, real ledgerd, real push path, every check enabled.

Every backdating case tested so far involves the attacker lying about *when*. If
they do not lie about when, nothing fires. Stop the agent, append one fabricated
record with a truthful current timestamp, push its digest through the normal
path, restart:

    record: {"seq":6, "event":"Accepted publickey for root from 10.0.0.1"}
    verifier --max-silence 60 --max-skew 300:
    chain=7 log=7 heartbeats=1 -> CLEAN     exit 0

Genuine digest, intact chain, in-order sequence, truthful timestamp. No
BACKDATED, no UNCORROBORATED, no UNWITNESSED, no SILENCE.

**This is not a defect. It is the edge of what the design can do**, and it is
categorically different from everything else in this file. The other findings
were implementation bugs with fixes. This one has no fix within the approach: a
record fabricated on the primary and witnessed at write time is byte-identical,
in every property the system checks, to a genuine one. The attacker is not
tampering with evidence at that point; they are producing it.

Heartbeats shrink the insertion window but do not close it. See the correction
below for what actually bounds it — the first version of this claim named the
wrong parameter.

The README's out-of-scope line covered *omission* ("if the application never
emits an event, nothing here helps"). Omission and insertion are different
failures and it did not cover the second. A reader seeing "tamper-evident audit
logging" will reasonably assume a fabricated entry is caught. It is not.

Now stated in the threat model rather than only here, because for a filing this
matters more than any bug fixed so far: everything else was a defect in the
implementation, and a reviewer who finds *this* unstated will discount the parts
that do work. Stating it also sharpens the real claim — the system establishes
that a record has not been altered or removed since it was witnessed, which is
precise, defensible and still worth having.

**Correction to an earlier report:** the previous limitations commit was
described as adding five bullets to the README. It added four — flat subnet,
open port, linear-cost walk, and lateness without heartbeats. Recorded because
the standard being held everywhere else applies to reports about the work too.

---

## Correction: a "Verified" claim that did not hold

The Known limitations bullet added for fabrication stated: "a fabricated SSH
authentication with a truthful timestamp, inserted during an eight-second stop
with heartbeats at two seconds, produced no alert of any kind."

That result was real but the configuration was not stated, and under the
configuration a reader would assume, it is false. The run used
`--max-silence 60`. An eight-second stop is well below a sixty-second threshold,
so nothing fired — that is a threshold set above the stop length, not a
demonstration that the stop is undetectable. Caught by the `tg` session,
rechecked here against the live stack:

    heartbeats 2s, --max-silence 6, agent stopped 8s:
      SILENCE seq=6->7  10s with no digests received (threshold 6.0s)   exit 1

    heartbeats 2s, --max-silence 6, agent stopped 1s, fabrication inserted:
      chain=8 log=8 heartbeats=4 -> CLEAN                               exit 0

So the eight-second insertion IS detected at a workable threshold. The one that
demonstrates the limitation is a stop shorter than the threshold.

**The claim also named the wrong parameter.** The undetectable window is bounded
by the *silence threshold*, not the heartbeat interval. The two are only loosely
coupled: the threshold cannot go below the heartbeat interval plus normal jitter
without false positives, so the interval sets a floor on how tight the threshold
can be, and the threshold is what an attacker must fit inside. With beats at 2s,
a 6s threshold is workable, so the window is about six seconds — not two.

None of this weakens the finding. Fabrication is undetectable in principle, and
a scripted insertion inside a few seconds is entirely practical. The threat-model
paragraph was correct as written and is unchanged. It was one sentence, and it
was the one sentence in that bullet a reviewer could falsify in a minute by
rerunning it with a tuned threshold.

Recorded rather than quietly edited, because a stated result that does not hold
under the stated configuration is precisely the failure this project exists to
make impossible. It should not appear in this project's own README.

### Reproduction notes for the fabrication result

Both stated configurations were independently rerun on `tg`'s live stack and
agree with the runs here. Two things will trip up anyone reproducing it.

**A trailing SILENCE appears if you verify after stopping the agent.** The
open-interval check compares the last receipt against *now*, so verifying a few
seconds after the harness has stopped the agent for good produces
`SILENCE seq=N->now`. That is the harness ending with a dead agent, not
detection of the fabrication. Verify while the agent is still running, or expect
to read past it. In both the 1s and 8s cases the *insertion* gap is silent.

**The measured gap runs longer than the stop.** An 8-second stop shows as a
10-second gap, because the last beat before the stop can be up to a full
interval old when the stop begins, and the first beat after restart arrives an
interval later still. Anyone measuring "eight seconds" and reading ten has not
found a discrepancy.

This also refines the attacker's arithmetic, in the design's favour. The window
is not the threshold; it is the threshold minus up to one beat interval, because
that slack is added to the gap for free. At 2s beats and a 6s threshold the real
room is about four seconds, not six. Small, but it is the number an attacker
would actually compute, and it is the number to use rather than the more
generous one already written.

The evidence position is also better than either host had alone: the runs here
are against the live stack, and `tg` reproduced them independently from its own
harness. Fixtures prove what the fixture builder does; two live stacks agreeing
is a different quality of claim.

---

## `systemctl is-active ssh` was the wrong check, on both hosts

Step 1 surfaced this on `tg`, and checking the same thing here showed it had
also been wrong in the opposite direction on `daddy`. Recorded in full because
it is the third instance of the same class of error in this build: a true
observation carried forward as support for a conclusion it did not support.

The original environment sweep on both hosts used:

    systemctl is-active ssh sshd    ->    inactive / inactive

That output was accurate and meant two completely different things.

**On `tg` it meant the unit does not exist.** `openssh-server` has never been
installed — `dpkg -l` shows `un`, there are no ssh unit files, and
`/usr/sbin/sshd` is absent. Step 1's `systemctl enable --now ssh` failed with
"Unit file ssh.service does not exist." The spec's step 1 had been written
assuming a service that merely needed enabling.

**On `daddy` it meant the service is socket-activated and currently listening.**
`openssh-server` is installed, `ssh.socket` is enabled, and the host is
accepting connections on `0.0.0.0:22` and `[::]:22`. `ssh.service` reads
inactive until a connection arrives, which is exactly what socket activation
does. So the ledger host has had an open SSH listener throughout.

That matters beyond tidiness. The evidence instruction issued for step 1 said
sshd must stay inactive on the ledger, using `systemctl is-active` as the test,
and named that as what makes claim 4 real — the primary having no inbound path
to the evidence host. Under that test the ledger passes while listening on every
interface. Had the capture been taken and filed, `evidence/` would have recorded
a false statement about the property the whole design rests on.

`systemctl is-active` cannot distinguish "no such unit" from "socket-activated
and listening". The checks that can:

    dpkg -l openssh-server                       # installed at all?
    systemctl list-unit-files | grep -E '^ssh'   # units, including .socket
    ss -tlnp | grep ':22 '                       # actually listening?

The last is the only one that answers the question the threat model asks. What
matters is not whether a unit is enabled but whether anything is bound to the
port. Both hosts' environment sweeps should have included it, and the evidence
protocol now requires it.

**Ordering note, in the build's favour.** Bringing ufw up before sshd was a
departure from the spec's step order. It pays off on `tg`: installing
`openssh-server` now starts a daemon behind an already-active deny-incoming
firewall carrying a single 10.0.0.212 rule, with no exposure window. `tg` has
four globally routable IPv6 addresses and a default v6 route, and the allow rule
is IPv4-only, so inbound v6 SSH is denied by policy rather than by luck. Run in
the original order on a host where the package needed installing, the daemon
would have come up on a public v6 address ahead of any firewall.

### Correction and clarification

Two updates to the entry above, both from the operator completing step 1 on `tg`.

**The `un` dpkg state was accurate at 03:35 and is now stale.** The operator
installed `openssh-server`; `tg` now has it at 1:9.6p1-3ubuntu13.19 with the
daemon listening.

**`ssh.service` reading `inactive` and `disabled` on `tg` is correct, not a
failure.** Ubuntu 24.04 ships SSH socket-activated: `ssh.socket` is enabled and
holds the listener, `ssh.service` is spawned per connection. So the earlier
diagnosis was right about `daddy` — socket activation, listening — and the same
mechanism applies on `tg` now that the package is present. The check
`systemctl is-active ssh` will report `inactive` on both hosts forever while SSH
works perfectly.

This must not be "fixed" by running `systemctl enable --now ssh.service`.
Doing so conflicts with the socket, disables socket activation, and moves the
host off the distribution default — altering a configuration that is itself
evidence, to make a status line read differently.

**Capture protocol changed as a result.** `ufw status numbered` does not print
default policies, so evidence showing one IPv4 allow rule beside a daemon
listening on a public IPv6 address does not, on its face, show that v6 is
denied. `ufw status verbose` prints `Default: deny (incoming), allow (outgoing)`
and is now required in every firewall capture on both hosts.

---

## Step 2 on the primary, and the startup warning's first catch

The operator started the agent before pulling, on a revision predating the
heartbeat default. The warning fired:

    [!] heartbeats DISABLED: a stopped agent leaves no detectable gap, so a
        record forged at the next sequence and witnessed normally will verify
        clean.

The run was halted. Without that warning it would have completed, produced twenty
clean records, and been filed as step 2 evidence for a configuration the operator
had not chosen — and specifically for the one configuration under which a record
forged at the next sequence verifies clean.

It was added on the reasoning that shipping a known-exploitable default silently
would be a trap. It caught a real misconfiguration within hours, on the first run
of the code on the machine it was written for. Recorded because "we added a
warning" and "the warning prevented something" are different claims and only the
second is worth anything.

The superseded records are archived on the primary rather than deleted. Not wrong
data, superseded configuration.

### Overhead, preliminary — the hash is not the cost

22 samples on the primary, SSD:

    hash_us                    median   131.1µs      1.73% of total
    digest_before_write_us     median  3060.3µs     50.06% of total
    state_us                   median  3530.4µs     48.18% of total
    total_us                   median  6921.9µs

This confirms the suspicion recorded earlier from a much smaller sample on the
ledger host, at a considerably larger ratio, and it splits into two parts that
must not be conflated:

The log write and its fsync is **not** attributable to this design. Any audit
logger whose records must survive a power cut pays it.

The state-file persist **is** — an atomic temp-write, fsync and rename per event
so the sequence is recoverable. It roughly doubles the fsync cost and is the
largest attributable overhead in the system. It is also addressable independently
of the hash-at-write property, for instance by persisting every N events and
recovering the remainder from the log's last line, which the agent already does
on startup.

The hash is under 2%, most of it interpreter time rather than SHA-256.

**This does not retire the README's "overhead not yet measured" limitation.** n=22
is a smoke test with a 5.2x spread; T6 needs orders of magnitude more samples and
percentiles rather than means. The temptation to close a known limitation on the
first favourable number is exactly what the truthfulness rule is for.

---

## Overhead: the hash is not the cost, the synchronous push is

Recorded before T6 runs, deliberately. T6 measures per-event overhead, and
without this note its number will be read as the cost of hashing. It is not.

Live push timings from the primary, six samples, real network:

    push_us  min 7342  med 77177  max 96173      pushed=true on 6 of 6
    ICMP to the ledger at the same time:  avg 5.9ms

The distribution is bimodal: two samples at 7-9ms, four at 76-96ms.

**The ledger's fsync is not the cause.** Measured here, 50 samples on the same
NVMe filesystem as chain.jsonl: median 919µs. So `Chain.submit`'s
write-flush-fsync-before-acknowledging contributes about a millisecond. The
append-only attribute does not make it expensive.

The budget closes on the fast mode:

    RTT ledger to primary        ~6-8ms
    ledger fsync                 ~0.9ms
    expected                     ~7-9ms
    observed fast mode            7.3ms, 8.6ms

So the fast pair is the correct cost of an acknowledged durable write across this
LAN, and the slow mode is the outlier — roughly 70ms of unexplained latency on a
radio that has been idle for the 60 seconds between heartbeats. Wifi power-save
wakeup fits the bimodality; fsync variance does not. A back-to-back run with no
idle gap will settle it.

### The per-event picture, combining both hosts' measurements

    SHA-256 + canonical JSON       ~130µs      1.7%    inherent, negligible
    log write + fsync              ~3.1ms              any durable logger pays this
    state-file persist             ~3.5ms              this design's addition
    synchronous acknowledged push   ~6ms      43%     this design's addition, largest

The README currently says "Hashing in the write path imposes overhead on the
logging host. Not yet measured." The measurement says hashing is not the
overhead. It is 1-2%. The synchronous acknowledged push is the largest single
component at 43%, with the two local fsyncs together making up most of the rest.

That is a considerably more useful thing to tell a prospective adopter than a
single aggregate number, and it is a better answer than the limitation implies:
the expensive parts are engineering choices that can be revisited, while the part
that is inherent to hash-at-write is negligible.

### Correction: those figures measured an idle radio, not the architecture

The paragraphs above were computed from six samples taken 60 seconds apart --
which is to say, six radio wakeups. They reported a throughput ceiling of 9-12
events/sec and a push share of 80-95%. Both are wrong as statements about the
design. They describe the wifi power-save behaviour of an idle laptop.

A back-to-back run of 50 events with no idle gap settles it:

    50 events in 0.832s -- 60.1 events/sec, 16.6 ms/event
    push_us   min 3985  p25 5306  med 5966  p75 7581  max 49594
    total_us  min 11333 p25 12760 med 13806 p75 16194 max 58062
    over 50ms: 0 of 50

In arrival order the first event pays 49594us and every one after it collapses
into a 4-8ms band. One wakeup, then nothing. The median push of 5966us sits just
under the 7-9ms the RTT-plus-fsync budget predicted, so that budget closes even
more tightly than it did on six samples.

Corrected, warm-radio:

    throughput      60.1 events/sec       not 9-12
    push share      5966/13806 = 43%      not 80-95%
    hash share      138/13806 = 1.0%      consistent with the 1.7% measured earlier
    remainder       ~7.8ms = 56%          log fsync + state fsync

### Both regimes are real and the write-up needs both

    isolated event, idle radio     ~90-110ms latency     what an occasional event costs
    sustained burst, warm radio    ~14ms, 60/sec         what volume costs

A production audit log with continuous traffic lives in the second regime. A
quiet system where events arrive minutes apart lives in the first, and every
event pays a wakeup. Reporting only one misleads, in opposite directions
depending which is picked. T6 must therefore state the traffic pattern it
measured, not only the numbers.

### The architectural consequence, which survives but shrinks

`handle_event` holds `self.lock` across `_push_with_retry`. The push remains the
largest single attributable component at 43%, and the write path is still
serialised behind the network. But at 60 events/sec, comparable to the two local
fsyncs rather than dwarfing them, this is a design question rather than a
throughput crisis, and it should be framed that way.

The open design question, stated rather than quietly fixed mid-build: must the
push happen inside the lock? The digest is already durable on disk before the
push is attempted — that is what makes the spool safe. So the digest could be
queued and pushed by the drainer, making the spool the normal path rather than
the failure path, and taking the network out of the write path entirely.

The cost of that change is a widened window between a record being written and
its digest reaching the ledger, which is exactly the interval this project exists
to shrink. It would need stating precisely rather than being treated as free.
Not changing it now; recording it as the question T6's results will raise.

---

## Systemd units, and a security property that fell out of writing them

Three units and a timer: the agent on the primary, ledgerd and a periodic
verifier on the ledger.

### RuntimeDirectory answers the question deferred at step 2

The agent's socket belongs under /run, but /run is root-owned, so the agent
cannot create its own directory there. Step 2 sidestepped this by putting the
socket in /var/lib/integrity, with a note that the real answer was
`RuntimeDirectory=`. It is: systemd creates /run/integrity at start with the
declared ownership and mode, and removes it at stop. No manual mkdir, and nothing
left behind that has to be cleaned up by hand.

### Restart=on-failure narrows the fabrication window

Not inherited from a template — it has a consequence specific to this threat
model.

The residual attack recorded earlier is: stop the agent, append a record at the
next sequence with a truthful timestamp, witness it normally, restart. The window
an attacker must fit inside is bounded by the verifier's silence threshold.

Under systemd, killing the process gets it back within RestartSec. To hold it
down the attacker must use `systemctl stop` or mask the unit — both of which
leave a journal record. That does not close the hole, and nothing can while a
root attacker can write records the agent would have written anyway. But it
raises the cheapest version of the attack from `kill` to an action that is both
harder and noisier, and the difference is worth stating.

### The verifier's exit code is a monitoring interface, and it was ambiguous

The verifier returned 0 for clean and 1 for everything else, so a systemd unit
went failed identically whether tampering had been detected or the verifier
itself had broken. Those mean opposite things about the system's health, and an
operator who cannot tell them apart has exactly the ambiguity this project exists
to remove — reproduced in the monitoring layer.

Separated:

    0  clean
    1  alerts raised — the system worked and found something
    2  verification could not be completed

An unreachable primary stays at 1 rather than 2. It is a genuine finding, not a
malfunction: the ledger could not see the log, and that is worth alerting on.
Verified reachable: a corrupt or missing chain file now exits 2, a run with
alerts exits 1, a clean run exits 0.

### Timer interval is a stated trade, not a default

`OnUnitActiveSec=5min` sets how long tampering can sit undetected: up to one
interval. Shortening it narrows that window at the cost of pulling the whole log
over SSH more often, which is O(log size) per run. On a production-sized log that
cost is the reason not to simply set it to a minute, and the write-up should say
so rather than presenting five minutes as a neutral default.

`Persistent=true` means a run missed while the host was off happens at next boot.
A gap in verification is precisely when tampering would be attempted, so a missed
run should be made up rather than skipped.

### Repository paths differ between the hosts

The primary has the repo at ~/witnessd, the ledger at ~/NIW. The unit files carry
absolute paths and therefore differ per host. Noted in each unit rather than left
for someone to discover from a failed start.

## Deliberate downtime is permanently visible in the chain, and that is correct

After restarting the agent, verification reports:

    SILENCE  seq=58->59  37.9 minutes with no digests received (threshold 180s)

That gap is the deliberate stop for T2, T3 and T3b — the agent was down from
05:11:5x to 05:48:09 while the log was being edited. The receipt timestamps of
seq 58 and seq 59 are in the chain, they are append-only, and the interval
between them is therefore permanent. **Every future verification of this chain
will report that gap.**

This is a property, not a defect, and it is worth stating in the write-up because
it cuts both ways.

In its favour: downtime cannot be hidden. An attacker who stops the agent leaves
a gap in the ledger's receipt timeline that no subsequent action on the primary
can remove, because the primary cannot write to the chain. The record of the
silence outlives the silence.

Against it: a long-running deployment accumulates historical gaps that alert on
every run forever. Every maintenance window, every reboot, every network outage
becomes a permanent line in the verification output. That is alert fatigue by
construction, and an operator who learns to skim past SILENCE lines has been
trained by the system to ignore exactly the signal that catches the fabrication
attack.

The design does not currently address this. Options, none implemented:

  - acknowledge a gap explicitly, recording the acknowledgement in the chain so
    the annotation is itself witnessed rather than kept in an operator's notes
  - report gaps only since a stated point, with the point recorded
  - distinguish gaps that overlap a declared maintenance window, which requires
    declaring them in advance and chaining the declaration

All three amount to the same thing: an operator must be able to say "this gap is
accounted for" in a way that is itself part of the evidence. Left unaddressed the
system is correct and progressively less usable, which is a worse failure mode
than being wrong, because it degrades quietly.

Practical consequence for the test protocol: this chain cannot produce a CLEAN
run at the default threshold again. T4, the false-positive check, must therefore
be run at --max-silence 0 to isolate what it is actually testing, with the
historical gap reported separately and labelled as the known consequence of the
deliberate stop.
