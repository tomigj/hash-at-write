# hash-at-write

**Tamper-evident audit logging for institutions that can't afford a dedicated appliance.**

A log integrity approach that computes a cryptographic digest of each audit record in the same
operation that produces the record, chains those digests on a host the logging system cannot
write to, and continuously verifies that the record has not been altered or removed.

---

## Status

**Design and specification published. Reference implementation in progress.**

This repository currently contains the architecture, threat model, verification method and test
protocol. Working code and test results will follow. The roadmap below tracks what exists.

I would rather publish a design that can be reviewed than wait until everything is finished.
If the approach is wrong, I would like to know before I build more of it.

---

## The problem

Audit logs are treated as evidence and stored like ordinary files.

On a typical host, the process that writes the log, the account that administers the host, and
anyone who obtains that account's privileges can all modify or delete entries after the fact.
Nothing in the file records that this happened.

Where integrity protection exists, it is usually applied after the fact — a signature or hash
computed over a completed log file at rotation, or on a batch schedule. This protects the wrong
interval. Between the moment an entry is written and the moment the file is signed, the entry is
unprotected, and an edit made inside that window is subsequently signed as though it were
genuine. The signature ends up certifying the altered record.

The practical consequence for a regulated institution is specific: it cannot distinguish
*"no one accessed that record"* from *"the evidence that someone did was removed."* Those are
opposite facts and they look identical. Every audit finding, examination response and incident
scope determination downstream inherits the ambiguity without anyone knowing it is there.

Attackers know this. The 2016 attacks on banks connected to the SWIFT network used purpose-built
malware to suppress and alter the local record of fraudulent transfers so the transfers would not
be noticed. Post-incident reviews of large breaches routinely describe missing or unreliable logs
as the reason scope could not be established.

---

## Threat model

**Assumed:** full compromise of the log-producing host, including root. The attacker can read,
rewrite or delete any file on that machine, stop any process, and remove any filesystem
attribute.

**Not assumed:** simultaneous compromise of a separately administered host on a different network
segment.

This assumption is the whole design. Filesystem permissions, append-only attributes and
write-protected directories are all worth having, but none of them survives root on the machine
that holds the log. Integrity has to rest on something the compromised host cannot reach.

**Out of scope:** confidentiality of log contents, log completeness at the source (if the
application never emits an event, nothing here helps), and wholesale rollback of the ledger host
itself. The last of these is addressed by external anchoring — see the roadmap.

---

## Approach

Three properties.

### 1. Hash at write

The digest is computed within the same operation that produces the entry, before it reaches
disk, rather than afterwards by a separate process.

This is the part that matters. Conventional log signing leaves a window — often minutes, often
a full rotation period — in which an entry exists unprotected. Computing the digest in the write
path removes the window rather than shortening it.

### 2. Chained digests

Each digest is bound to the digest of the entry before it:

```
chain_hash[n] = SHA256(digest[n] || chain_hash[n-1])
chain_hash[0] = 0000...0000
```

Altering or removing an entry invalidates that entry and every entry after it, up to the current
chain head. Concealing a single edit requires rewriting the entire subsequent chain.

### 3. Split custody

The chain lives on a separate, network-segmented host. Digests travel to it on a write-only
path. The logging host has no route to read, alter or delete what is stored there.

Verification runs in the opposite direction: the ledger host retrieves log content over a
read-only channel and recomputes the digest itself. The host under suspicion is never asked to
attest to its own integrity — under the threat model, it may be lying.

---

## Architecture

```
  ZONE 1 (exposed)                          ZONE 2 (restricted)

  ┌────────────────────┐                    ┌────────────────────┐
  │  Application       │                    │                    │
  │        │           │   digests only     │  Ledger node       │
  │        ▼           │  ───────────────▶  │  - chains digests  │
  │  Hashing agent     │   (write-only)     │  - retains chain   │
  │        │           │                    │                    │
  │        ▼           │   log content      │  Verifier          │
  │  events.log        │  ◀───────────────  │  - recomputes      │
  │                    │   (read-only)      │  - alerts          │
  └────────────────────┘                    └────────────────────┘

  holds the logs                            holds the evidence
  never holds digests                       never holds the logs
```

Neither host can produce a clean history on its own. That is the property.

The read-only channel is enforced by an SSH forced command restricted to reading the log file —
no shell, no port forwarding, no other command. The write-only channel is a single listening port
on the ledger node accepting connections from the log host only.

---

## What this is not

Cryptographic protection of audit records is not a new idea, and this project claims no new
cryptography.

Hash-chained and forward-secure audit logging has a literature going back to the late 1990s
(Schneier & Kelsey). Signed syslog is standardised in RFC 5848. Merkle-tree transparency logs are
widely deployed. Commercial keyless signature services, write-once storage and enterprise SIEM
integrity modules all exist and work.

**What is different here is engineering and reach, not primitives:**

- **Where the hash is taken.** In the write path rather than over a completed file. Most deployed
  approaches accept the exposure window; this one doesn't.
- **Who holds what.** Custody of the record and custody of the evidence about the record are
  separated across hosts over a one-way path. Many implementations keep both on the same machine,
  which defeats the purpose against a privileged attacker.
- **What it costs to adopt.** Commodity hardware, no appliance, no SIEM replacement, no licence.
  The existing options are priced and scoped for institutions with dedicated security engineering
  teams.

SHA-256 is used precisely because it is a published standard that needs no defending.

---

## Who this is for

Institutions that carry an audit-trail obligation without the budget or staff to meet it the way
a money-center bank does — community banks, credit unions, regional broker-dealers, mid-size
insurers — and the managed service providers, CUSOs and audit firms that serve them.

Relevant obligations include NYDFS 23 NYCRR § 500.06 (systems to reconstruct material financial
transactions and audit trails to detect and respond to cybersecurity events, with five- and
three-year retention), the GLBA Safeguards Rule at 16 CFR Part 314, and PCI DSS v4.0 Requirement
10, which requires audit logs to be protected against modification. Each presupposes a trustworthy
record. None establishes one.

Nothing here is specific to financial services. Any environment where the log is evidence has the
same problem.

---

## Roadmap

- [x] Architecture, threat model, verification method
- [x] Test protocol
- [ ] Hashing agent
- [ ] Ledger node and chain construction
- [ ] Verifier with tamper, deletion and chain-break detection
- [ ] Test results published
- [ ] Overhead measurement at volume
- [ ] External anchoring of the chain head
- [ ] Failure-mode handling: channel interruption, ledger unavailability, clock skew, rotation
- [ ] Integration notes for Splunk, QRadar, Sentinel, ArcSight

---

## Known limitations

Stated up front rather than discovered by whoever reads the code.

- Development and testing on two hosts at laboratory volumes. Throughput, latency and storage
  behaviour at production log rates are not yet characterised.
- Hashing in the write path imposes overhead on the logging host. Not yet measured.
- Segmentation is enforced by SSH configuration and firewall rules. Physical or hardware
  unidirectional separation is stronger and is not required for the property to hold, but the
  distinction should be understood.
- The chain establishes internal consistency. It does not yet prevent wholesale rollback of the
  ledger host — that requires anchoring the chain head somewhere the ledger cannot retroactively
  rewrite.
- No integration with commercial SIEM platforms yet.
- The two hosts in the current test environment share one flat subnet over wifi, behind a single
  router, and are administered by the same person. The threat model assumes a separately
  administered host on a different network segment; this environment does not instantiate that
  assumption, and no claim of physical separation or an air gap is made.
- The ledger accepts digest submissions from anything that can reach its port. Firewall rules are
  the only control on that. A flood of submissions for records that do not exist is loudly
  detectable — every one produces an alert — but it is not preventable at this layer, and it can
  put a large number of alert lines into a verification run.
- The bound on implausible sequence numbers raises the cost of walking the chain head forward from
  constant to linear, rather than eliminating it. An attacker willing to submit roughly a thousand
  digests per thousand sequences can still advance the head, and every one of those submissions
  raises an alert.
- Detecting that a digest arrived late is not the same as knowing why. From the ledger's position,
  "the ledger was unreachable" and "the primary chose not to speak" are the same observation, so a
  primary under full root can manufacture a quiet window and date a forged record into it. Running
  the liveness heartbeat is what makes such a window visible as silence rather than accepted as an
  outage; without it, lateness has no independent corroboration.

---

## License

Apache 2.0. Chosen deliberately: the express patent grant makes it safe for institutions and
their vendors to adopt without legal review overhead. Use it, fork it, ship it in a product. The
point is that this capability should be available, not that I should own it.

---

## Author

Tomi Gjenerali — security practitioner. Fifteen years in technology and security roles at Morgan
Stanley, AIG and Charles Schwab. B.S. and M.S. in Cybersecurity and Information Assurance,
Western Governors University.

This problem came out of operational work: verifying that authentication events into databases
holding personally identifiable information were actually being captured, tracing them from the
application layer to the database access log, and chasing down the gaps when entries were
missing. Doing that by hand is how you learn that an incomplete log and a clean log look the
same from the outside.

Issues and pull requests welcome. If you think the approach is wrong, I would genuinely like to
hear why.
