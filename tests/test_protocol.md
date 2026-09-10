# Test protocol, as run

Each scenario as actually executed, with its result and the evidence file holding
the capture. Where a test was run more than once, or produced something other
than the expected result, that is recorded rather than smoothed over.

Times are UTC. Full captures are in `evidence/`.

---

## Status

| # | Scenario | Result | Evidence |
|---|---|---|---|
| T1 | Normal operation, volume | pending | — |
| T2 | Modification | **PASS** | `step6-tamper-deletion.txt` |
| T3 | Deletion, last record | **PASS** | `step6-tamper-deletion.txt` |
| T3b | Deletion, middle record | **PASS** | `step6-tamper-deletion.txt` |
| T4 | Legitimate activity, false-positive check | pending | — |
| T5 | Write refusal | **PASS** | `step1-claim4-reverse-test.txt`, `step7-chain-integrity.txt` |
| T6 | Overhead | partial | `step5-clean-run.txt` |
| T7 | Unwitnessed insertion | pending | — |
| T8 | Backdating | pending | — |
| T9 | Stopped agent | **PASS** (incidental) | `step6-tamper-deletion.txt` |
| T10 | Lost acknowledgement | **PASS** (unplanned) | `step3-push-path.txt` |
| T11 | Implausible sequence | pending | — |
| T12 | Fabrication, expected to pass verification | **PASS** | `NOTES.md` |

---

## T2 — Modification

Target chosen by content, not index: an authentication record, altered in one
field. Source address changed from `10.0.0.212` to `10.0.0.99`, leaving `seq`,
`ts` and the stored digest byte-identical — the realistic shape, since an
attacker cannot recompute a digest the ledger already holds.

    TAMPER  seq=57  recomputed 58def3401134675a... != chained 3837d93eb51c596d...

The recomputed value was predicted independently on the primary before the
verifier ran on the ledger, and the two agreed exactly. Two hosts, two
implementations of the check, same result.

---

## T3 — Deletion, last record

Removed a root login from an external address. Seq 58 was the final record, so
removing it left the log **contiguous 1–57 with no gap**. Every remaining record
hashes correctly. Nothing on the primary distinguishes the deletion from an agent
that stopped early.

    DELETION  seq=58  (beyond the log's highest sequence 57: either the tail was
                       truncated or this digest was submitted for a record that
                       never existed)

The hedge is correct: beyond the log's maximum the ledger genuinely cannot tell
truncation from a digest for a record that never existed, and it declines to
assert more than it knows.

## T3b — Deletion, middle record

Removed the publickey authentication at seq 57 with 58 present after it, leaving
a real hole.

    DELETION  seq=57  digest is chained but no record with this sequence exists
                      in the log

No hedge. Seq 57 is below the maximum and cannot be explained as truncation.

**Both belong in the write-up.** T3 is the harder case and the stronger statement
of the thesis; T3b gives the unambiguous alert. Presenting only T3b hides the
limit; presenting only T3 invites a reviewer to read the hedge as doubt.

---

## T5 — Write refusal

Two halves, both captured.

**The primary cannot reach the ledger except on the digest port.** From the
primary:

    port 22    15012ms  silent drop     no rule matches; default deny
    port 9900     71ms  refused         rule matches; ledgerd not yet running

Self-validating: the refusal proves the ledger was up and reachable seconds
either side, so the silent drop cannot be unreachability.

**The chain cannot be altered by the operator of the host holding it.** Four
attempts against the live chain — `sed -i`, truncation, `open("w")`,
seek-overwrite — all refused, sha256 unchanged. On a throwaway probe, `rm` and
`mv` also refused, and the attribute cannot be cleared without root.

---

## T9 — Stopped agent

Observed incidentally rather than staged, which is better evidence. The agent
must be stopped to edit the log cleanly for T2 and T3, so the stop is part of
those attacks. The threshold was seen being crossed rather than read after the
fact:

    at 150s elapsed:  TAMPER only, no SILENCE
    at 209s elapsed:  TAMPER + SILENCE seq=58->now, 3.5 minutes

Still to run deliberately against the systemd-managed service, since
`Restart=always` is specifically meant to make holding the agent down require an
action that leaves a journal record.

---

## T10 — Lost acknowledgement

Also unplanned. The agent ran before ledgerd was listening; twenty events and a
heartbeat were refused, retried on the inline backoff, and spooled with the
reason recorded per digest. **21 log records against 21 spooled digests — exact
parity, nothing dropped.** On restart the drainer delivered all 21 in 129ms
without anyone touching the primary.

That is the roadmap's "channel interruption" item demonstrated on hardware, by
accident, which is stronger than a staged version.

---

## T12 — Fabrication, expected to PASS verification

    agent stopped 1s, fabricated record with a truthful timestamp appended and
    its digest witnessed through the normal path, agent restarted

    verifier --max-silence 6:  chain=8 log=8 heartbeats=4 -> CLEAN   exit 0

**This is not a failure of the test.** It is the boundary of the design, and
documenting it matters more than any detection result here. Both parameters are
stated because the result depends entirely on the stop being shorter than the
silence threshold — a run that omits them proves nothing. An 8-second stop at the
same threshold IS detected; the undetectable window is bounded by the threshold,
which cannot be set below the heartbeat interval plus jitter.
