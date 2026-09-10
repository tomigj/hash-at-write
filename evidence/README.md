# Evidence

Captured output supporting the test protocol. Two rules govern what goes in here.

## 1. Results are recorded as they occurred

Failures stay. `step1-tg.txt` retains the `Unit file ssh.service does not exist`
failure from 03:35 UTC alongside the successful state that followed, because
that is what happened. A capture that only shows the working end state is a
weaker artifact, not a stronger one.

Every capture states the configuration that produced it. A result whose
parameters are omitted can be falsified by anyone who reruns it with different
ones — and during this build a result was recorded as "no alert of any kind"
from a run whose threshold was set well above the condition being tested, which
demonstrated nothing. Parameters are part of the result.

## 2. This is a public repository

**Hardware addresses are redacted.** Raw `ufw` log lines carry a `MAC=` field
containing the host's NIC address followed by the router's, e.g.
`MAC=aa:bb:cc:dd:ee:ff:...`. A MAC is a stable, globally unique device
identifier and its OUI names the hardware vendor. Published in a repository tied
to a named individual, it is a durable identifier for that person's personal
machine and home network, and pushing it is not reversible.

**Pseudonymised, not blanked.** An earlier version of this rule said to replace
the MAC field with `[redacted]`. That was wrong, and the first real log showed
why: the MAC field is what distinguishes traffic relayed by the router from
traffic sent directly on the LAN, and what establishes that blocked packets came
from the ledger host itself rather than something else using its address. It also
carries the ethertype, which is how an IPv4 block is told from an IPv6 one.
Blanking it destroys that.

Each device gets a stable pseudonym — `<tg-nic>`, `<daddy-nic>`, `<router>` — used
consistently everywhere, with a mapping in the file. The reader can then follow
which device sent what, without the permanent identifier being published. The
ethertype suffix is kept verbatim: `0800` is IPv4, `86dd` is IPv6.

A stated redaction is entirely acceptable in evidence. An unnoticed disclosure
is not.

**Global IPv6 addresses are redacted too**, for the same reason. A routable v6
address carries the ISP-delegated prefix for the operator's home network plus an
interface identifier — a durable pointer to that network in a way a private
address is not. Where a test turns on address family, the family, the port, the
verdict and the timing are the evidence; the address is not.

RFC 1918 addresses (`10.0.0.0/24`) are kept: they are not globally unique, they
are necessary to read the rules, and they identify nothing outside the lab.

## 3. Firewall log lines need their cause stated

Enabling `ufw` installs a fresh ruleset whose ESTABLISHED,RELATED accept only
matches flows conntrack is tracking under the new rules. Connections that
predate the enable lose their return path and die, producing a burst of
`[UFW BLOCK]` lines in the seconds after activation.

Those lines are the host's **own outbound traffic being severed by its own
firewall coming up**. They are not inbound attack traffic, and next to a claim
about blocking unauthorised access they read exactly like it. Any such lines are
annotated as activation artifacts or excluded, with the exclusion stated.

A `[UFW BLOCK]` line is evidence of enforcement only when the traffic it names
was an actual unauthorised inbound attempt, deliberately generated as part of a
test, at a recorded time.

## 3b. What is published deliberately

Two things in the captured authentication events were identified before commit
and published on a considered decision, not by oversight.

**The verifier's public key fingerprint** appears in every accepted-publickey
line. It is a public key, scoped to a forced command on one host, and redacting
it would obscure that the captured authentications are genuine rather than
synthesised. The only cost is that the fingerprint permanently identifies that
keypair, so reusing the key elsewhere would link the two — an argument for not
reusing it, rather than for hiding it.

**sudo session lines** showing privilege escalation by the operator, in the form
`session opened for user root(uid=0) by tomigj(uid=1000)`. This is the operator's
own activity on their own machine, and it is the kind of event the system exists
to record. Removing it would make the captured set less representative of what a
real audit trail contains.

Both were put to the operator with the tradeoffs stated and both were approved
for publication.

## 4. The firewall log is a sample, not a complete record

Both hosts run `ufw` at `LOGLEVEL=low`, which rate-limits blocked-packet logging.
A probe window timed by `date -u` will generally be longer than the span of
logged blocks inside it — five seconds of one such window produced no lines at
all, which was rate limiting rather than a gap in enforcement.

So: attempt counts are never derived from log line counts. "Seven blocked SYNs
were logged" is supportable; "seven SYNs were blocked" is not. And the absence of
a log line is never evidence that a packet was not blocked.

## 5. Direction is stated on every result

The same port appears with opposite verdicts depending on which way the
connection ran — `tg -> daddy:9900` is refused because the rule permits it, while
`daddy -> tg:9900` is dropped because no rule covers it. Both are correct. A
reader who sees one file say "9900 blocked" and another say "9900 permitted" will
assume an error unless the direction is explicit in both.
