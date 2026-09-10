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

The evidentiary content of a firewall log line is the **timestamp, SRC, DST,
DPT and the ALLOW/BLOCK verdict**. The MAC field carries none of it. It is
replaced with `MAC=[redacted]` in anything committed here.

A stated redaction is entirely acceptable in evidence. An unnoticed disclosure
is not.

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
