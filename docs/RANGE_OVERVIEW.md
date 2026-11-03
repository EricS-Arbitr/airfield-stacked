# Blackstone Auxiliary Field

### A military airfield. Two domains, real OT. Watched by two SIEMs at once.

---

Most SIEM training environments treat the network as a backdrop. Logs arrive,
analysts triage them, and nothing an attacker does is constrained by where they
are.

**Blackstone is built the other way round.** An 89-host military-base estate
with a two-domain Active Directory forest — a base enterprise and a flight-ops
child domain — a DMZ, a genuinely segmented fuel-farm OT enclave running real
ICS equipment, and a bespoke air-traffic-control subsystem fed from recorded
flight data. Four Security Onion sensors watch it from four different vantage
points, a distributed Splunk cluster watches the same estate in parallel, and a
Malcolm appliance parses the OT protocols — *which sensor sees an event tells
you where the adversary is standing, and the same activity is there to work in
either SIEM*.

Lateral movement stops being a diagram and becomes something a defender
reconstructs from evidence.

---

## What defenders get

**Two SIEMs over one network.** Security Onion 2.4 distributed across a manager,
a search node and four sensors — Suricata and Zeek on every mirrored segment —
and a distributed Splunk cluster with a universal forwarder on every managed
host. The same endpoints and the same device logs feed both, so a cohort can be
trained and assessed on either platform, and a gap in one is not a gap in the
other.

**OT visibility at the protocol level.** A Malcolm appliance parses the
fuel-farm ICS traffic the OT sensor mirrors to it, turning opaque process TCP
into legible Modbus and friends.

**IT and OT, properly separated.** The enterprise and flight-ops domains run
OSPF; the fuel farm sits behind a default-deny L3.5 boundary reachable only by
static route. The OT process hosts are deliberately left off endpoint
monitoring, so that enclave has to be investigated from the wire — and that
traffic is in both Security Onion and Malcolm.

**Real control systems and real flight data.** An OpenPLC controller, a Modbus
field simulator, a FUXA operator HMI and an in-enclave historian and audit DB
model a fuel farm; a radar/ADS-B replay and recorded weather drive an
air-traffic-control subsystem the flight-ops domain actually uses.

**A network that is already busy.** Emulated users log in, browse, open
documents and move files continuously across both domains. Detections have to
survive contact with a network that is not quiet.

---

## What event coordinators get

**A multi-SIEM exercise.** The same attack is visible in Security Onion and in
Splunk at the same time, so analysts can pivot between platforms over identical
data — or a cohort can be split across the two.

**Tunable visibility.** Endpoint coverage is an inventory group, not a
hard-coded list. Which OT hosts carry an agent, and which segments feed which
sensor, are one-line decisions recorded in the inventory.

**Repeatable builds.** The entire range is Ansible from a pinned tarball,
verified by scripts that assert outcomes rather than exit codes. Stand it up,
run the exercise, rebuild it clean.

---

## The terrain

| | |
|---|---|
| **Scale** | 89 hosts across 13 host-bearing segments, plus six point-to-point transit links |
| **Identity** | one forest, two domains (`blackstone.mil` + child `fops.blackstone.mil`), four domain controllers, 44 domain members |
| **Enterprise** | Services, Headquarters, IT, Supply; DMZ with public web, FTP and DNS |
| **Flight ops** | Flight-Ops-Services, Flight-Control-Center (ATC + weather), Flight-Ops-Users |
| **OT enclave** | Fuel farm — control-room HMI, OpenPLC, field simulator, historian, audit DB — behind a default-deny L3.5 boundary |
| **Security** | Security Onion grid, a distributed Splunk cluster and a Malcolm OT appliance, plus six FLARE-imaged analyst workstations and a SIFT/OpenVAS bench |
| **Routing** | OSPF core, eBGP at the ISP edge, static across the OT boundary |

---

## Training value

| Skill | How the range exercises it |
|---|---|
| Network forensics | Full packet visibility on four segments via layer-2 mirrors — Zeek connection, DNS, HTTP and file logs |
| Endpoint investigation | Sysmon and Elastic Agent process, file and network telemetry across the Windows and Linux fleet |
| Multi-SIEM operations | The same activity is visible in both Security Onion and Splunk, so analysts pivot between platforms over identical data |
| OT protocol analysis | Malcolm parses the fuel-farm ICS traffic into protocol-aware records alongside the Security Onion view |
| Lateral movement detection | Segment-aware sensor placement makes east-west movement observable as a change in *which* sensor carries the traffic |
| IT/OT boundary defence | A real default-deny boundary into a fuel-farm enclave whose process hosts are deliberately dark to endpoint tooling |
| Cross-domain identity | A parent/child forest trust means authentication crosses two domains by default — and stands out where it should not |

---

## Deployment

Ansible from a pinned, versioned tarball. Two to three hours from a clean
blueprint to a verified range, unattended. Its major install artifacts —
Security Onion, Splunk and Malcolm, their container images, the Ansible
collections, the fuel-farm packages — come from the platform's own package
repository rather than the public internet, so a build is deterministic and does
not depend on upstream availability. Verification asserts what actually matters —
that sensors are receiving packets, that Zeek is producing connection records,
that the Splunk indexers are up and the search head can search, that every
endpoint is enrolled — not merely that the playbook exited zero.

---

*Technical detail: see the Range Guide.*
