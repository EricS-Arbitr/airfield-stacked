# airfield-stacked

Range-specific Ansible overlay for the **Blackstone Auxiliary Field**
cyber-range scenario on the SimSpace NG platform, carrying **both SIEMs on one
range**: a distributed Splunk cluster and a Security Onion 2.4 grid, plus a
**Malcolm** appliance for OT deep-packet analysis. Every managed endpoint feeds
both SIEMs.

The scenario is a military airfield: a single Active Directory forest with a
`blackstone.mil` root (enterprise / SOC) and a `fops.blackstone.mil` child
(flight operations), an OT fuel farm, and a simulated air-traffic-control
subsystem. This is the **full-stack** range; it is forked from
[`airfield-range`](../airfield-range), which is Security Onion only. The two
share almost all of their Ansible — the difference here is the Splunk tier, a
universal forwarder on every managed host, the Malcolm appliance, and the
blueprint VMs behind them. `ss-pp-stacked` is the same relationship on the
PowerPlant side and the working reference for the Splunk half.

This is an overlay, not a standalone playbook. It layers on the customer's
shared platform repo at `../range-development-ansible/`: that repo ships base
roles, this one ships the range's inventory, variables, custom roles and
playbooks. `build_tarball.sh` combines the two into `airfield_full_stack.tgz`,
which is extracted to `/etc/ansible` on the range's Ansible controller.

## Build and deploy

```bash
./build_tarball.sh          # -> airfield_full_stack.tgz  (validates before it writes)
# copy airfield_full_stack.tgz to the controller, extract to /etc/ansible, then:
./deploy.sh                 # site.yml, up to 3 attempts
BOOT_DELAY=0 ./deploy.sh    # skip the boot wait on an already-up range
```

`build_tarball.sh` refuses to write an archive that would not deploy. It checks
Jinja variable references (`verify_vars.py`), free-form shell arguments that
Ansible's `split_args()` would reject (`verify_shell_args.py`), handler
`notify`/`listen` wiring (`verify_handlers.py`), duplicate YAML keys
(`verify_dup_keys.py`), task-keyword misuse (`verify_task_keywords.py`), and the
Elastic Defend path filters (`verify_defend_filters.py`).

`deploy.sh` runs `site.yml` up to three times: full sweep, then a
retry-file-scoped pass over only the hosts that failed, then a full sweep again
as a safety net. A cold build from a fresh blueprint legitimately needs all
three — some AD, grid and Malcolm steps self-clear on a later attempt.

## The range

89 hosts across 13 host-bearing segments — the SO-only range plus the four-node
Splunk tier and the Malcolm appliance. 44 are domain members (29 on
`blackstone.mil`, 15 on `fops.blackstone.mil`), and the managed Windows fleet is
48 hosts.

**Splunk** is a distributed cluster, not a single box:

| Host | Role |
|---|---|
| `soc-splunk-cm` | cluster manager, and the license manager for the whole deployment |
| `soc-splunk-idx01`, `soc-splunk-idx02` | indexer peers, cluster label `mb-idxc` |
| `soc-splunk` | search head, runs Enterprise Security |

Universal forwarders run on every managed host except the Splunk tier itself and
the SO control plane (`[splunk_forwarder_exempt]`).

**Security Onion** is a distributed grid: `soc-so-manager`, `soc-so-search`, and
four sensors — `soc-sensor-corp` (enterprise), `soc-sensor-fops` (flight-ops),
`soc-sensor-ot` (fuel-farm OT) and `soc-sensor-edge` (attack path + simulated
Internet) — fed by GRE + `tc` mirror rules from the routers in
`[so_mirror_routers]`. Endpoints report through an Elastic Agent enrolled into
the grid's Fleet.

**Malcolm** (`soc-malcolm`) is a CISA Malcolm 26.08.0 OT appliance
(OpenSearch / Arkime / Zeek / Suricata / Logstash under Docker) with its own
`gretap` GRE-mirror decap interface watching the OT segments.

Two scenario subsystems ride on top of the baseline: an OT **fuel farm** (POL)
and a virtual **air-traffic-control** stack.

## What gets deployed

`site.yml` is the entry point. `10-mirror` is imported first so its
container-image build overlaps the range baseline. The baseline plays run inline
in `site.yml` (network, the two-forest AD build, hosts, services) **and the
whole Splunk cluster**; the Security Onion phases, Malcolm, and the two
subsystems are imported at the tail.

| Phase | Does |
|---|---|
| `10-mirror` | nginx on the controller serving the SO source, detection content and container registry artifacts |
| *(baseline, inline)* | network, two-forest AD (`blackstone.mil` + `fops.blackstone.mil`), VyOS/pfSense, DNS, domain joins, hosts, services |
| *(Splunk, inline)* | the distributed Splunk cluster — manager, indexer peers, search head + ES, then universal forwarders |
| `05-time` | Windows clock correction, DC-first |
| `20-vyos` | GRE tunnels + `tc` mirror rules to the sensors |
| `30-prereqs` | `so_base` on every grid node |
| `40-manager` | waits for the registry artifacts, then installs the manager |
| `50-nodes` | search + sensors join the grid |
| `60-verify` | grid health |
| `70-analyst` | analyst workstation enablement (SIFT / FLARE / OpenVAS bench) |
| `75-endpoint` | Sysmon, then Elastic Agent enrolment into Fleet |
| `80-fleet-integrations` | host-scoped log sources into SO via dedicated Fleet policies |
| `90-malcolm` | installs/host-preps/runs the Malcolm stack and brings up its GRE decap |
| `fuel_farm_playbook.yml` | the OT fuel-farm subsystem (runs after the SIEM tier) |
| `atc_playbook.yml` | the air-traffic-control subsystem |

## Both SIEMs receive endpoint data

Every managed endpoint outside the forwarder-exempt set carries **both** a
Splunk universal forwarder and an Elastic Agent, so the same process, file,
registry and Windows-event telemetry is workable in either tool. Sysmon and a
central rsyslog collector feed both: the SO Fleet integrations and the Splunk
forwarders each read the same sources. Neither SIEM is a fallback for the other.

## Security Onion

A distributed grid: manager, search node and four sensors. Endpoints report
through Elastic Agent; the sensors see network traffic through GRE mirrors from
the VyOS/OT routers.

Container images and the SO source snapshot are served from the controller's
mirror (`so_apt_mirror` runs on the controller, not a grid node) rather than
pulled from ghcr.io, so no in-play system needs internet access. The source and
images are staged from the in-platform Nexus (`ng_raw` for source/airgap
content, `nexus-docker` for images); the controller is the only host that
reaches out, and only to build those artifacts. Malcolm is sourced the same way.

## Subsystems

These are what distinguish the airfield scenario from the PowerPlant ranges.
Both deploy after the SIEM tier so the grid, Splunk and Malcolm can all see
their traffic as it comes up, and both can be iterated on their own.

- **Fuel farm (OT / POL)** — a segmented Modbus-TCP industrial control system:
  OpenPLC controller, a field-instrument simulator, a FUXA HMI, an
  InfluxDB/Grafana historian and a PostgreSQL audit DB. `soc-sensor-ot` and the
  Malcolm appliance both watch the OT segments. Iterate with
  `ansible-playbook fuel_farm_playbook.yml`; verify with `./verify_fuel_farm.sh`.
- **Air traffic control** — an ADS-B feed driving `readsb` → a `tar1090` scope
  and a Flight Data Processor, a METAR/TAF/ATIS weather feed, and a
  controller-working-position kiosk. Iterate with
  `ansible-playbook atc_playbook.yml`; verify with `./verify_atc.sh`.

## Documentation

| File | For |
|---|---|
| `BUILD_SPEC.md` | working on this repo — layout, conventions, pitfalls, recipes |
| `docs/RANGE_GUIDE.md` | operators and instructors |
| `docs/RANGE_OVERVIEW.md` | the range at a glance |
| `docs/engineering/` | the full engineering pack (also bundled as the PDFs in `docs/`) |
| `UPSTREAM_FIXES.md` | customer-repo bugs and the overlay workarounds, with the reasoning |
| `PROJECT_LOG.md` | chronological build history |

Read `UPSTREAM_FIXES.md` before changing network, AD, Splunk or Security Onion
plumbing. Most surprises are already diagnosed there.

## Secrets

Credentials live in `group_vars/all/vault.yml`, encrypted with ansible-vault.
`ansible.cfg` points `vault_password_file` at `/home/simspace/.vault_pass` on
the controller; that file does not persist across range spin-ups, and
`deploy.sh` fails closed with the recreate command when it is missing.
