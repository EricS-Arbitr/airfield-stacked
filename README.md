# airfield-stacked
Simulated Cyber Range representing an airfield, running **both SIEMs**: a
distributed Security Onion grid and a distributed Splunk cluster, with every
endpoint feeding both.

Forked from [`airfield-range`](../airfield-range), which is Security Onion
only. The two share almost all of their Ansible; the difference is the Splunk
tier, the universal forwarder on every managed host, and the blueprint VMs
behind them. `ss-pp-stacked` is the same relationship on the PowerPlant side
and is the working reference for the Splunk half.

| | airfield-range | airfield-stacked |
|---|---|---|
| Security Onion | yes | yes |
| Splunk | no | distributed: search head, 2 indexer peers, cluster manager |
| Endpoint telemetry | Elastic Agent | Elastic Agent **and** universal forwarder |
| Blueprint | `ARBITR_MB_*.yml` | `ARBITR_MB_STACKED-001.yml` |
| Tarball | `ab_mb.tgz` | `ab_mbs.tgz` |
