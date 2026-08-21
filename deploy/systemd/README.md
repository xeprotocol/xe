# Deployment units

Committed for #841. Before this, no systemd unit, pm2 config or Dockerfile
existed in any repository in the project — every node was configured by hand on
the box. That mattered for one specific reason beyond tidiness: **the log-size
policy could not be changed from tracked configuration**, which is the direct
fix for the disk-full outage class already on this project's record.

- `xe-node.service` + `xe-node.env` — systemd, used on the provider hosts.
- `../pm2/ecosystem.config.js` — pm2, used on the bootstrap hosts.

Both bound log output and both wire the liveness probe. Neither wires a restart
to `/ready`, and that is deliberate: readiness reports whether a node should
receive traffic, and during a network-wide quorum incident every node is
not-ready at once. A supervisor acting on it would restart the whole fleet in
the middle of a consensus incident.
