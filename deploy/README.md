# deploy/

Packaging for an XE node.

| File | What it is |
|---|---|
| `Dockerfile` | Static, non-root, distroless node image. Build from the repo root. |
| `xe-node.service` | systemd unit, hardened, reads `/etc/xe/xe-node.env`. |
| `xe-node.env.example` | Every knob the unit reads. No secrets. |

See [`../docs/run-a-node.md`](../docs/run-a-node.md) for the network values to
put in the env file and for the verification recipe.

## Docker

```sh
docker build -f deploy/Dockerfile -t xe-node:dev --build-arg VERSION=$(git describe --tags --always) .
docker run --rm -v xe-data:/data -p 9000:9000 xe-node:dev \
  node --data /data --api-bind 0.0.0.0 \
       --genesis-dir /genesis --dial <bootstrap-multiaddr>
```

Mount the published genesis at `/genesis` (`-v /etc/xe/genesis:/genesis:ro`).
Without `--genesis-dir` the container runs whatever genesis the image was built
from, which for a clean-master build is a placeholder no live network uses.

## systemd

The unit deliberately
runs under `ProtectSystem=strict` with `ReadWritePaths=/var/lib/xe`: the
genesis and env file are inputs, never written by the node.

Compute providers additionally need a `kvm.conf` drop-in
(`SupplementaryGroups=kvm`) for Lima/QEMU.

