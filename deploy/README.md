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

The unit deliberately runs under `ProtectSystem=strict` with `ReadWritePaths=/var/lib/xe`:
the genesis and env file are inputs, never written by the node.

### Quick Setup

1. Copy the example configuration to `/etc/xe/xe-node.env`:
   ```sh
   sudo mkdir -p /etc/xe
   sudo cp deploy/xe-node.env.example /etc/xe/xe-node.env
   ```
2. Copy the genesis pair for the active network (e.g. `testnet-0005`):
   ```sh
   sudo mkdir -p /etc/xe/genesis
   sudo cp genesis/testnet-0005/*.json /etc/xe/genesis/
   ```
3. Build and install the binary as `/usr/local/bin/xe-node`:
   ```sh
   make build
   sudo install -m 0755 xe /usr/local/bin/xe-node
   ```
4. Create the service user and data directory:
   ```sh
   sudo useradd -r -s /bin/false xe || true
   sudo mkdir -p /var/lib/xe/data
   sudo chown -R xe:xe /var/lib/xe
   ```
5. Install and start the systemd unit:
   ```sh
   sudo cp deploy/xe-node.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now xe-node
   ```

Compute providers additionally need a `kvm.conf` drop-in
(`SupplementaryGroups=kvm`) for Lima/QEMU.
