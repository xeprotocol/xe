# deploy/

Packaging for an XE node. Before this directory existed, the operational
definition of a node lived only as untracked state on five machines (#839).

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

Install steps are in the header of `xe-node.service`. The unit deliberately
runs under `ProtectSystem=strict` with `ReadWritePaths=/var/lib/xe`: the
genesis and env file are inputs, never written by the node.

Compute providers additionally need a `kvm.conf` drop-in
(`SupplementaryGroups=kvm`) for Lima/QEMU.

---

## Release signing — DECISION REQUIRED

`.github/workflows/release.yml` signs `SHA256SUMS` with **Sigstore cosign
keyless (OIDC)**. This is a deliberate choice and it is reversible; it needs
confirming before the first tag.

**What was chosen: keyless.**

- No private key exists anywhere, so none can leak, none needs custody, and
  none needs rotating.
- The signature is bound to this workflow's GitHub OIDC identity and recorded
  in the public Rekor transparency log, so a forged release would have to
  forge a GitHub Actions identity *and* the log would show it.
- Verification needs no prior trust distribution — a stranger runs
  `cosign verify-blob` with the repository identity and is done.
- **Adam must provide nothing.** This is the reason to prefer it.

**What it costs.**

- Verifiers need `cosign` installed; `sha256sum -c` alone proves integrity but
  not origin.
- Trust roots to Sigstore's public-good infrastructure and to GitHub's OIDC
  issuer. A project that wants its trust anchored in a key *it* holds does not
  get that here.

**The alternative, if Adam wants a project-held key.**

Generate a key offline, publish the public half on `xe.network`, store the
private half as an Actions secret, and sign with GPG or `minisign` in the
release job. That requires Adam to:

1. Generate the keypair on a machine that is not this VM.
2. Add the private key + passphrase as repository secrets.
3. Publish the public key and its fingerprint somewhere out-of-band from the
   release artifacts.
4. Own rotation and revocation forever.

**No signing key has been generated or committed by this change**, and none
should be added to the repository under any circumstance.

**Recommendation:** keep keyless. Revisit only if a specific downstream
requires a project-held key. Both can coexist later — keyless now does not
foreclose adding a project key.
