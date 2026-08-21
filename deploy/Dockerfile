# XE node image (#839).
#
# Build from the repository root:
#   docker build -f deploy/Dockerfile -t xe-node:dev .
#
# Static, non-root, distroless. CGO is off everywhere in this project and no
# package imports "C", so the binary needs no libc and the runtime layer needs
# no shell — which also removes the shell from the attack surface of a process
# that speaks to the open internet.

# ---- build ------------------------------------------------------------------
# Pinned by digest-free tag on purpose: the tag must match .go-version, and the
# reproducible-build guarantee comes from the toolchain pin plus -trimpath, not
# from the base image. Keep this in step with .go-version.
FROM golang:1.25.0-alpine AS build

WORKDIR /src

# Dependency layer first so a source-only change does not re-download modules.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# VERSION is stamped into `xe version` and the libp2p user agent. Pass the tag
# for a release image; the default makes it obvious when someone did not.
ARG VERSION=docker-dev
ENV CGO_ENABLED=0
RUN go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/xe ./cmd/xe/

# ---- runtime ----------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/xe /usr/local/bin/xe

# 9000 p2p (must be reachable from the internet for this node to serve sync,
# chat and tunnels), 8080 API, 8000 embedded UI. Only 9000 needs publishing for
# a plain validator; the API and UI default to 127.0.0.1 inside the container,
# so override --api-bind/--ui-bind explicitly if you intend to expose them.
EXPOSE 9000 8080 8000

# Ledger, statechain, keypair and any runtime genesis live here. Mount it, or
# every restart is a cold resync from an empty data dir.
VOLUME ["/data"]

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/xe"]
CMD ["node", "--data", "/data", "--api-bind", "0.0.0.0"]
