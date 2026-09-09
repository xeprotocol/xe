FROM golang:1.25.0-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=docker-dev
ENV CGO_ENABLED=0
RUN go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/xe ./cmd/xe/

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/xe /usr/local/bin/xe

EXPOSE 9000 8080 8000

VOLUME ["/data"]

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/xe"]
CMD ["node", "--data", "/data", "--api-bind", "0.0.0.0"]
