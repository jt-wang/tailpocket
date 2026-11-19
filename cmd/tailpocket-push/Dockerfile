# Build from the repository root:
#
#   docker build -f cmd/tailpocket-push/Dockerfile -t tailpocket-push .
#
# Run next to a reverse proxy on the same machine (see README.md, "In a container"):
#
#   docker run --rm --network host --user "$(id -u):$(id -g)" \
#     -v "$PWD/push:/data" \
#     tailpocket-push --config /data/push.json --listen 127.0.0.1:8443

# Base images are pinned by index digest (all platforms), the same ones as
# cmd/tailpocket-relay/Dockerfile; move them together, following the rules
# written there.
FROM golang@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY connectpush/ connectpush/
COPY cmd/tailpocket-push/ cmd/tailpocket-push/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/tailpocket-push ./cmd/tailpocket-push

FROM gcr.io/distroless/static-debian13@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/tailpocket-push /tailpocket-push
USER nonroot:nonroot
EXPOSE 8443
# The config, credentials, handle key and state file live in /data, which
# must be writable (the gateway creates the handle key and the state file).
# Inside the container the gateway must listen on all interfaces; publish
# the port only where you mean to (for example -p 127.0.0.1:8443:8443).
ENTRYPOINT ["/tailpocket-push", "--config", "/data/push.json", "--listen", "0.0.0.0:8443"]
