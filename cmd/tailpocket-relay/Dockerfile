# Build from the repository root:
#
#   docker build -f cmd/tailpocket-relay/Dockerfile -t tailpocket-relay .
#
# Run next to a reverse proxy on the same machine (see README.md, "In a container"):
#
#   docker run --rm --network host --user "$(id -u):$(id -g)" \
#     -v "$PWD/relay.token:/run/secrets/relay.token:ro" \
#     tailpocket-relay --token-file /run/secrets/relay.token \
#     --public-host relay.example.com --listen 127.0.0.1:8080 --trust-proxy 127.0.0.1/32

# Base images are pinned by index digest (all platforms). To move one, pick a
# digest published at least 14 days earlier, unless the move fixes a security
# issue in what the relay runs (golang:1.27.4, for GO-2026-6859 in net/http):
#   golang:1.27.4: the digest history of docker-library/repo-info,
#     repos/golang/remote/1.27.4.md
#   distroless static-debian13 nonroot: timeUploadedMs in
#     https://gcr.io/v2/distroless/static-debian13/tags/list
FROM golang@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY connectrelay/ connectrelay/
COPY cmd/tailpocket-relay/ cmd/tailpocket-relay/
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/tailpocket-relay ./cmd/tailpocket-relay

FROM gcr.io/distroless/static-debian13@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/tailpocket-relay /tailpocket-relay
USER nonroot:nonroot
EXPOSE 8080
# Inside the container the relay must listen on all interfaces; publish the
# port only where you mean to (for example -p 127.0.0.1:8080:8080 behind a proxy).
ENTRYPOINT ["/tailpocket-relay", "--listen", "0.0.0.0:8080"]
