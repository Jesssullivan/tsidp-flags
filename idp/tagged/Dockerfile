# tsidp built from one reviewed upstream commit plus the tagged-identity patch.
# Used only by the optional `tagged-identity` compose profile (idp/compose.yaml).
#
# Pin: github.com/tailscale/tsidp 8fa860f333d9b0ed7eee66e0c7c08531f743fd16
# (2026-09-08, "feat: support auth key from file (TS_AUTHKEY_FILE) (#190)").
# Base images are pinned by digest. Licensing: see idp/tagged/README.md.

FROM docker.io/library/golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build
ARG TSIDP_REV=8fa860f333d9b0ed7eee66e0c7c08531f743fd16
RUN apk add --no-cache git
WORKDIR /src
RUN git init -q . \
 && git fetch -q --depth 1 https://github.com/tailscale/tsidp "${TSIDP_REV}" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "${TSIDP_REV}"
COPY 0001-tagged-identity.patch /patches/
RUN git apply --verbose /patches/0001-tagged-identity.patch
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/tsidp-server .

FROM docker.io/library/alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache ca-certificates \
 && mkdir -p /data \
 && addgroup -g 1001 -S app \
 && adduser -u 1001 -S app -G app \
 && chown app:app /data
COPY --from=build /out/tsidp-server /tsidp-server
USER app:app
ENTRYPOINT ["/tsidp-server"]
