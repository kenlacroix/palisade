# Palisade agent image for the self-contained demo.
#
# The final stage bundles the fake-vulnerable LiteLLM target (demo/fake_litellm.py)
# and runs it as a background process inside THIS container. The agent discovers
# services by parsing its own /proc/net/tcp, so co-locating the target in the
# agent's network namespace is what makes discover -> scan -> finding work
# end-to-end: discover sees the 0.0.0.0:4000 LISTEN socket (-> service=litellm,
# exposure=external) and the scan reaches it at <hostname>:4000 in the same netns.
#
# Build context must be the repo root so we can COPY both agent/ and demo/.

# --- build stage: static Go binary -----------------------------------------
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY agent/go.mod ./
COPY agent/ ./
ENV CGO_ENABLED=0
RUN go build -ldflags="-s -w" -o /out/palisade ./cmd/palisade

# --- final stage: minimal runtime with python for the target ----------------
FROM python:3.12-slim
WORKDIR /app

COPY --from=build /out/palisade /usr/local/bin/palisade
COPY demo/fake_litellm.py /app/fake_litellm.py
COPY agent/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Persisted enrollment state lives here (mounted as a volume in compose) so
# restarts reuse the existing agent identity instead of re-enrolling.
ENV PALISADE_HOME=/var/lib/palisade
RUN mkdir -p /var/lib/palisade

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
