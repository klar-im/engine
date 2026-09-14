# klar-milterd, built from this source tree, shipped without weights.
#
# Build from the repository root (the engine is a sibling of postfix/):
#     docker build -f postfix/docker/Dockerfile -t klar-milterd .
#
# Run with a volume for the model and the event store, and the licence accepted:
#     docker run -e KLAR_ACCEPT_MODEL_LICENSE=1 -v klar-data:/var/lib/klar -p 8891:8891 klar-milterd
#
# First start fetches the released model into /var/lib/klar/model (postfix/
# scripts/fetch_model.sh, sha256-verified against postfix/model/released-
# manifest.json) and refuses to start until the model licence is accepted; the
# image itself carries no weights, so publishing it redistributes code only
# (AGPLv3), never the CC-BY-NC-4.0 model. Later starts find the model in the
# volume and skip the download. Configure with your own toml at /etc/klar/
# klar-milterd.toml (default: the Stalwart-shaped one, listening on all
# interfaces so an MTA in another container can reach it).

# --- build ------------------------------------------------------------------
FROM ubuntu:24.04 AS build
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake pkg-config git curl ca-certificates \
    libgmime-3.0-dev libarchive-dev nlohmann-json3-dev libxxhash-dev \
    libmilter-dev libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Build parallelism, read by engine/scripts/build.sh. Default: the builder's
# cores; pass --build-arg CPU_COUNT=1 on a small box.
ARG CPU_COUNT
ENV CPU_COUNT=${CPU_COUNT}
# Two layers: the engine (llama.cpp download + the long compile) first, the
# milter second, so a change under postfix/ rebuilds only the milter. setup.sh's
# Linux branch installs the pinned llama.cpp release into engine/deps/llama-install
# and configures cmake; its apt step is done above (KLAR_SKIP_APT) and its model
# download does not exist in a public tree.
COPY engine/ engine/
RUN KLAR_SKIP_APT=1 bash engine/scripts/setup.sh && bash engine/scripts/build.sh
COPY postfix/ postfix/
RUN bash postfix/scripts/build.sh && bash postfix/scripts/install.sh /opt/klar

# --- runtime ----------------------------------------------------------------
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgmime-3.0-0 libarchive13t64 libmilter1.0.1 libsqlite3-0 libgomp1 \
    libstdc++6 curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin klarmilter \
    && mkdir -p /var/lib/klar /etc/klar && chown klarmilter:klarmilter /var/lib/klar
COPY --from=build /opt/klar/bin /opt/klar/bin
COPY postfix/scripts/fetch_model.sh /opt/klar/fetch_model.sh
COPY postfix/model/released-manifest.json /opt/klar/released-manifest.json
COPY postfix/docker/klar-milterd-entrypoint.sh /opt/klar/entrypoint.sh
COPY stalwart/config/klar-milterd.toml /etc/klar/klar-milterd.toml
# In a container the MTA is another host: bind all interfaces, not loopback.
RUN sed -i 's#^listen = .*#listen = "inet:8891@0.0.0.0"#; s#^health_listen = .*#health_listen = "0.0.0.0:8892"#' /etc/klar/klar-milterd.toml \
    && printf '\n# Container: readiness is probed from outside this namespace.\nhealth_allow_public = true\n' >> /etc/klar/klar-milterd.toml \
    && chmod 0755 /opt/klar/entrypoint.sh /opt/klar/fetch_model.sh
ENV LD_LIBRARY_PATH=/opt/klar/bin
USER klarmilter
VOLUME /var/lib/klar
EXPOSE 8891 8892
# The first start downloads the ~400 MB model into the volume before /readyz can
# answer, so the start period covers a slow link (1 MB/s is ~7 min), not just
# the model load. Failures inside it do not count towards the retries.
# stalwart/scripts/test_e2e.sh reads this number for its own --wait-timeout.
HEALTHCHECK --interval=10s --timeout=3s --start-period=900s --retries=6 \
    CMD curl -fsS http://127.0.0.1:8892/readyz || exit 1
ENTRYPOINT ["/opt/klar/entrypoint.sh"]
CMD ["--config", "/etc/klar/klar-milterd.toml"]
