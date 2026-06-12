# DEV ONLY — NOT the release recipe. Images built here will NOT match the
# released digest: production images are produced by the deterministic
# recipe in issue 012 (pinned-container build + crane wrap), and only those
# digests are admitted by the KMS attestation policy.
# Multi-stage build: static musl launcher + llama.cpp server runtime.
# Build with:
#   docker buildx build --platform linux/amd64 \
#     [--build-arg MODEL_URL=https://...gguf] -t <tag> launcher/
FROM --platform=$BUILDPLATFORM rust:1.88-alpine AS build
RUN apk add --no-cache musl-dev
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# Cache dependency compilation with a stub main.
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --target x86_64-unknown-linux-musl \
    && rm -rf src
COPY src ./src
COPY prompts ./prompts
RUN touch src/main.rs && cargo build --release --target x86_64-unknown-linux-musl

# Optionally bake chat-model weights into the image (issue 006 allows
# plaintext weights; attestation-gated encrypted delivery is issue 007).
FROM alpine:3.22 AS weights
ARG MODEL_URL=""
RUN mkdir -p /models \
    && if [ -n "$MODEL_URL" ]; then \
         apk add --no-cache curl \
         && curl -fL --retry 3 -o /models/model.gguf "$MODEL_URL"; \
       fi

# Runtime: the official llama.cpp server image (pinned) provides
# /app/llama-server, which the launcher supervises on 127.0.0.1 (llama.rs).
FROM ghcr.io/ggml-org/llama.cpp:server@sha256:df320e983b2871d31fcb88165eedfcbd5156841d3d7dbd2b7ea3e85a1e1286a1
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/launcher /launcher
COPY --from=weights /models /models
ARG MODEL_URL=""
# Set only when weights are baked; empty means /chat serves 503.
ENV LLAMA_MODEL_PATH=${MODEL_URL:+/models/model.gguf}
# The base image defaults LLAMA_ARG_HOST to 0.0.0.0. The launcher already
# passes --host 127.0.0.1 explicitly (CLI beats env); neutralize the default
# anyway so nothing ever binds the model to a public interface.
ENV LLAMA_ARG_HOST=127.0.0.1
# Confidential Space launch policy: allow stdout/stderr redirection to Cloud
# Logging on the production image (default is debug-only; without it stdout
# is unavailable and the first println! kills the workload).
# Never add a tee.launch_policy.allow_env_override label listing any LLAMA_*
# variable: an operator who could set LLAMA_UPSTREAM would redirect decrypted
# user messages outside the enclave (see llama.rs module docs).
LABEL "tee.launch_policy.log_redirect"="always"
# Env vars the operator may set via tee-env-* VM metadata (issue 004 TLS).
# Deliberately narrow: only the ACME/TLS wiring is overridable, none of it
# can weaken the user-privacy story (TLS is defense-in-depth; the trust
# rides on HPKE + attestation), and none of it points at state — the ACME
# account and cert are fresh per boot and live only in enclave memory.
LABEL "tee.launch_policy.allow_env_override"="TLS_DOMAIN,ACME_CONTACT,ACME_DIRECTORY"
EXPOSE 8080 443
ENTRYPOINT ["/launcher"]
