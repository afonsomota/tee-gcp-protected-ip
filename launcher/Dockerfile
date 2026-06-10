# DEV ONLY — NOT the release recipe. Images built here will NOT match the
# released digest: production images are produced by the deterministic
# recipe in issue 012 (pinned-container build + crane wrap), and only those
# digests are admitted by the KMS attestation policy.
# Multi-stage build: static musl binary -> scratch image.
# Build with: docker buildx build --platform linux/amd64 -t <tag> launcher/
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
RUN touch src/main.rs && cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/launcher /launcher
# Confidential Space launch policy: allow stdout/stderr redirection to Cloud
# Logging on the production image (default is debug-only; without it stdout
# is unavailable and the first println! kills the workload).
LABEL "tee.launch_policy.log_redirect"="always"
EXPOSE 8080
ENTRYPOINT ["/launcher"]
