# Multi-stage build: static musl binary -> scratch image.
# Build with: docker buildx build --platform linux/amd64 -t <tag> launcher/
FROM --platform=$BUILDPLATFORM rust:1.85-alpine AS build
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
EXPOSE 8080
ENTRYPOINT ["/launcher"]
