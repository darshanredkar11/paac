FROM rust:1.85-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p authz-llm-proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/paac-proxy /usr/local/bin/paac-proxy
COPY paac.toml.example /app/paac.toml
EXPOSE 8080
CMD ["paac-proxy", "--config", "/app/paac.toml", "--listen", "0.0.0.0:8080"]
