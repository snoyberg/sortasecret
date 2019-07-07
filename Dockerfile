FROM rust:1.35.0 AS build

COPY ./ ./
RUN mkdir -p /artifacts/
RUN cargo build --release
RUN cp target/release/sortasecret /artifacts/

FROM fpco/pid1:18.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install ca-certificates libssl-dev && rm -rf /var/lib/apt/lists/*
COPY --from=build /artifacts/sortasecret /usr/bin/
