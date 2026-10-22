FROM rust:1.87-slim AS build
WORKDIR /src
COPY core/daemon/Cargo.toml core/daemon/Cargo.lock* ./core/daemon/
COPY core/daemon/src ./core/daemon/src
COPY contracts ./contracts
WORKDIR /src/core/daemon
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -r -m kronos
COPY --from=build /src/core/daemon/target/release/kronos-daemon /usr/local/bin/kronos-daemon
USER kronos
ENV KRONOS_STATE_DIR=/home/kronos/.kronos
VOLUME ["/home/kronos/.kronos"]
ENTRYPOINT ["kronos-daemon"]
CMD ["up"]
