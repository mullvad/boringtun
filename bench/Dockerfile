# Start with the linuxserver/wireguard base image
FROM alpine:latest

# Install wireguard-go (userspace WireGuard implementation)
#RUN apt update && apt install -y git golang
# Install build essentials, wireguard-go & benchmarking tools
RUN apk update && apk upgrade && apk add git crun bash go wireguard-tools iperf3

# Build & install wireguard-go
# RUN git clone https://git.zx2c4.com/wireguard-go && cd wireguard-go && go build && mv wireguard /bin/

# Build & install boringtun
RUN apk add clang lld curl
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y \
    --default-toolchain stable \
    --profile minimal
ENV PATH="$PATH:/root/.cargo/bin/"
RUN git clone -b bench https://github.com/mullvad/boringtun.git && cd boringtun && cargo build --release && cp target/release/boringtun-cli /bin/wireguard

# Copy init script to container
COPY init.sh /

ENTRYPOINT ["/bin/bash", "/init.sh"]
