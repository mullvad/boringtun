# Steps to run
## Build base container
```bash
podman build -t benchy
```

## Run the peers
```bash
podman-compose up
```

Now two containers have been spun up: `wireguard-server` & `wireguard-client` with `wireguard-go` installed & configured.
`wireguard-server` will have ip `10.13.13.1` and `wireguard-client` will have ip `10.13.13.2`.
Feel free to run iperf3 between them!
