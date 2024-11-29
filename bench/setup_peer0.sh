PEER0_IP=10.100.123.1

sudo ip l del dev peer0

WG_SUDO=1 cargo run --bin boringtun-cli peer0

# Dump conf

cat <<-EOF >peer0.conf.temp
[Interface]
PrivateKey = GOxrlZilSgaR5yF9Xqu94JyuTom4G00Mgg6S2UmYb04=
#pubkey cmDzGsB71iWCi05QdgcF+HVmjfc3+u1ER3nDH7erpCc=

[Peer]
PublicKey = 3wYfE1TbG5v0td0QtTTpGw52rT3C7sOe/MsZ7ZH2CBU=
#privkey aOwPSa4ISy87rgpaJsS8cUnLX4gsi8TGVPZCax4+gFo=
Endpoint = 192.168.1.97:51820
AllowedIPs = 10.100.123.2/32
EOF

sudo ip a add dev peer0 $PEER0_IP
sudo ip l set dev peer0 up
sudo wg setconf peer0 ./peer0.conf.temp
