PEER1_IP=10.100.123.2

sudo ip l del dev peer1

WG_SUDO=1 cargo run --bin boringtun-cli peer1

# Dump conf

cat <<-EOF >peer1.conf.temp
[Interface]
PrivateKey = aOwPSa4ISy87rgpaJsS8cUnLX4gsi8TGVPZCax4+gFo=
ListenPort = 51820

[Peer]
PublicKey = cmDzGsB71iWCi05QdgcF+HVmjfc3+u1ER3nDH7erpCc=
AllowedIPs = 10.100.123.1/32
EOF

sudo ip a add dev peer1 $PEER1_IP
sudo ip l set dev peer1 up
sudo ip r add dev peer1 10.100.123.0/24
sudo wg setconf peer1 ./peer1.conf.temp
