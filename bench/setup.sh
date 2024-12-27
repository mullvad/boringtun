#!/usr/bin/env bash
set -eu

sudo ip a add dev peer0 $PEER0_IP
sudo ip l set dev peer0 up
sudo ip r add dev peer0 10.100.123.0/24
sudo wg setconf peer0 ./peer0.conf.temp
