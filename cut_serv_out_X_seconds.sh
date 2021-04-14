#!/bin/bash

# stop on error
set -e

# for putting 100ms delay on tap0
#sudo tc qdisc add dev tap0 root netem delay 100ms

X=5
echo Number of args $#

if [[ $# -gt 0 ]]; then
	X=$1
fi

echo The server corresponds to tap0 and HW_ADDR_5=0x01 and IP addr 192.168.1.3
echo Loss 100% on tap0 during $X seconds
sudo tc qdisc replace dev tap0 root netem loss 100% delay 100ms

sleep $X

echo Loss 0% again on tap0
sudo tc qdisc replace dev tap0 root netem delay 100ms
