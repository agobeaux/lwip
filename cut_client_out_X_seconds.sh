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

echo The client corresponds to tap1 and HW_ADDR_5=0x88 and IP addr 192.168.1.4

echo Loss 100% on tap1 during $X seconds
sudo tc qdisc replace dev tap1 root netem loss 100%
sleep $X

echo Loss 0% again on tap1
sudo tc qdisc delete dev tap1 root netem
