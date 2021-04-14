#!/bin/bash

# stop on error
set -e

# for putting 100ms delay on tap0
#sudo tc qdisc add dev tap0 root netem delay 100ms

echo The client corresponds to tap1, the server corresponds to tap0

echo Setting both to delay 100ms and loss 30% on tap0

sudo tc qdisc replace dev tap1 root netem delay 100ms
sudo tc qdisc replace dev tap0 root netem delay 100ms loss 30%

