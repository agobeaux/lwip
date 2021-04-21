#!/bin/bash

# Stop on error
set -e

server_rate=1024
client_rate=40960
ACK_THRESHOLD=2

# Compile delayed_ack_plugin; should be done by the server since it impacts the server
# At the moment, not a problem since eBPF codes are not preloaded!
cd ubpf/plugins/delayed_ack; make ACK_THRESHOLD=$ACK_THRESHOLD; cd ../../..;

# Create tap interfaces if not already done
if !(ifconfig | grep -q "tap0") || !(ifconfig | grep -q "tap1"); then
  echo "Creating interfaces"
  sudo ./contrib/ports/unix/setup-tapif
fi
# Compile server and client
# TODO

# Modify bandwidth of the transfer
sudo tc qdisc replace dev tap0 root tbf rate ${server_rate}kbit latency 0.1ms burst 10000000
sudo tc qdisc replace dev tap1 root tbf rate ${client_rate}kbit latency 0.1ms burst 10000000

# Compile lwiperf server and client
cd build
#rm -f ./contrib/ports/unix/example_app/example_app
#cmake .. -DCLIENT_OR_SERVER=SERVER; cmake --build .

rm -f ./build/contrib/ports/unix/example_app_client/example_app_client
cmake .. -DCLIENT_OR_SERVER=CLIENT; cmake --build .

cd ..

# Launch lwiperf server and client
#sudo  ./build/contrib/ports/unix/example_app/example_app >server_delayed_ack.out 2>server_delayed_ack.err &
#sudo ./launch-server.sh &
#server_pid=$!
#sleep 1
#sudo  ./build/contrib/ports/unix/example_app_client/example_app_client >client_delayed_ack.out 2>client_delayed_ack.err &
#sudo ./launch-client.sh &

timeout 35s sudo  ./build/contrib/ports/unix/example_app_client/example_app_client >client_delayed_ack.out 2>client_delayed_ack.err || echo "Client timed out"

# After 30 seconds the lwiperf test should have finished, add 5 more seconds just in case for cmake ${aaazzz)
#sleep 35

# Stop scripts
#sudo kill ${server_pid}

# Append result to file
#grep -a "IPERF report" server_delayed_ack.out >> server_delayed_ack_perf_ackrate_${ACK_THRESHOLD}servrate_${server_rate}clirate_${client_rate}.txt
grep -a "IPERF report" client_delayed_ack.out >> client_delayed_ack_perf_ackrate_${ACK_THRESHOLD}servrate_${server_rate}clirate_${client_rate}.txt

echo "Performance of this transfer:"
tail -n 1 client_delayed_ack_perf_ackrate_${ACK_THRESHOLD}servrate_${server_rate}clirate_${client_rate}.txt
