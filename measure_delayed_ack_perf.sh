#!/bin/bash

# Stop on error
set -e

server_rate=1
client_rate="NOLIMIT"
bitrate=2000
burst=200
ACK_THRESHOLD=3

echo "This script is meant to be sourced as sudo (didn't work otherwise with timeout function)"


# iptables rules to update the transfers coming from tap0, tap1 and lwipbridge
if !(sudo iptables -L -v -n | grep -q "tap0"); then
  echo "SETTING IPTABLES RULES !!!"
  sudo iptables -I FORWARD 1 -i lwipbridge -j ACCEPT
  sudo iptables -I FORWARD 1 -i tap0 -j ACCEPT
  sudo iptables -I FORWARD 1 -i tap1 -j ACCEPT

  sudo iptables -I INPUT 1 -i lwipbridge -j ACCEPT
  sudo iptables -I INPUT 1 -i tap0 -j ACCEPT
  sudo iptables -I INPUT 1 -i tap1 -j ACCEPT
else
  echo "Not setting IPTABLES rules"
fi

# Compile delayed_ack_plugin; should be done by the server since it impacts the server
# At the moment, not a problem since eBPF codes are not preloaded!
cd ubpf/plugins/delayed_ack; make ACK_THRESHOLD=$ACK_THRESHOLD; cd ../../..;

# Create tap interfaces if not already done
if !(ifconfig | grep -q "tap0") || !(ifconfig | grep -q "tap1"); then
  echo "Creating interfaces"
  sudo ./contrib/ports/unix/setup-tapif
fi

# Modify bandwidth of the transfer
if (tc class show dev tap1 parent 5:0 | grep -q "class htb"); then
  sudo tc qdisc delete dev tap1 root handle 5:0 htb default 1
fi
sudo tc qdisc add dev tap1 root handle 5:0 htb default 1; sudo tc class add dev tap1 parent 5:0 classid 5:1 htb rate ${bitrate}bit burst ${burst}

# Compile lwiperf server and client
cd build
#rm -f ./contrib/ports/unix/example_app/example_app
#cmake .. -DCLIENT_OR_SERVER=SERVER; cmake --build .

rm -f ./build/contrib/ports/unix/example_app_client/example_app_client
cmake .. -DCLIENT_OR_SERVER=CLIENT; cmake --build .

rm -f ./build/contrib/ports/unix/example_app/example_app
cmake .. -DCLIENT_OR_SERVER=SERVER; cmake --build .

cd ..

# Launch lwiperf server and client
#sudo  ./build/contrib/ports/unix/example_app/example_app >server_delayed_ack.out 2>server_delayed_ack.err &
#sudo ./launch-server.sh &
#server_pid=$!
#sleep 1
#sudo  ./build/contrib/ports/unix/example_app_client/example_app_client >client_delayed_ack.out 2>client_delayed_ack.err &
#sudo ./launch-client.sh &

timeout 40s sudo ./build/contrib/ports/unix/example_app/example_app >server_delayed_ack.out 2>server_delayed_ack.err &
server_PID=$!


timeout 35s sudo  ./build/contrib/ports/unix/example_app_client/example_app_client >client_delayed_ack.out 2>client_delayed_ack.err &
client_PID=$!

wait

# After 30 seconds the lwiperf test should have finished, add 5 more seconds just in case for cmake ${aaazzz)
#sleep 35

# Stop scripts
#sudo kill ${server_pid}

# Append result to file
#grep -a "IPERF report" server_delayed_ack.out >> server_delayed_ack_perf_ackrate_${ACK_THRESHOLD}servrate_${server_rate}clirate_${client_rate}.txt
grep -a "IPERF report" measurements/data/client_delayed_ack.out >> client_delayed_ack_perf_ackrate_${ACK_THRESHOLD}_servrate_${server_rate}_clirate_${client_rate}_bitrate_${bitrate}_burst_${burst}.txt

echo "Performance of this transfer:"
tail -n 1 measurements/data/client_delayed_ack_perf_ackrate_${ACK_THRESHOLD}_servrate_${server_rate}_clirate_${client_rate}_bitrate_${bitrate}_burst_${burst}.txt
