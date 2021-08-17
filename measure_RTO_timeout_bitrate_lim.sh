#!/bin/bash

# Stop on error
set -ex

server_rate="NOLIMIT"
client_rate=1
bitrate=100000
burst=10000

if [[ $# -ne 2 && $# -ne 3 ]]; then
  echo "Usage : source ./measure_RTO_timeout_bitrate_lim.sh RTO_MAX_VALUE (in seconds) BIT_RATE (bits/s) [20% loss duration (in seconds)]"
  return
fi

LOSS_DURATION=0
if [[ $# -eq 3 ]]; then
	LOSS_DURATION=$3
fi

ACK_THRESHOLD=1
UTO_TIMEOUT=300 # make sure UTO does not intervene, even though it shouldn't be used
RTO_MAX_VALUE=$1
# TODO remettre? if delay method
#IF_DELAY=$2
bitrate=$2
burst=$(($bitrate/10))
IF_DELAY=25  # IF_DELAY=0; LOSS_PERCENTAGE=20, parfois on tombe sur un graphe comme si on coupait (comme UTO), joli pour plot_rto mais sinon bof pour wireshark I/O graph
LOSS_PERCENTAGE=30

echo "This script is meant to be sourced as sudo (didn't work otherwise with timeout function)"

# Create tap interfaces if not already done
if [[ !(sudo ifconfig | grep -q "tap0") || !(sudo ifconfig | grep -q "tap1") ]]; then
  echo "Creating interfaces"
  sudo ./contrib/ports/unix/setup-tapif
fi


# iptables rules to update the transfers coming from tap0, tap1 and lwipbridge
if ! (sudo iptables -L -v -n | grep -q "tap0"); then
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
cd ubpf/plugins/user_timeout; make UTO_TIMEOUT=$UTO_TIMEOUT; cd ../../..;
cd ubpf/plugins/retransmission_timeout; make RTO_MAX_VALUE=$RTO_MAX_VALUE; cd ../../..;


# Modify bandwidth of the transfer sender (client) -> receiver (server)
#if (tc class show dev tap0 parent 5:0 | grep -q "class htb"); then
#  sudo tc qdisc delete dev tap0 root handle 5:0 htb default 1
#fi

# doesn't work if (tc class show dev tap1 parent 5:0 | grep -q "class netem"); then
#  sudo tc qdisc delete dev tap1 root handle 5:0 netem
#fi

#sudo tc qdisc add dev tap0 root handle 5:0 htb default 1
# doesn't work sudo tc qdisc add dev tap1 root handle 5:0 netem
if sudo tc qdisc show | grep "tap0" | grep -q "netem"; then
	#sudo tc qdisc delete dev tap0 root netem
	#sudo tc qdisc delete dev tap1 root netem
  echo "did not delete tc qdisc tap0 and tap1"
fi

if sudo tc qdisc show | grep "lwipbridge" | grep -q "netem"; then
	sudo tc qdisc delete dev lwipbridge root netem
fi


if [[ ${IF_DELAY} -ne 0 ]]; then
	if_delay_str="delay ${IF_DELAY}ms"
fi

if [[ ${LOSS_PERCENTAGE} -ne 0 ]]; then
	loss_perc_str="loss ${LOSS_PERCENTAGE}%"
fi


# TODO: put them back? Useful to delay packets. Doesn't work with htb in its current state.
#sudo tc qdisc replace dev tap1 root netem ${if_delay_str}
#sudo tc qdisc replace dev tap0 root netem ${if_delay_str}


# Modify bandwidth of the transfer, trying on lwipbridge
if (tc class show dev lwipbridge parent 5:0 | grep -q "class htb"); then
  sudo tc qdisc delete dev lwipbridge root handle 5:0 htb default 1
fi
#TOOO: remettre?
#sudo tc qdisc add dev lwipbridge root handle 5:0 htb default 1; sudo tc class add dev lwipbridge parent 5:0 classid 5:1 htb rate ${bitrate}bit burst ${burst}

# Modify bandwidth of the transfer (sender -> receiver, limit the upload rate)
if (tc class show dev tap0 parent 5:0 | grep -q "class htb"); then
  sudo tc qdisc delete dev tap0 root handle 5: htb default 11
fi
sudo tc qdisc add dev tap0 root handle 5: htb default 11
sudo tc class add dev tap0 parent 5: classid 5:1 htb rate ${bitrate}bit burst ${burst}
sudo tc class add dev tap0 parent 5:1 classid 5:11 htb rate ${bitrate}bit burst ${burst}
sudo tc qdisc add dev tap0 parent 5:11 handle 10: netem delay 0ms






#if [[ ${LOSS_PERCENTAGE} -ne 0 ]]; then
#	sudo tc qdisc replace dev tap0 root netem loss ${LOSS_PERCENTAGE}% delay 30ms
#fi
#sudo tc class add dev tap0 parent 5:0 classid 5:1 htb rate ${bitrate}bit burst ${burst}
# doesn't work sudo tc class add dev tap1 parent 5:0 classid 5:1 netem loss 25%
# AUTRE IDEE: pourquoi ne pas juste limiter la sender window pour avoir max 4 paquets et engendrer des loss avec netem?
# ça ne requiert plus de mettre htb!!!

# Compile lwiperf server and client
cd build
#rm -f ./contrib/ports/unix/example_app/example_app
#cmake .. -DCLIENT_OR_SERVER=SERVER; cmake --build .

rm -f ./build/contrib/ports/unix/example_app_client/example_app_client
cmake .. -DCLIENT_OR_SERVER=CLIENT; cmake --build .

rm -f ./build/contrib/ports/unix/example_app/example_app
cmake .. -DCLIENT_OR_SERVER=SERVER; cmake --build .

cd ..

timeout 40s sudo ./build/contrib/ports/unix/example_app/example_app >measurements/data/retransmission_timeout/server_retransmission_timeout.out 2>measurements/data/retransmission_timeout/server_retransmission_timeout.err &
server_PID=$!


timeout 35s sudo  ./build/contrib/ports/unix/example_app_client/example_app_client >measurements/data/retransmission_timeout/client_retransmission_timeout.out 2>measurements/data/retransmission_timeout/client_retransmission_timeout.err &
client_PID=$!

if [[ $LOSS_DURATION -gt 0 ]]; then
	sleep 6
  tc qdisc replace dev tap1 root netem ${if_delay_str} # delay on ACK packets
	sudo tc qdisc replace dev tap0 parent 5:11 handle 10: netem ${loss_perc_str} ${if_delay_str} # loss on DATA packets
	sleep $LOSS_DURATION
  tc qdisc delete dev tap1 root netem ${if_delay_str}
	sudo tc qdisc replace dev tap0 parent 5:11 handle 10: netem delay 0ms
fi

wait

# After 30 seconds the lwiperf test should have finished, add 5 more seconds just in case for cmake ${aaazzz)
#sleep 35

# Stop scripts
#sudo kill ${server_pid}
sleep 1
# Append result to file
#grep -a "IPERF report" server_retransmission_timeout.out >> server_retransmission_timeout_perf_ackrate_${ACK_THRESHOLD}servrate_${server_rate}clirate_${client_rate}.txt

grep -a "IPERF report" measurements/data/retransmission_timeout/client_retransmission_timeout.out >> measurements/data/retransmission_timeout/client_retransmission_timeout_perf_ackrate_${ACK_THRESHOLD}_RTO_MAX_VALUE_${RTO_MAX_VALUE}_bitrate_${bitrate}_burst_${burst}_LOSSDURATION_${LOSS_DURATION}_LOSSPERCENTAGE_${LOSS_PERCENTAGE}_IFDELAY_${IF_DELAY}.txt

echo "Performance of this transfer:"
tail -n 1 measurements/data/retransmission_timeout/client_retransmission_timeout_perf_ackrate_${ACK_THRESHOLD}_RTO_MAX_VALUE_${RTO_MAX_VALUE}_bitrate_${bitrate}_burst_${burst}_LOSSDURATION_${LOSS_DURATION}_LOSSPERCENTAGE_${LOSS_PERCENTAGE}_IFDELAY_${IF_DELAY}.txt
