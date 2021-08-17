from scapy.all import * # to read the pcap

from matplotlib import pyplot as plt
import os
import sys
import statistics
from math import ceil

dir_path = os.path.dirname(os.path.realpath(__file__))

# N = 3 # N is going from 1 to this value (3 here)
# print(len(sys.argv))
# print(sys.argv)
# if len(sys.argv) > 1:
#   N = int(sys.argv[1])

ack_threshold = 1
stop_pcap_filename = 'tap1_bitrate_280000_burst_28000_stop_after_5s.pcapng'
restart_pcap_filename = 'tap1_bitrate_280000_burst_28000_restart_after_5s.pcapng'

sender_addr = '192.168.1.4'
receiver_addr = '192.168.1.3'

stop_pcap_fd = rdpcap(dir_path + '/data/user_timeout/time_print_limited_bandwidth/' + stop_pcap_filename)
restart_pcap_fd = rdpcap(dir_path + '/data/user_timeout/time_print_limited_bandwidth/' + restart_pcap_filename)

def plot_pcap(pcap_file, title, timeout_value):
  x_min = 11.8
  x_max = 23.8
  sender_timestamps = []
  receiver_timestamps = []

  sender_seqs = []
  receiver_acks = []

  first_timestamp = pcap_file[0].time
  last_timestamp = pcap_file[-1].time

  # processing packets: getting timestamps and seqnums / acks
  for packet in pcap_file:
    try:
      ip_pkt = packet[IP]
      tcp_pkt = packet[IP][TCP]
      print(packet.time-first_timestamp)
      if float(packet.time-first_timestamp) < x_min or float(packet.time-first_timestamp) > x_max:
        continue
      else:
        print("ok")
      if ip_pkt.src == sender_addr and ip_pkt.dst == receiver_addr:
        sender_seqs.append(tcp_pkt.seq)
        sender_timestamps.append(packet.time-first_timestamp)
      elif ip_pkt.src == receiver_addr and ip_pkt.dst == sender_addr:
        receiver_acks.append(tcp_pkt.ack)
        receiver_timestamps.append(packet.time-first_timestamp)
      else:
        print('Unrecognized couple sent TCP packets: sender: {}, receiver: {}'.format(ip_pkt.src, ip_pkt.dst))
    except:
      pass

  # ploting seqnums and acks
  plt.figure()
  plt.scatter(sender_timestamps, sender_seqs, s=13)
  plt.scatter(receiver_timestamps, receiver_acks, s=13)
  plt.rcParams.update({'legend.fontsize':13})
  plt.title(title, fontsize=14)
  plt.xlim(x_min, min(x_max, float(last_timestamp)))
  plt.ylim(410000, 440000)
  plt.legend(["Sequence number", "ACK number"])
  plt.vlines(12.6, 0, 500_000, colors='r')
  plt.vlines(17.6, 0, 500_000, colors='r')
  plt.xlabel('Time [s]', fontsize=14)
  plt.ylabel('Sequence/ACK number', fontsize=14)
  plt.xticks(fontsize=12)
  plt.yticks(fontsize=12)
  plt.savefig(dir_path+ '/plots/' + 'UTO_timeout_after_' + str(timeout_value) + 'sec', dpi=400, bbox_inches='tight')
  plt.show()

plot_pcap(stop_pcap_fd, "UTO plugin activated, timeout after 5 seconds", 5)
plot_pcap(restart_pcap_fd, "UTO plugin activated, timeout after 12 seconds", 12)
