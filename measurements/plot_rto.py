from scapy.all import * # to read the pcap

from matplotlib import pyplot as plt
import os
import sys
import statistics
from math import ceil

dir_path = os.path.dirname(os.path.realpath(__file__))


client_output_filenames = {
  (
    'data/retransmission_timeout/rto_restart/save_4-ackrate_1_RTO_MAX_VALUE_24000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25/client_retransmission_timeout.out',
    'RTO plugin activated, RTO_MAX=24000ms',
    'RTO_value_timeout_if_RTOMAX=24000_bitrate_280000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25'
  ),
  (
    'data/retransmission_timeout/rto_stop/save_3-ackrate_1_RTO_MAX_VALUE_6000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25/client_retransmission_timeout.out',
    'RTO plugin activated, RTO_MAX=6000ms',
    'RTO_value_timeout_if_RTOMAX=6000_bitrate_280000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25'
  )
}
rto_values_predecessor_str = 'Printing rto and then rto max'
slowtmr_timestamps_str = 'IN TCP_SLOWTMR just before should_drop'

def plot_rto_curve(filename, title, savefilename):

  with open(filename, 'r') as fd:
    rto_values_follows = False
    rto_values = []
    timestamps = []
    for line in fd.readlines():
      if not rto_values_follows:
        # No RTO value on next line
        if rto_values_predecessor_str in line:
          rto_values_follows = True
        elif slowtmr_timestamps_str in line:
          print("Time !!: ", line)
          timestamps.append(float(line.split(' ')[-1].split('ms')[0]))
      else:
        # RTO value is here
        if line == '\n':
          continue
        print(line)
        rto_values.append(int(line.split('\n')[0]))
        rto_values_follows = False

    print(timestamps)
    print(rto_values)

    # Change timestamps so that the first one has value 0
    timestamps = [(ts-timestamps[0])/1000 for ts in timestamps]
    #timestamps = [i*500 for i in range(len(rto_values))]

    # Now we can plot the RTO values
    plt.plot(timestamps[:len(rto_values)], rto_values) # TODO: mettre au bon endroit sur les X
    # Comment mettre au bon endroit? Il suffit de check quand le RTO change, et là on sait qu'on vient de recevoir un paquet!
    plt.title(title, fontsize=14)
    plt.vlines(5.96, 0, 25000, colors='r')
    plt.vlines(20.96, 0, 25000, colors='r')
    plt.xlabel('Time [s]', fontsize=14)
    plt.ylabel('RTO value [ms]', fontsize=14)
    plt.xticks(fontsize=12)
    plt.yticks([0,1500,3000,6000,12000,24000], fontsize=12)
    plt.ylim(0, 25000)
    x_min = 5
    x_max = 23
    plt.xlim(x_min, x_max)
    plt.grid()
    plt.savefig(dir_path+ '/plots/' + savefilename, dpi=400, bbox_inches='tight')
    plt.show()

for fname, title, savefilename in client_output_filenames:
  plot_rto_curve(fname, title, savefilename)


##############################################################

def get_common_and_different_DATA_packets_and_ACKs(pcap_filenames):
  tap0_fd = rdpcap(pcap_filenames['tap0'])
  tap1_fd = rdpcap(pcap_filenames['tap1'])

  common_DATA_packets = []
  different_DATA_packets = []
  ACK_packets = []

  # tap1 should contain more packets
  ind_tap0 = len(tap0_fd) - 1
  for packet1 in reversed(tap1_fd): # reverse order: the last packet sent for a certain seqnum is the one that will be acknowledged
    try:
      ip_pkt1 = packet1[IP]
      tcp_pkt1 = ip_pkt1[TCP]
      print("tap1, packet seq: ", tcp_pkt1.seq, "src addr: ", ip_pkt1.src)
      if ip_pkt1.src != sender_addr:
        if ip_pkt1.src == receiver_addr:
          ACK_packets.insert(0, packet1)
        continue
    except: # not a TCP packet
      continue

    while ind_tap0 >= 0: # filter until empty list or TCP DATA packet
      try:
        ip_pkt0 = tap0_fd[ind_tap0][IP]
        tcp_pkt0 = ip_pkt0[TCP]
        if ip_pkt0.src == sender_addr:
          break
        else:
          ind_tap0 -= 1
          continue
      except:
        ind_tap0 -= 1
        continue

    if ind_tap0 == -1:
      # no more packets in tap0 but packets in tap1 => different ones
      different_DATA_packets.insert(0, packet1)

      continue

    # check if packets are similar
    if tcp_pkt1.seq == tcp_pkt0.seq: # considered to be the same
      common_DATA_packets.insert(0, packet1)
      ind_tap0 -= 1 # go to next packet on tap0

    else:
      print("Different seq: tap1 ({}): {}, tap0({}): {}".format(
        ip_pkt1.src,
        tcp_pkt1.seq,
        ip_pkt0.src,
        tcp_pkt0.seq))
      different_DATA_packets.insert(0, packet1)

  return common_DATA_packets, different_DATA_packets, ACK_packets


ack_threshold = 1
stop_pcap_filenames = {
  'tap0': dir_path + '/data/retransmission_timeout/rto_stop/save_3-ackrate_1_RTO_MAX_VALUE_6000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25/' +
                      'tap0_save_3-ackrate_1_RTO_MAX_VALUE_6000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25.pcapng',
  'tap1': dir_path + '/data/retransmission_timeout/rto_stop/save_3-ackrate_1_RTO_MAX_VALUE_6000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25/' +
                      'tap1_save_3-ackrate_1_RTO_MAX_VALUE_6000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25.pcapng'
}
restart_pcap_filenames = {
  'tap0': dir_path + '/data/retransmission_timeout/rto_restart/save_4-ackrate_1_RTO_MAX_VALUE_24000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25/' +
                      'tap0_save_4-ackrate_1_RTO_MAX_VALUE_24000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25.pcapng',
  'tap1': dir_path + '/data/retransmission_timeout/rto_restart/save_4-ackrate_1_RTO_MAX_VALUE_24000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25/' +
                      'tap1_save_4-ackrate_1_RTO_MAX_VALUE_24000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25.pcapng'
}

sender_addr = '192.168.1.4'
receiver_addr = '192.168.1.3'

#stop_pcap_fd = rdpcap(dir_path + '/data/retransmission_timeout/rto_stop/save_3-ackrate_1_RTO_MAX_VALUE_6000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25/' + stop_pcap_filename)
#restart_pcap_fd = rdpcap(dir_path + '/data/retransmission_timeout/rto_restart/save_4-ackrate_1_RTO_MAX_VALUE_24000_bitrate_280000_burst_28000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25/' + restart_pcap_filename)

def plot_pcap(pcap_filenames, title, savefilename):

  common_DATA, different_DATA, ACKs = get_common_and_different_DATA_packets_and_ACKs(pcap_filenames)
  print('common len: ', len(common_DATA), 'diff len: ', len(different_DATA), 'ACKs len: ', len(ACKs))
  common_DATA_seq = [x[IP][TCP].seq for x in common_DATA]
  different_DATA_seq = [x[IP][TCP].seq for x in different_DATA]
  ACKs_seq = [x[IP][TCP].ack for x in ACKs]

  first_ts = min(common_DATA[0].time, ACKs[0].time, different_DATA[0].time)

  common_DATA_ts = [x.time - first_ts for x in common_DATA]
  different_DATA_ts = [x.time - first_ts for x in different_DATA]
  ACKs_ts = [x.time - first_ts for x in ACKs]

  plt.figure()
  plt.scatter(common_DATA_ts, common_DATA_seq, s=13, label="DATA packets")
  plt.scatter(ACKs_ts, ACKs_seq, s=13, label="ACKs")
  plt.plot(different_DATA_ts, different_DATA_seq, 'xg', markersize=5, label="Filtered DATA packets")
  plt.rcParams.update({'legend.fontsize':13})
  plt.legend()
  x_min = 5
  x_max = 23
  y_min = 180000
  y_max = 250000
  plt.xlim(x_min, x_max)
  plt.ylim(y_min, y_max)
  plt.vlines(5.96, 0, 500_000, colors='r')
  plt.vlines(20.96, 0, 500_000, colors='r')
  plt.xlabel('Time [s]', fontsize=14)
  plt.ylabel('Sequence/ACK number', fontsize=14)
  plt.xticks(fontsize=12)
  plt.yticks(fontsize=12)
  plt.grid()
  plt.title(title, fontsize=14)
  plt.savefig(dir_path+ '/plots/' + savefilename, dpi=400, bbox_inches='tight')

  plt.show()
  return

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


plot_pcap(stop_pcap_filenames, "RTO plugin activated, RTO_MAX=6000ms", "RTO_seqnums_timeout_if_RTOMAX=6000_bitrate_280000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25")
plot_pcap(restart_pcap_filenames, "RTO plugin activated, RTO_MAX=24000ms", "RTO_seqnums_timeout_if_RTOMAX=24000_bitrate_280000_LOSSDURATION_15_LOSSPERCENTAGE_30_IFDELAY_25")

#plot_pcap(stop_pcap_fd, "UTO plugin activated, timeout after 5 seconds", 5)
#plot_pcap(restart_pcap_fd, "UTO plugin activated, timeout after 12 seconds", 12)
