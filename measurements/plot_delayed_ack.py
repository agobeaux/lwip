from matplotlib import pyplot as plt
import os
import sys

dir_path = os.path.dirname(os.path.realpath(__file__))

N = 3 # N is going from 1 to this value (3 here)
print(len(sys.argv))
print(sys.argv)
if len(sys.argv) > 1:
  N = int(sys.argv[1])

server_rate=1
client_rate='NOLIMIT'
bitrate=2000
burst=200


def get_bw_from_line(line):
  _, _, total_bytes, ms_duration, _ = line.split(',')
  total_bytes = int(total_bytes.split(':')[1])
  ms_duration = int(ms_duration.split(':')[1])
  bandwidth = total_bytes*8 / ms_duration
  print(bandwidth)
  return bandwidth

bandwidths = []

for i in range(N):
  current_N = i+1
  filename = 'client_delayed_ack_perf_ackrate_{}_servrate_{}_clirate_{}_bitrate_{}_burst_{}.txt'.format(
    current_N, server_rate, client_rate, bitrate, burst
  )
  current_bandwidth = []
  with open(dir_path + '/data/' + filename, 'r') as file:
    print('Delayed ACK N={}'.format(current_N))
    for line in file.readlines():
      current_bandwidth.append(get_bw_from_line(line))
  bandwidths.append(current_bandwidth)

plt.boxplot(bandwidths)
plt.title('Bandwidth [kbit/s] when sending 1/N ACKs (N=' + str([i+1 for i in range(N)]) + ')')
plt.ylabel('Bandwidth [kbit/s]')
plt.xlabel('Value of N')
plt.grid()
plt.savefig(dir_path+ '/plots/' + 'Delayed_ack_bandwidth_N=' + str(N), dpi=400)
plt.show()
