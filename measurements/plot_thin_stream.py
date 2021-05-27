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
loss_percentages = [0, 5, 10, 15, 20] #[0, 10, 20, -1]
num_packets_out_thresholds = [-1, 4]


def get_duration_from_line(line):
  report_type, _, total_bytes, ms_duration, _ = line.split(',')
  if "IPERF report: type=1" not in report_type:
    return None
  total_bytes = int(total_bytes.split(':')[1])
  ms_duration = int(ms_duration.split(':')[1])
  return ms_duration

durations = []

for num_packets_out_threshold in num_packets_out_thresholds:
  durations_for_numPackOut_threshold = []
  for loss_percentage in loss_percentages:
    filename = 'client_thin_stream_perf_ackrate__lossperc_{1}_numPacketsOutThreshold_{2}.txt'.format(
      ack_threshold, loss_percentage, num_packets_out_threshold
    )
    current_duration = []
    with open(dir_path + '/data/thin_stream/' + filename, 'r') as file: # TODO: retirer le backup du path
      for line in file.readlines():
        duration = get_duration_from_line(line)
        if duration is not None:
          current_duration.append(duration)
    durations_for_numPackOut_threshold.append(current_duration)
  
  durations.append(durations_for_numPackOut_threshold)


def is_even(x):
  if x%2 == 1:
    return -1
  return 1
def odd(x):
  if x%2 == 0:
    return x-1
  return x
positions_without_thin_stream = [1.5*i-0.3 for i in range(1, 1+len(loss_percentages))]
positions_with_thin_stream = [1.5*i+0.3 for i in range(1, 1+len(loss_percentages))]
fig, ax = plt.subplots()
bp_without = ax.boxplot(durations[0], positions=positions_without_thin_stream, notch=True,
                        patch_artist=True, boxprops=dict(facecolor="C0"))
bp_with = ax.boxplot(durations[1], positions=positions_with_thin_stream, notch=True,
                     patch_artist=True, boxprops=dict(facecolor="C2"))

ax.legend([bp_without["boxes"][0], bp_with["boxes"][0]], ['Default configuration', 'Using thin_stream detection'])
for index, duration_list in enumerate(durations):
  thin_stream = "using thin_stream" if index % 2 == 1 else "without thin_stream"
  print('When loss_percentage = {}, the median duration is {} {}'.format(loss_percentages[index//2], statistics.median(duration_list), thin_stream))

max_duration = 0
for duration_list_for_case in durations:
  for duration_list in duration_list_for_case:
    for duration_value in duration_list:
      max_duration = max(max_duration, duration_value)
plt.ylim([0, 5000*ceil(max_duration/5000)+5])
plt.title('Transfer duration [ms] with and without thin_stream detection\naccording to different data packet loss percentage')
plt.ylabel('Transfer duration [ms]')
plt.xlabel('Data packet loss percentage [%]')
positions = positions_without_thin_stream + positions_with_thin_stream
xticks = loss_percentages*2
print('xticks', xticks, 'positions', positions)
plt.xticks(positions, xticks)
plt.grid()
plt.savefig(dir_path+ '/plots/' + 'Thin_stream_loss_percentages=' + str(loss_percentages), dpi=400)
plt.show()
