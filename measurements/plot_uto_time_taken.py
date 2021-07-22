
from matplotlib import pyplot as plt
import os
import sys
import statistics
from math import ceil
from collections import defaultdict

dir_path = os.path.dirname(os.path.realpath(__file__))

# N = 3 # N is going from 1 to this value (3 here)
# print(len(sys.argv))
# print(sys.argv)
# if len(sys.argv) > 1:
#   N = int(sys.argv[1])

ack_threshold = 1
filenames = ['client_user_timeout.out', 'server_user_timeout.out']

parsing_option = defaultdict(lambda: defaultdict(lambda: []))
send_seg_update = defaultdict(lambda: defaultdict(lambda: []))
empty_ack = defaultdict(lambda: defaultdict(lambda: []))

def get_number_from_line(line):
	return float(line.split('ms')[-2].split(': ')[-1])

for filename in filenames:
	cli_or_serv = filename.split('_')[0]
	with open(dir_path + '/data/user_timeout/time_print_limited_bandwidth/' + filename, 'r') as file:
		for line in file.readlines():
			if "Time taken" not in line:
				continue
			
			if "to handle arguments for VM" in line:
				time_handle_VM_args = get_number_from_line(line)
			elif "to malloc memory for the VM" in line:
				time_malloc_VM_mem = get_number_from_line(line)
			elif "to read the eBPF program" in line:
				time_read_eBPF_prog = get_number_from_line(line)
			elif "to create VM" in line:
				time_create_VM = get_number_from_line(line)
			elif "to load the code" in line:
				time_load_code = get_number_from_line(line)
			elif "to execute the code without using JIT" in line:
				time_exec_noJIT = get_number_from_line(line)
				uses_jit = False
			elif "to destroy the VM" in line:
				time_destroy_VM = get_number_from_line(line)
			elif "for run_ubpf_args except" in line:
				time_run_ubpf_args = get_number_from_line(line)
			elif "to parse the option" in line:
				time_parse_option = get_number_from_line(line)
				parsing_option[cli_or_serv]['time_parse_option'].append(time_parse_option)
				parsing_option[cli_or_serv]['time_handle_VM_args'].append(time_handle_VM_args)
				parsing_option[cli_or_serv]['time_malloc_VM_mem'].append(time_malloc_VM_mem)
				parsing_option[cli_or_serv]['time_read_eBPF_prog'].append(time_read_eBPF_prog)
				parsing_option[cli_or_serv]['time_create_VM'].append(time_create_VM)
				parsing_option[cli_or_serv]['time_load_code'].append(time_load_code)
				parsing_option[cli_or_serv]['time_exec_noJIT'].append(time_exec_noJIT)
				parsing_option[cli_or_serv]['time_destroy_VM'].append(time_destroy_VM)
				parsing_option[cli_or_serv]['time_run_ubpf_args'].append(time_run_ubpf_args)
			elif "by tcp_output_segment" in line:
				time_tcp_output_seg = get_number_from_line(line)
			elif "to send the segment and update" in line:
				time_send_seg_and_update = get_number_from_line(line)
				send_seg_update[cli_or_serv]['time_handle_VM_args'].append(time_handle_VM_args)
				send_seg_update[cli_or_serv]['time_malloc_VM_mem'].append(time_malloc_VM_mem)
				send_seg_update[cli_or_serv]['time_read_eBPF_prog'].append(time_read_eBPF_prog)
				send_seg_update[cli_or_serv]['time_create_VM'].append(time_create_VM)
				send_seg_update[cli_or_serv]['time_load_code'].append(time_load_code)
				send_seg_update[cli_or_serv]['time_exec_noJIT'].append(time_exec_noJIT)
				send_seg_update[cli_or_serv]['time_destroy_VM'].append(time_destroy_VM)
				send_seg_update[cli_or_serv]['time_run_ubpf_args'].append(time_run_ubpf_args)
				send_seg_update[cli_or_serv]['time_ebpf_write_tcp_uto_option'].append(time_ebpf_write_tcp_uto_option)
				send_seg_update[cli_or_serv]['time_write_TCP_options_pluglet'].append(time_write_TCP_options_pluglet)
				send_seg_update[cli_or_serv]['time_tcp_output_seg'].append(time_tcp_output_seg)
				send_seg_update[cli_or_serv]['time_send_seg_and_update'].append(time_send_seg_and_update)
			elif "to write TCP options implemented with a pluglet" in line:
				time_write_TCP_options_pluglet = get_number_from_line(line)
			elif "by tcp_send_empty_ack" in line:
				time_tcp_send_empty_ack = get_number_from_line(line)
				empty_ack[cli_or_serv]['time_handle_VM_args'].append(time_handle_VM_args)
				empty_ack[cli_or_serv]['time_malloc_VM_mem'].append(time_malloc_VM_mem)
				empty_ack[cli_or_serv]['time_read_eBPF_prog'].append(time_read_eBPF_prog)
				empty_ack[cli_or_serv]['time_create_VM'].append(time_create_VM)
				empty_ack[cli_or_serv]['time_load_code'].append(time_load_code)
				empty_ack[cli_or_serv]['time_exec_noJIT'].append(time_exec_noJIT)
				empty_ack[cli_or_serv]['time_destroy_VM'].append(time_destroy_VM)
				empty_ack[cli_or_serv]['time_run_ubpf_args'].append(time_run_ubpf_args)
				empty_ack[cli_or_serv]['time_ebpf_write_tcp_uto_option'].append(time_ebpf_write_tcp_uto_option)
				empty_ack[cli_or_serv]['time_tcp_send_empty_ack'].append(time_tcp_send_empty_ack)
			elif "by the timeouts (check+remove)" in line:
				time_timeouts_checks_and_remove = get_number_from_line(line)
			elif "by the timeouts checks" in line:
				time_timeouts_checks = get_number_from_line(line)
			elif "by rto check" in line:
				time_rto_check = get_number_from_line(line)
			elif "by ebpf_should_drop_connection_rto" in line:
				time_ebpf_should_drop_connection_rto = get_number_from_line(line)
			elif "by ebpf_write_tcp_uto_option" in line:
				is_uto = True
				is_rto = False
				time_ebpf_write_tcp_uto_option = get_number_from_line(line)
			elif "by ebpf_write_tcp_rto_option" in line:
				is_rto = True
				is_uto = False
				time_ebpf_write_tcp_rto_option = get_number_from_line(line)
			else:
				print("LINE UNRECOGNIZED:", line)
				
positions = [i for i in range(1, 1+len(parsing_option['client'].keys()))]
fig = plt.figure()
bp = plt.boxplot(parsing_option['client'].values(), positions, patch_artist=True)
#plt.legend(parsing_option.keys())
plt.yscale('log')
#plt.xticks(positions, parsing_option['client'].keys(), rotation=-45)
plt.xticks(positions, parsing_option['client'].keys())
fig.autofmt_xdate()
plt.tight_layout()
plt.title('Graph showing the duration of the parsing operations on the sender')
medians = [med.get_ydata()[0] for med in bp['medians']]
print(medians)
plt.savefig(dir_path+ '/plots/' + 'UTO_duration_parsing_sender', dpi=400, bbox_inches='tight')
plt.show()

positions = [i for i in range(1, 1+len(parsing_option['server'].keys()))]
fig = plt.figure()
bp = plt.boxplot(parsing_option['server'].values(), positions, patch_artist=True)
#plt.legend(parsing_option.keys())
plt.yscale('log')
#plt.xticks(positions, parsing_option['server'].keys(), rotation=-45)
plt.xticks(positions, parsing_option['server'].keys())
fig.autofmt_xdate()
plt.tight_layout()
plt.title('Graph showing the duration of the parsing operations on the receiver')
medians = [med.get_ydata()[0] for med in bp['medians']]
print(medians)
plt.savefig(dir_path+ '/plots/' + 'UTO_duration_parsing_receiver', dpi=400, bbox_inches='tight')
plt.show()


positions = [i for i in range(1, 1+len(send_seg_update['client'].keys()))]
fig = plt.figure()
bp = plt.boxplot(send_seg_update['client'].values(), positions, patch_artist=True)
#plt.legend(parsing_option.keys())
#plt.yscale('log')
#plt.xticks(positions, send_seg_update['client'].keys(), rotation=-45)
plt.xticks(positions, send_seg_update['client'].keys())
fig.autofmt_xdate()
plt.tight_layout()
plt.title('Graph showing the duration of the send_segment writing operations on the sender')
medians = [med.get_ydata()[0] for med in bp['medians']]
print(medians)
plt.savefig(dir_path+ '/plots/' + 'UTO_duration_send_seg_sender', dpi=400, bbox_inches='tight')
plt.show()


positions = [i for i in range(1, 1+len(empty_ack['server'].keys()))]
fig = plt.figure()
bp = plt.boxplot(empty_ack['server'].values(), positions, patch_artist=True)
#plt.legend(parsing_option.keys())
#plt.yscale('log')
#plt.xticks(positions, empty_ack['server'].keys(), rotation=-45)
plt.xticks(positions, empty_ack['server'].keys())
fig.autofmt_xdate()
plt.tight_layout()
plt.title('Graph showing the duration of the empty_ack writing operations on the receiver')
medians = [med.get_ydata()[0] for med in bp['medians']]
print(medians)
plt.savefig(dir_path+ '/plots/' + 'UTO_duration_empty_ack_receiver', dpi=400, bbox_inches='tight')
plt.show()

