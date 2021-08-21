#include "lwip/tcp.h"
#include "getset.h"

int is_ack_needed(struct tcp_pcb *pcb) {
	u8_t num_rcv_unacked = get_num_rcv_unacked(pcb);
	if (num_rcv_unacked >= ACK_THRESHOLD) {
		help_printf_str("num_rcv_unacked >= threshold");
		return 1;
	}
	return 0;
}
