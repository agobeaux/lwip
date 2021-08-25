#include <stdio.h>
#include "lwip/tcp.h"
#include "getset.h"

int is_ack_needed(struct tcp_pcb *pcb) {
	u8_t num_rcv_unacked = get_num_rcv_unacked(pcb);
	tcp_ubpf_cnx_t *cnx = get_cnx(pcb);
	int max = get_input(cnx, 0);
	for (u8_t i = 0; ((int) i) < max; ++i) {
		// looping infinitely if max >= 2^8
	}

	if (num_rcv_unacked >= ACK_THRESHOLD) {
		help_printf_str("num_rcv_unacked >= threshold");
		return 1;
	} else {
		help_printf_str("Threshold has not been reached. Printing num_rcv_unacked and then ACK_THRESHOLD");
		help_printf_uint8_t(num_rcv_unacked);
		help_printf_uint8_t(ACK_THRESHOLD);
	}
	return 0;
}
