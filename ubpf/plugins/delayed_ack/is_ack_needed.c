#include <stdio.h>
#include "lwip/tcp.h"
#include "getset.h"

int is_ack_needed(struct tcp_pcb *pcb) {
	char *str = "Currently launching eBPF function is_ack_needed!\n";
	help_printf_str(str);

	/*
	u32_t last_acked_seqno = get_last_acked_seqno(pcb);
	help_printf_str("last_acked_seqno");
	help_printf_uint32_t(last_acked_seqno);
	u32_t nextseqnotosend = get_next_seqno(pcb);
	help_printf_str("nextseqnotosend");
	help_printf_uint32_t(nextseqnotosend);
	*/

	u8_t num_rcv_unacked = get_num_rcv_unacked(pcb);
	help_printf_uint8_t(num_rcv_unacked);
	/* help_printf_uint32_t(get_tmr(pcb)); */
	//help_printf_uint32_t(pcb->tmr);
	//pcb->inactivity_timeout = pcb->tmr;
	// and if delayed acks are not used??

	// MANUAL set of flags, should not be done this way...
	//pcb->flags |= 0x01U// should be TF_ACK_DELAY instead -> include tcp.h ? or define in another file?;
	// set_delayed_ack_flag(pcb);

	// TAKE CARE: TODO: take care of seqnum wrapping!!!
	// TODO: hardcoded 4, to change. Should be an environment variable such as in PQUIC
	if (num_rcv_unacked >= ACK_THRESHOLD) {
		help_printf_str("num_rcv_unacked >= threshold\n");
		return 1;
	}
	return 0;
}
