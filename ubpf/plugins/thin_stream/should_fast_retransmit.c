#include "lwip/tcp.h"
#include "getset.h"

/* A connection is considered to be a thin-stream if it has less than
 * NUM_PACKETS_OUT_THRESHOLD packets that were sent out without being acknowledged
 */

/* WARNING: current hypotheses:
 *						1. we do not care if tcp is in slow start mode yet
 *						2. we approximate the number of packets out by checking the number of unacked
 *							 bytes and dividing it by the current TCP_MSS
 */

/* If the TCP stream is a thin one, we retransmit on first dupAck, else, we retransmit on third dupAck */
u8_t should_fast_retransmit(struct tcp_pcb *pcb) {
	u32_t next_seqno = get_next_seqno(pcb);
	u32_t last_acked_seqno = get_last_acked_seqno(pcb);
	u32_t mss = (u32_t) get_mss(pcb);

	/* This already takes care of the wrap around behaviour of tcp (since unsigned bits are used) */
	u32_t num_bytes_unacked = next_seqno - last_acked_seqno;
	u32_t num_packets_out = num_bytes_unacked/mss;
	u8_t dupacks = get_dupacks(pcb);

	if ((int)num_packets_out < NUM_PACKETS_OUT_THRESHOLD) {
		return dupacks >= 1; /* Should always be true when calling this function */
	} else {
		/* Not a thin-stream: apply basic behaviour */
		return dupacks >= 3;
	}
	return 0;
}
