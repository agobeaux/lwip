#include <stdio.h>
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "getset.h"

#define TCP_OPT_RTO 	253 /* Retransmission TimeOut option kind: 253 (experimental) */
#define TCP_ExID_RTO	0x12EF /* Retransmission TimeOut Experimental ID: 134 */
#define RTO_MAX_INDEX 0 /* Index of the rto_max value in the metadata array */
int parse_tcp_rto_option(struct tcp_pcb *pcb) {
	/* In this function, we parse the TCP RTO option */
	tcp_ubpf_cnx_t *cnx = get_cnx(pcb);
	u8_t option_length = get_input(cnx, 0);
	if (option_length != 6) {
		help_printf_str("ERROR: tcp_get_next_optbyte should be 6 for RTO");
		return ERR_VAL;
	}

	u16_t rto_max = custom_ntohs(tcp_get_next_optbyte() | tcp_get_next_optbyte() << 8);
	set_metadata(cnx, RTO_MAX_INDEX, rto_max);

	return ERR_OK; /* Parsed option successfully */
}
