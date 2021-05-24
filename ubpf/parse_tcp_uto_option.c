#include <stdio.h>
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "getset.h"

#define TCP_OPT_UTO 28 /* User TimeOut option kind: 28 */
int parse_tcp_uto_option(struct tcp_pcb *pcb) {
	/* In this function, we parse the different TCP options that we can */
	tcp_ubpf_cnx_t *cnx = get_cnx(pcb);
	u8_t option_length = get_input(cnx, 0);
	if (option_length != 4) {
		/* Length is different than 4, not normal */
		help_printf_str("ERROR: tcp_get_next_optbyte should be 4 for UTO");
		return ERR_VAL;
	}

	u8_t granularity;
	u32_t timeout;
	timeout = tcp_get_next_optbyte();
	timeout |= (tcp_get_next_optbyte() << 8);
	timeout = custom_ntohs(timeout);
	granularity = (timeout & 0x8000) >> 15;
	timeout &= 0x7fff; // filter out the granularity part
	if (granularity == 1) {
		/* Timeout parsed is in minutes, put it in ms, u32_t is enough to contain this */
		timeout = timeout * 1000 * 60;
	} else {
		/* Timeout parsed is in seconds, put it in ms */
		timeout = 1000 * timeout;
	}
	timeout = 1000*timeout; /* Option timeout was either in seconds or in me*/
	help_printf_str("granularity received :");
	help_printf_uint8_t(granularity);
	set_user_timeout(pcb, timeout);
	return ERR_OK; /* Parsed option successfully */
}
