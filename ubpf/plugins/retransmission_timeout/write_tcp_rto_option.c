#include <stdio.h>
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "getset.h"

#define TCP_OPT_RTO 	253 /* Retransmission TimeOut option kind: 253 (experimental) */
#define TCP_ExID_RTO	0x12EF /* Retransmission TimeOut Experimental ID: 134 */
u32_t *write_tcp_rto_option(struct tcp_pcb *pcb) {
	tcp_ubpf_cnx_t *cnx = get_cnx(pcb);
	u32_t *opts = (u32_t *)get_input(cnx, 0);
	if (opts == NULL) {
		help_printf_str("uBPF: write_tcp_uto_option: input opts could not be retrieved");
	}
	help_printf_str("I'm in write_tcp_uto_option, address of opts");
	help_printf_ptr(opts);

	u8_t kind = TCP_OPT_RTO;
	u8_t length = 6;
	u16_t exID = TCP_ExID_RTO;
	u16_t rto_max = RTO_MAX_VALUE; /* in ms for now, passed through a macro at compilation time */
	/* Need to pad with 2 NOP options as the option takes 6 bytes -> needs to be aligned */
	u32_t opts_value = custom_htonl((u32_t) kind << 24 | (u32_t) length << 16 | exID);
	set_opt(opts, 0, opts_value);
	u32_t rto_max_padded = custom_htonl(rto_max << 16 | 0x0101);
	set_opt(opts, 1, rto_max_padded);
	help_printf_str("I'm in write_tcp_uto_option, address of opts");
	help_printf_ptr(opts);
	help_printf_str("I'm in write_tcp_uto_option, address of opts+2");
	help_printf_ptr(opts+2);
	return opts+2;
}
