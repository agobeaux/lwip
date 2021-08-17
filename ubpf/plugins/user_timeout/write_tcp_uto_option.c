#include "lwip/tcp.h"
#include "lwip/err.h"
#include "getset.h"

#define TCP_OPT_UTO 28 /* User TimeOut option kind: 28 */
u32_t *write_tcp_uto_option(struct tcp_pcb *pcb) {
	/* In this function, we write the UTO TCP option */
	tcp_ubpf_cnx_t *cnx = get_cnx(pcb);
	u32_t *opts = (u32_t *)get_input(cnx, 0);
	if (opts == NULL) {
		help_printf_str("uBPF: write_tcp_uto_option: input opts could not be retrieved");
		return ERR_ARG;
	}
	u8_t kind = TCP_OPT_UTO;
	u8_t granularity = UTO_GRANULARITY;
	u8_t length = 4;
	u16_t timeout = UTO_TIMEOUT; /* in ms for now, should be in seconds tho, or in minutes thanks to the granularity bit */
	/* No need to pad with NOP options as the option takes 4 bytes (and thus is aligned) */
	u32_t opts_value = custom_htonl((u32_t) kind << 24 | (u32_t) length << 16 | (u32_t) granularity << 15 | timeout);
	set_opt(opts, 0, opts_value);
	return opts+1;
}
