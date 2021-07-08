#include <stdio.h>
#include "lwip/tcp.h"
#include "getset.h"

#define RTO_MAX_INDEX 0

int ebpf_should_drop_connection_rto(struct tcp_pcb *pcb) {
	tcp_ubpf_cnx_t *cnx = get_cnx(pcb);
	char *str = "Currently launching eBPF function ebpf_should_drop_connection_rto!\n";
	help_printf_str(str);
	s16_t rto = get_rto(pcb);
	s16_t rto_max = (s16_t) get_metadata(cnx, RTO_MAX_INDEX);
	help_printf_str("Printing rto and then rto max\n");
	help_printf_sint16_t(rto);
	help_printf_sint16_t(rto_max);
	/* Check if rto_max > 0, if not, it has not been initialize */
	if (rto_max > 0 && rto >= rto_max) {
		help_printf_str("pcb->rto >= rto_max\n");
		return 1;
	}
	return 0;
}
