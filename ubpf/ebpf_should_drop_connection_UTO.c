#include <stdio.h>
#include "lwip/tcp.h"
#include "getset.h"

int ebpf_should_drop_connection_UTO(tcp_ubpf_cnx_t *cnx) {
	struct tcp_pcb *pcb = get_pcb(cnx);
	char *str = "Currently launching eBPF function epbf_should_drop_connection_UTO!\n";
	help_printf_str(str);
	s16_t rto = get_rto(pcb);
	s16_t rto_max = get_rto_max(pcb);
	help_printf_str("Printing rto and then rto max\n");
	help_printf_sint16_t(rto);
	help_printf_sint16_t(rto_max);
	if (rto >= rto_max) {
		help_printf_str("pcb->rto >= pcb->rto_max\n");
		return 1;
	}
	return 0;
}
