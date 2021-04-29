#include <stdio.h>
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "getset.h"

u8_t ebpf_get_options_length(struct tcp_pcb *pcb) {
	/*return 4;*/
	tcp_ubpf_cnx_t *cnx = get_cnx(pcb);
	help_printf_str("Got context");
	u8_t optlen = get_ebpf_options_length(cnx);
	help_printf_str("Got length:");
	help_printf_uint8_t(optlen);
	return optlen;
}
