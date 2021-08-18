#include "lwip/tcp.h"
#include "getset.h"

#define RTO_MAX_INDEX 0

int ebpf_should_drop_connection_rto(struct tcp_pcb *pcb) {
	tcp_ubpf_cnx_t *cnx = get_cnx(pcb);
	u32_t rto = get_rto(pcb);
	u32_t rto_max = (s16_t) get_metadata(cnx, RTO_MAX_INDEX);
	/* Check if rto_max > 0, if not, it has not been initialized */
	if (rto_max > 0 && rto >= rto_max) {
		return 1;
	}
	return 0;
}
