#include <stdio.h>
#include "lwip/tcp.h"
#include "lwip/err.h"

u8_t ebpf_get_options_length(struct tcp_pcb *pcb) {
	return 4; /* Only User Timeout option */
}
