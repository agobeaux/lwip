#include <stdio.h>
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "getset.h"

u8_t ebpf_get_options_length(tcp_ubpf_cnx_t *cnx) {
	return 4; /* Only User Timeout option */
}
