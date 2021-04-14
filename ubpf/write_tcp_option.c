#include <stdio.h>
#include "lwip/tcp.h"
#include "lwip/err.h"
//#include <arpa/inet.h>


#define TCP_OPT_UTO 28 /* User TimeOut option kind: 28 */
u32_t *write_tcp_uto_option(u32_t *opts) {
	help_printf_str("I'm in write_tcp_uto_option, address of opts");
	help_printf_ptr(opts);
	/* In this function, we parse the different TCP options that we can */
	u8_t kind = TCP_OPT_UTO;
	u8_t granularity = 1;
	u8_t length = 4;
	u16_t timeout = 1600; /* in ms for now, should be in seconds tho, or in minutes thanks to the granularity bit */
	/* No need to pad with NOP options as the option takes 4 bytes (and thus is aligned) */
	u32_t opts_value = custom_htonl((u32_t) kind << 24 | (u32_t) length << 16 | (u32_t) granularity << 15 | timeout);
	set_opt(opts, 0, opts_value);
	help_printf_str("Printed UTO option as %u", opts_value);
	help_printf_str("Gonna return opts+1: %p\n", opts+1);
	return opts+1;
}
