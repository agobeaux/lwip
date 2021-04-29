#include <stdio.h>
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "getset.h"
//#include <arpa/inet.h>

/* TODO: déclarer les fonctions dans un fichier header */

#define TCP_OPT_UTO 28 /* User TimeOut option kind: 28 */
u32_t *write_tcp_uto_option(struct tcp_pcb *pcb) {
	/*
	help_printf_str("Printing what is got directly");
	help_printf_ptr(get_input(cnx, 0));
	set_opt(get_input(cnx, 0), 0, 0);
	void *ptr = (void *)get_input(cnx, 0);
	help_printf_str("Printing ptr");
	help_printf_ptr(ptr);
	uint64_t input64 = get_input(cnx, 0);
	help_printf_str("Printing pointer but uint64");
	help_printf_ptr(input64);
	uint64_t *opts64 = (uint64_t *) get_input(cnx, 0);
	help_printf_str("I'm in write_tcp_uto_option, address of opts64");
	*/
	tcp_ubpf_cnx_t *cnx = get_cnx(pcb);
	u32_t *opts = (u32_t *)get_input(cnx, 0);
	if (opts == NULL) {
		help_printf_str("uBPF: write_tcp_uto_option: input opts could not be retrieved");
	}
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
	help_printf_str("I'm in write_tcp_uto_option, address of opts");
	help_printf_ptr(opts);
	help_printf_str("I'm in write_tcp_uto_option, address of opts+1");
	help_printf_ptr(opts+1);
	return opts+1;
}
