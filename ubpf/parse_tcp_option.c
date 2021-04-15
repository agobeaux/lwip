#include <stdio.h>
#include "lwip/tcp.h"
#include "lwip/err.h"
#include "getset.h"

#define TCP_OPT_UTO 28 /* User TimeOut option kind: 28 */
int parse_tcp_option(tcp_ubpf_cnx_t *cnx) {
	/* In this function, we parse the different TCP options that we can */
	struct tcp_pcb *pcb = get_pcb(cnx);
	u8_t granularity;
	u16_t timeout;
	//help_printf_str("opt in ubpf is: "); help_printf_uint8_t(opt);
	/* TODO: change it back to have parse_tcp_option or one plugin by option? (better I think) */
	//switch (opt) {
		//case TCP_OPT_UTO:
			if (tcp_get_next_optbyte() != 4) {
				/* Length is different than 4, not normal */
				help_printf_str("ERROR: tcp_get_next_optbyte should be 4 for UTO");
				return ERR_VAL;
			}
			timeout = tcp_get_next_optbyte();
    	timeout |= (tcp_get_next_optbyte() << 8);
			timeout = custom_ntohs(timeout);
			granularity = (timeout & 0x8000) >> 15;
			timeout &= 0x7fff; // filter out the granularity part
			help_printf_str("granularity received :");
			help_printf_uint8_t(granularity);
			set_rto_max(pcb, timeout);
			//pcb->rto_max = timeout; /* TODO: should be replaced by a setter to allow flexibility */
			/* TODO: what to do about granularity ?*/
			// TODO: update uto in pcb?
			// TODO: tcp_get_next_optbyte() should be available from here (file tcp_in.c, not cool)
			//break;
		//default:
			//help_printf_str("in default, opt is: "); help_printf_uint8_t(opt);
			//return ERR_ARG; /* Could not parse the option */
	//}
	return ERR_OK; /* Parsed option successfully */
}
