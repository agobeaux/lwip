
#include "lwip/tcp_in_helper.h" /* for tcp_get_next_optbyte */
#include "lwip/tcp.h" /* this contains multiple types, including the tcp_ubpf_cnx_t */

/*
 * Returns the pcb corresponding to the tcp_ubpf context
 */
struct tcp_pcb *get_pcb(tcp_ubpf_cnx_t *cnx);
/*
 * Returns the (index+1)th input passed to the tcp_ubpf context or NULL if it is out of range
 */
int64_t get_input(tcp_ubpf_cnx_t *cnx, int index);

void help_printf_uint8_t(uint8_t val);

void help_printf_sint16_t(s16_t val);

void help_printf_uint32_t(uint32_t val);

void help_printf_char(char c);

void help_printf_str(char *s);

void help_printf_ptr(void *p);

/* TODO: define several functions in other file like getset.c, getset.h for pquic */
/* TODO: use "tcpflags_t", have to include here + in plugin, -> lwip_interal.h ? */
uint16_t get_flag(struct tcp_pcb *pcb);

u32_t get_last_ack(struct tcp_pcb *pcb);

u32_t get_next_seqno(struct tcp_pcb *pcb);

void set_delayed_ack_flag(struct tcp_pcb *pcb);

u8_t get_num_rcv_unacked(struct tcp_pcb *pcb);

u32_t get_tmr(struct tcp_pcb *pcb);

u16_t custom_htons(u16_t x);

u16_t custom_ntohs(u16_t x);

u32_t custom_htonl(u32_t x);

u32_t custom_ntohl(u32_t x);

void set_opt(u32_t *opts, int index, u32_t value);

s16_t get_rto(struct tcp_pcb *pcb);

s16_t get_rto_max(struct tcp_pcb *pcb);

void set_rto_max(struct tcp_pcb *pcb, u16_t timeout);

void membound_fail(uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr);
