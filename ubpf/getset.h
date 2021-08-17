
#include "lwip/tcp_in_helper.h" /* for tcp_get_next_optbyte */
#include "lwip/tcp.h" /* this contains multiple types, including the tcp_ubpf_cnx_t */
#include "lwip/priv/tcp_priv.h" /* for the definition of the constants (e.g. TCP_SLOW_INTERVAL) */

/*
 * Returns the pcb corresponding to the tcp_ubpf context
 */
tcp_ubpf_cnx_t *get_cnx(struct tcp_pcb *pcb);

/*
 * Returns the (index+1)th input passed to the tcp_ubpf context or 0 if it is out of range
 */
int64_t get_input(tcp_ubpf_cnx_t *cnx, int index);

/*
 * Returns the (index+1)th variable stocked in the plugin's context or 0 if it is out of range
 */
uint64_t get_metadata(tcp_ubpf_cnx_t *cnx, int index);

/*
 * Sets the (index+1)th variable stocked in the plugin's context
 */
void set_metadata(tcp_ubpf_cnx_t *cnx, int index, uint64_t value);

void help_printf_uint8_t(uint8_t val);

void help_printf_sint16_t(s16_t val);

void help_printf_uint32_t(uint32_t val);

void help_printf_char(char c);

void help_printf_str(char *s);

void help_printf_ptr(void *p);

/* TODO: use "tcpflags_t", have to include here + in plugin, -> lwip_internal.h ? */
uint16_t get_flag(struct tcp_pcb *pcb);

u32_t get_last_acked_seqno(struct tcp_pcb *pcb);

u32_t get_next_seqno(struct tcp_pcb *pcb);

u8_t get_mss(struct tcp_pcb* pcb);

u8_t get_dupacks(struct tcp_pcb *pcb);

void set_delayed_ack_flag(struct tcp_pcb *pcb);

u8_t get_num_rcv_unacked(struct tcp_pcb *pcb);

u32_t get_tmr(struct tcp_pcb *pcb);

u16_t custom_htons(u16_t x);

u16_t custom_ntohs(u16_t x);

u32_t custom_htonl(u32_t x);

u32_t custom_ntohl(u32_t x);

void set_opt(u32_t *opts, int index, u32_t value);

u32_t get_rto(struct tcp_pcb *pcb);

u32_t get_user_timeout(struct tcp_pcb *pcb);

void set_user_timeout(struct tcp_pcb *pcb, u32_t timeout);

void membound_fail(uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr);
