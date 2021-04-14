#include "lwip/opt.h"

extern struct tcp_hdr *tcphdr;
extern u16_t tcphdr_optlen;
extern u16_t tcphdr_opt1len;
extern u8_t *tcphdr_opt2;
extern u16_t tcp_optidx;

u8_t tcp_get_next_optbyte(void);
