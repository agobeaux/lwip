#include "lwip/tcp_in_helper.h"
#include "lwip/priv/tcp_priv.h"

#if LWIP_TCP /* don't build if not configured for use in lwipopts.h */

/* These variables are global to all functions involved in the input
   processing of TCP segments. They are set by the tcp_input()
   function. */
struct tcp_hdr *tcphdr;
u16_t tcphdr_optlen;
u16_t tcphdr_opt1len;
u8_t *tcphdr_opt2;
u16_t tcp_optidx;


u8_t
tcp_get_next_optbyte(void)
{
  printf("in tcp_get_next_optbyte\n");
  u16_t optidx = tcp_optidx++;
  printf("After accessing tcp_optidx\n");
  if ((tcphdr_opt2 == NULL) || (optidx < tcphdr_opt1len)) {
    printf("In if in tcp_get_next_optbyte\n");
    u8_t *opts = (u8_t *)tcphdr + TCP_HLEN;
    printf("after setting opts\n");
    u8_t ret = opts[optidx];
    printf("after SETTING ret !!! no problem should happen\n"); fflush(stdout);
    return ret;
    //return opts[optidx];
  } else {
    printf("in else\n");
    u8_t idx = (u8_t)(optidx - tcphdr_opt1len);
    return tcphdr_opt2[idx];
  }
  printf("Returning from tcp_get_next_optbyte\n");
}

#endif /* LWIP_TCP */
