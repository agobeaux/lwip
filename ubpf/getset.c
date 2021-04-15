#include "getset.h"


/*
 * Returns the pcb corresponding to the tcp_ubpf context
 */
struct tcp_pcb *get_pcb(tcp_ubpf_cnx_t *cnx) {
    return cnx->pcb;
}

/*
 * Returns the (index+1)th input passed to the tcp_ubpf context or NULL if it is out of range
 */
int64_t get_input(tcp_ubpf_cnx_t *cnx, int index) {
    if (index >= cnx->inputc) {
        printf("uBPF: error in get_input: out of range\n");
        return NULL;
    }
    printf("Index is : %d. Returning object at addr %p\n", index, cnx->inputv[index]);
    return cnx->inputv[index];
}

/*
uint32_t
sqrti(uint32_t x)
{
    return sqrt(x);
}
*/

void help_printf_uint8_t(uint8_t val) {
    printf("%u\n", val);
}

void help_printf_sint16_t(s16_t val) {
    printf("%u\n", val);
}

void help_printf_uint32_t(uint32_t val) {
    printf("%u\n", val);
}

void help_printf_char(char c) {
    printf("%c\n", c);
}

void help_printf_str(char *s) {
    printf("%s\n", s);
}

void help_printf_ptr(void *p) {
    printf("%p\n", p);
}

/* TODO: define several functions in other file like getset.c, getset.h for pquic */
/* TODO: use "tcpflags_t", have to include here + in plugin, -> lwip_interal.h ? */
uint16_t get_flag(struct tcp_pcb *pcb) {
    printf("Returning flags: %u\n", pcb->flags); /* TODO: %u should be PRIu16 technically */
    return pcb->flags;
}

u32_t get_last_ack(struct tcp_pcb *pcb) {
    printf("Returning last ack seqno sent: %u\n", pcb->lastack); /* TODO: %u should be PRIu32 */
    return pcb->lastack;
}

u32_t get_next_seqno(struct tcp_pcb *pcb) {
    printf("Returning next seqno to send: %u\n", pcb->snd_nxt); /* TODO: %u should be PRIu32 */
    return pcb->snd_nxt;
}

void set_delayed_ack_flag(struct tcp_pcb *pcb) {
    printf("Setting delayed ack flag: NOT THIS TIME\n");
    printf("flag %u\n", pcb->flags);
    pcb->flags |= 0x01U; /* TODO: should not be done this way */
}

u8_t get_num_rcv_unacked(struct tcp_pcb *pcb) {
    printf("Returning num_rcv_unacked: %u\n", pcb->num_rcv_unacked);
    return pcb->num_rcv_unacked;
}

u32_t get_tmr(struct tcp_pcb *pcb) {
    printf("Returning tmr: %u\n", pcb->tmr);
    return pcb->tmr;
}

u16_t custom_htons(u16_t x) {
    return ((u16_t)((((x) & (u16_t)0x00ffU) << 8) | (((x) & (u16_t)0xff00U) >> 8)));
}

u16_t custom_ntohs(u16_t x) {
    return custom_htons(x);
}

u32_t custom_htonl(u32_t x) {
    return ((((x) & (u32_t)0x000000ffUL) << 24) | \
            (((x) & (u32_t)0x0000ff00UL) <<  8) | \
            (((x) & (u32_t)0x00ff0000UL) >>  8) | \
            (((x) & (u32_t)0xff000000UL) >> 24));
}

u32_t custom_ntohl(u32_t x) {
    return custom_htonl(x);
}

void set_opt(u32_t *opts, int index, u32_t value) {
    printf("I am in set_opt function\n");
    printf("opts is at %p\n", opts);
    opts[index] = value;
    printf("Returning from set_opt function\n");
}

s16_t get_rto(struct tcp_pcb *pcb) {
    /* TODO: modify using TCP_TMR_INTERVAL */
    printf("Returning rto: %d\n", pcb->rto);
    return pcb->rto;
}

s16_t get_rto_max(struct tcp_pcb *pcb) {
    /* TODO: modify using TCP_TMR_INTERVAL */
    printf("Returning rto_max: %d\n", pcb->rto_max);
    return pcb->rto_max;
}

void set_rto_max(struct tcp_pcb *pcb, u16_t timeout) {
    /* TODO: modify using TCP_TMR_INTERVAL */
    pcb->rto_max = timeout;
    printf("rto_max set to %u\n", timeout);
    printf("rto_max set to 0x%x\n", timeout);
}

void membound_fail(uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr) {
    printf("Out of bound access with val 0x%lx, start of mem is 0x%lx, top of stack is 0x%lx\n", val, mem_ptr, stack_ptr);
}
