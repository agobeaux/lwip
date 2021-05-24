/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef UBPF_H
#define UBPF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "lwip/tcp.h"

#include<stdarg.h> /* VA_ARGS, va_arg(ap, type) etc */

/*
 * Enable/disable some plugins
 * Not scalable, more scalable way: like PQUIC, enable by putting the path to the plugin folder
 */
bool use_uto_option;
bool use_rto_option;


/* Each entry is either NULL if the index does not correspond to an option that could be parsed by an eBPF plugin
 * currently used, or it is the filename of the plugin that can parse the said option.
 * TODO: take care of the special case of temporary options that allow multiple options
 * TODO: move this to the tcp_pcb/context as it should be per-connection based. Makes sense if we can launch multiple apps
 *       operating on different addresses (which I am not sure if it is the case).
 */
char *ebpf_options_parser_bpf_code[256];

/*
 * Experimental Options case: two buffers are needed. Those are similar to the previous one
 * as the ExID is 16 bits longs.
 */
char *ebpf_options_parser_bpf_code_253[256];
char *ebpf_options_parser_bpf_code_254[256];

/*
 * Those variables contain the options length for packets sent either during the options negotiation
 * or after these negotiations.
 * Current hypothesis: Options are either written once (options negotiation) or every time. Plugins can't adapt
 * to the situation.
 *
 * If this no longer holds: a solution would be to do the write checks before allocating the outgoing segment
 * and compute the length at this time, before allocating the pbuf. Then, only call the functions that returned true
 * on the write check. Bit more complex but more flexible.
 *
 * Those are considered to be global and not be part of a tcp_pcb or a tcp_ubpf_cnx_t.
 */
int ebpf_options_length_options_negotiation;
int ebpf_options_length;

/* Helper macros */
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)

/* C99-style: anonymous argument referenced by __VA_ARGS__, empty arg not OK */
/* Helps to find the number of arguments in __VA_ARGS__ (up to 9 arguments though) */
/* Works by the fact that in N_ARGS_HELPER2, we put to the trash the first 9 elements
   and return the 10th one. Taken from PQUIC implementation */
# define N_ARGS(...) N_ARGS_HELPER1(__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
# define N_ARGS_HELPER1(...) N_ARGS_HELPER2(__VA_ARGS__)
# define N_ARGS_HELPER2(x1, x2, x3, x4, x5, x6, x7, x8, x9, n, ...) n

#define run_ubpf_with_args(pcb, filename, ...) run_ubpf_args(pcb, filename, N_ARGS( __VA_ARGS__), ## __VA_ARGS__)

#elif defined(__GNUC__)

/* GCC-style: named argument, empty arg is OK */

# define N_ARGS(args...) N_ARGS_HELPER1(args, 9, 8, 7, 6, 5, 4, 3, 2, 1)
# define N_ARGS_HELPER1(args...) N_ARGS_HELPER2(args)
# define N_ARGS_HELPER2(x1, x2, x3, x4, x5, x6, x7, x8, x9, n, x...) n

#define run_ubpf_with_args(pcb, filename, ...) run_ubpf_args(pcb, filename, N_ARGS(args), args)

#else

#error variadic macros for your compiler here

#endif

struct ubpf_vm;
typedef uint64_t (*ubpf_jit_fn)(void *mem, size_t mem_len);

struct ubpf_vm *ubpf_create(void);
void ubpf_destroy(struct ubpf_vm *vm);

/*
 * Register an external function
 *
 * The immediate field of a CALL instruction is an index into an array of
 * functions registered by the user. This API associates a function with
 * an index.
 *
 * 'name' should be a string with a lifetime longer than the VM.
 *
 * Returns 0 on success, -1 on error.
 */
int ubpf_register(struct ubpf_vm *vm, unsigned int idx, const char *name, void *fn);

/*
 * Load code into a VM
 *
 * This must be done before calling ubpf_exec or ubpf_compile and after
 * registering all functions.
 *
 * 'code' should point to eBPF bytecodes and 'code_len' should be the size in
 * bytes of that buffer.
 *
 * Returns 0 on success, -1 on error. In case of error a pointer to the error
 * message will be stored in 'errmsg' and should be freed by the caller.
 */
int ubpf_load(struct ubpf_vm *vm, const void *code, uint32_t code_len, char **errmsg, uint64_t memory_ptr, uint32_t memory_size);

/*
 * Load code from an ELF file
 *
 * This must be done before calling ubpf_exec or ubpf_compile and after
 * registering all functions.
 *
 * 'elf' should point to a copy of an ELF file in memory and 'elf_len' should
 * be the size in bytes of that buffer.
 *
 * The ELF file must be 64-bit littleubpf_exec-endian with a single text section
 * containing the eBPF bytecodes. This is compatible with the output of
 * Clang.
 *
 * Returns 0 on success, -1 on error. In case of error a pointer to the error
 * message will be stored in 'errmsg' and should be freed by the caller.
 */
int ubpf_load_elf(struct ubpf_vm *vm, const void *elf, size_t elf_len, char **errmsg, uint64_t memory_ptr, uint32_t memory_size);

uint64_t ubpf_exec(struct ubpf_vm *vm, void *mem, size_t mem_len);

/*
 * Provide arg to R1, but ensure store and load access remains in the range
 * [mem, mem + mem_len[.
 */
uint64_t ubpf_exec_with_arg(struct ubpf_vm *vm, void *arg, void *mem, size_t mem_len);

/*
 * Return the cause of the error if the VM crashed, or NULL otherwise
 */
const char *ubpf_get_error_msg(const struct ubpf_vm *vm);

ubpf_jit_fn ubpf_compile(struct ubpf_vm *vm, char **errmsg);

/* FUNCTIONS DEFINED BEFORE = LIBRARY */

/* Use the UTO option writer */
void set_use_uto_option(void);

/* Use the RTO option writer */
void set_use_rto_option(void);

/*
 * TODO: This function SHOULD be merged with the other one, but how do we know that we have to multiply the value by TCP_SLOW_INTERVAL?
 * Check if the connection should be dropped according to eBPF plugins. Currently: User Timeout option (UTO)
 * TODO: WRONG???!!! Should change the UTO if possible... A timeout exists and it should replace it....
 *      Well, the existing timeout is simply 2*MSL (Maximum Segment lifetime) which is 2*1minute.
 *      Well, we could want to have this set higher!... Should define the variable which holds the timeout value!
 *      UPDATE: Maybe we do not want that, this timer is for the TIME_WAIT state which is a closing one.
 */
int ebpf_should_drop_connection_rto(struct tcp_pcb *pcb); /* u64_t time_waiting_unacked */

/*
 * Parses tcp options
 * Updates tcp_optidx and returns either ERR_OK if everything went fine, ERR_VAL if the option does not correspond
 * any parser registered, and ERR_ARG if the eBPF parsing went wrong or if the length is badly formatted.
 */
int ebpf_parse_tcp_option(struct tcp_pcb *pcb, u8_t opt);

/*
 * Writes tcp option User TimeOut
 */
u32_t *ebpf_write_tcp_uto_option(struct tcp_pcb *pcb, u32_t *opts);

/*
 * Writes custom tcp option that puts a limit on the value or the retransmission timer rto
 */
u32_t *ebpf_write_tcp_rto_option(struct tcp_pcb *pcb, u32_t *opts);

/*
 * Writes the different TCP options that are enabled
 */
u32_t *ebpf_write_tcp_options(struct tcp_pcb *pcb, u32_t *opts);
/*
 * Returns the length of the TCP options defined in the plugins. Only User TimeOut for now
 */
u8_t ebpf_get_options_length(struct tcp_pcb *pcb);

/*
 * Called to know if an ACK should be sent. Returns true if it is the case, false otherwise
 */
int ebpf_is_ack_needed(struct tcp_pcb *pcb);

/*
 * Returns true if a fast retransmit should be sent on the TCP stream linked to the PCB pcb.
 */
int ebpf_should_fast_retransmit(struct tcp_pcb *pcb);

/*
 * Like run_ubpf but with extensible args
 */
uint64_t run_ubpf_args(struct tcp_pcb *pcb, const char *code_filename, int n_args, ...);

/*
 * This function adds an eBPF option parser that correponds to a certain option.
 * This function should not be called twice with the same option or memory leaks will happen.
 * exID is only used with experimental options; this parameter is ignored when using a traditional tcp option.
 */
void ubpf_register_tcp_option_parser(const char *code_filename, u8_t opt, u16_t exID);

#endif
