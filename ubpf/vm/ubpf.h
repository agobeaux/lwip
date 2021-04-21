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

#include "lwip/tcp.h"

#include<stdarg.h> /* VA_ARGS, va_arg(ap, type) etc */

/* Helps to find the number of arguments in __VA_ARGS__ (up to 9 arguments though) */
/* Works by the fact that in N_ARGS_HELPER2, we put to the trash the first 9 elements
   and return the 10th one. Taken from PQUIC implementation */
# define N_ARGS(...) N_ARGS_HELPER1(__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
# define N_ARGS_HELPER1(...) N_ARGS_HELPER2(__VA_ARGS__)
# define N_ARGS_HELPER2(x1, x2, x3, x4, x5, x6, x7, x8, x9, n, ...) n

#define run_ubpf_with_args(pcb, filename, ...) run_ubpf_args(pcb, filename, N_ARGS( __VA_ARGS__), ## __VA_ARGS__)

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


/*
 * TODO: This function SHOULD be merged with the other one, but how do we know that we have to multiply the value by TCP_SLOW_INTERVAL?
 * Check if the connection should be dropped according to eBPF plugins. Currently: User Timeout option (UTO)
 * TODO: WRONG???!!! Should change the UTO if possible... A timeout exists and it should replace it....
 *      Well, the existing timeout is simply 2*MSL (Maximum Segment lifetime) which is 2*1minute.
 *      Well, we could want to have this set higher!... Should define the variable which holds the timeout value!
 *      UPDATE: Maybe we do not want that, this timer is for the TIME_WAIT state which is a closing one.
 */
int epbf_should_drop_connection_UTO(struct tcp_pcb *pcb); /* u64_t time_waiting_unacked */

/*
 * Parses tcp options
 */
int ebpf_parse_tcp_option(struct tcp_pcb *pcb, u8_t opt);

/*
 * Writes tcp option User TimeOut
 */
u32_t *ebpf_write_tcp_uto_option(struct tcp_pcb *pcb, u32_t *opts);

/*
 * Returns the length of the TCP options defined in the plugins. Only User TimeOut for now
 */
u8_t ebpf_get_options_length(struct tcp_pcb *pcb);

/*
 * Called to know if an ACK should be sent. Returns true if it is the case, false otherwise
 */
int ebpf_is_ack_needed(struct tcp_pcb *pcb);

/*
 * Returns true if the TCP stream linked to the pcb is considered as a thin stream
 */
int ebpf_is_thin_stream(struct tcp_pcb *pcb);

/*
 * Like run_ubpf but with extensible args
 */
uint64_t run_ubpf_args(struct tcp_pcb *pcb, const char *code_filename, int n_args, ...);

#endif
