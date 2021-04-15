/*
 * Copyright 2015 Big Switch Networks, Inc
 * Copyright 2017 Google Inc.
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

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <elf.h>
#include <math.h>
#include "ubpf.h"

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>

#include "../getset.h"

/* #include "lwip/tcp.h" // included in ubpf.h for now, needed. DOES NOT WORK YET, change compilation flags.. include for type tcpflags_t */

void ubpf_set_register_offset(int x);
static void *readfile(const char *path, size_t maxlen, size_t *len);
static void register_functions(struct ubpf_vm *vm);

/*
static void usage(const char *name)
{
    fprintf(stderr, "usage: %s [-h] [-j|--jit] [-m|--mem PATH] BINARY\n", name);
    fprintf(stderr, "\nExecutes the eBPF code in BINARY and prints the result to stdout.\n");
    fprintf(stderr, "If --mem is given then the specified file will be read and a pointer\nto its data passed in r1.\n");
    fprintf(stderr, "If --jit is given then the JIT compiler will be used.\n");
    fprintf(stderr, "\nOther options:\n");
    fprintf(stderr, "  -r, --register-offset NUM: Change the mapping from eBPF to x86 registers\n");
}
*/

/* TODO: This function SHOULD be merged with the other one, but how do we know that we have to multiply the value by TCP_SLOW_INTERVAL? */
int epbf_should_drop_connection_UTO(struct tcp_pcb *pcb) { /* u64_t time_waiting_unacked */
    printf("epbf_should_drop_connection_UTO\n");
    const char *code_filename = "/home/agobeaux/Desktop/M2Q1/MASTER_THESIS/VM_folder/lwip_programs/externals/lwip/ubpf/ebpf_should_drop_connection_UTO.bpf";
    /* LWIP_UNUSED_ARG(time_waiting_unacked); */
    return run_ubpf_with_args(pcb, code_filename);
}

int ebpf_parse_tcp_option(struct tcp_pcb *pcb, u8_t opt) {
    printf("ebpf_parse_tcp_option\n");
    const char *code_filename = "/home/agobeaux/Desktop/M2Q1/MASTER_THESIS/VM_folder/lwip_programs/externals/lwip/ubpf/parse_tcp_option.bpf";
    LWIP_UNUSED_ARG(opt);
    return run_ubpf_with_args(pcb, code_filename);
}

u32_t *ebpf_write_tcp_uto_option(struct tcp_pcb *pcb, u32_t *opts) { /* TODO: use VA_ARGS for passing multiple options to the ebpf function? */
    /* TODO: for using this argument, we could have a thing like in QUIC (cf plugins/tlp/set_next_wake_time.c/set_next_wake_time)
     *       This requires to cast in a new type (protoop_arg_t as in quic for ex) and to cast to the good type once in the plugin implementation
     *       PROBLEM: dereferencing a pointer here... will not be able to access "opts"... how to solve this ? Should transmit in the VM's memory I guess...
     *                but is that functional?...
     */
    printf("ebpf_write_tcp_uto_option\n");
    const char *code_filename = "/home/agobeaux/Desktop/M2Q1/MASTER_THESIS/VM_folder/lwip_programs/externals/lwip/ubpf/write_tcp_option.bpf";
    printf("ebpf_write_tcp_uto_option: Before calling run_ubpf_with_args, opts is at %p\n", opts);
    return run_ubpf_with_args(pcb, code_filename, opts);
}

u8_t ebpf_get_options_length(struct tcp_pcb *pcb) {
    printf("ebpf_get_options_length\n");
    const char *code_filename = "/home/agobeaux/Desktop/M2Q1/MASTER_THESIS/VM_folder/lwip_programs/externals/lwip/ubpf/ebpf_get_options_length.bpf";
    return run_ubpf_with_args(pcb, code_filename);
}

int ebpf_is_ack_needed(struct tcp_pcb *pcb) {
    printf("ebpf_is_ack_needed\n");
    const char *code_filename = "/home/agobeaux/Desktop/M2Q1/MASTER_THESIS/VM_folder/lwip_programs/externals/lwip/ubpf/is_ack_needed.bpf";
    return run_ubpf_with_args(pcb, code_filename);
}

uint64_t run_ubpf_args(struct tcp_pcb *pcb, const char *code_filename, int n_args, ...) {
    int i;
    va_list ap;

    va_start(ap, n_args);
    uint64_t args[n_args]; /* Cast everything to a uint64_t, thus able to contain pointers */

    for (i = 0; i < n_args; ++i) {
        args[i] = va_arg(ap, uint64_t);
        printf("run_ubpf_args: Before calling the function, args[%d] is at %p\n", i, args[i]);
    }

    va_end(ap);

    tcp_ubpf_cnx_t cnx = {.pcb = pcb, .inputc = n_args, .inputv = args};
    const char *mem_filename = NULL;
    bool jit = false;

    size_t code_len;
    void *code;
    
    size_t mem_len = 20000; /* TODO: change this value */
    void *mem = (void*) malloc(20000);

    struct ubpf_vm *vm;

    uint64_t ret;

    printf("Beginning of run_ubpf()\n"); fflush(NULL); /* TODO: erase */
    
    code = readfile(code_filename, 1024*1024, &code_len);
    if (code == NULL) {
        return 1;
    }

    if (mem_filename != NULL) {
        mem = readfile(mem_filename, 1024*1024, &mem_len);
        if (mem == NULL) {
            return 1;
        }
    }
    

    vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    register_functions(vm);

    /* 
     * The ELF magic corresponds to an RSH instruction with an offset,
     * which is invalid.
     */
    bool elf = code_len >= SELFMAG && !memcmp(code, ELFMAG, SELFMAG);

    char *errmsg;
    int rv;
    
    ubpf_jit_fn fn;

    if (elf) {
        rv = ubpf_load_elf(vm, code, code_len, &errmsg, (uint64_t) mem, mem_len);
    } else {
        rv = ubpf_load(vm, code, code_len, &errmsg, (uint64_t) mem, mem_len);
    }

    free(code);

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    printf("Before JIT\n"); fflush(NULL); /* TODO: erase */

    if (jit) {
        printf("jit is true\n"); fflush(NULL); /* TODO: erase */
        fn = ubpf_compile(vm, &errmsg);
        if (fn == NULL) {
            fprintf(stderr, "Failed to compile: %s\n", errmsg);
            free(errmsg);
            return 1;
        }
        ret = fn(mem, mem_len);
    } else {
        printf("jit not used\n"); fflush(NULL); /* TODO: erase */
        ret = ubpf_exec_with_arg(vm, &cnx, mem, mem_len);
    }

    printf("0x%"PRIx64"\n", ret);

    ubpf_destroy(vm);

    return ret; /* TODO: change, should not return int but something else, protooop_arg_t like PQUIC */
}

static void *readfile(const char *path, size_t maxlen, size_t *len)
{
    FILE *file;

    void *data;

    size_t offset;
    size_t rv;
    
    if (!strcmp(path, "-")) {
        file = fdopen(STDIN_FILENO, "r");
    } else {
        file = fopen(path, "r");
    }

    if (file == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }

    data = calloc(maxlen, 1);
    offset = 0;
    while ((rv = fread((char *)data+offset, 1, maxlen-offset, file)) > 0) {
        offset += rv;
    }

    if (ferror(file)) {
        fprintf(stderr, "Failed to read %s: %s\n", path, strerror(errno));
        fclose(file);
        free(data);
        return NULL;
    }

    if (!feof(file)) {
        fprintf(stderr, "Failed to read %s because it is too large (max %u bytes)\n",
                path, (unsigned)maxlen);
        fclose(file);
        free(data);
        return NULL;
    }

    fclose(file);
    if (len) {
        *len = offset;
    }
    return data;
}

static uint64_t
gather_bytes(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e)
{
    return ((uint64_t)a << 32) |
        ((uint32_t)b << 24) |
        ((uint32_t)c << 16) |
        ((uint16_t)d << 8) |
        e;
}

static void
trash_registers(void)
{
    /* Overwrite all caller-save registers */
    asm(
        "mov $0xf0, %rax;"
        "mov $0xf1, %rcx;"
        "mov $0xf2, %rdx;"
        "mov $0xf3, %rsi;"
        "mov $0xf4, %rdi;"
        "mov $0xf5, %r8;"
        "mov $0xf6, %r9;"
        "mov $0xf7, %r10;"
        "mov $0xf8, %r11;"
    );
}

static void
register_functions(struct ubpf_vm *vm)
{
    int function_index = 0;
    ubpf_register(vm, function_index++, "gather_bytes", (void *) gather_bytes);
    ubpf_register(vm, function_index++, "memfrob", memfrob);
    ubpf_register(vm, function_index++, "trash_registers", trash_registers);
    /* ubpf_register(vm, 3, "sqrti", sqrti); */
    /* problem, cannot get sqrt ?? */
    ubpf_register(vm, function_index++, "strcmp_ext", strcmp);
    ubpf_register(vm, function_index++, "memset", memset);
    ubpf_register(vm, function_index++, "socket", socket);
    ubpf_register(vm, function_index++, "bind", bind);
    ubpf_register(vm, function_index++, "recv", recv);
    ubpf_register(vm, function_index++, "malloc", malloc);
    ubpf_register(vm, function_index++, "help_printf_uint32_t", help_printf_uint32_t);
    ubpf_register(vm, function_index++, "help_printf_char", help_printf_char);
    ubpf_register(vm, function_index++, "help_printf_str", help_printf_str);
    ubpf_register(vm, function_index++, "help_printf_ptr", help_printf_ptr);

    /* functions I added */
    ubpf_register(vm, function_index++, "get_flag", get_flag);
    ubpf_register(vm, function_index++, "get_last_ack", get_last_ack);
    ubpf_register(vm, function_index++, "get_next_seqno", get_next_seqno);
    ubpf_register(vm, function_index++, "set_delayed_ack_flag", set_delayed_ack_flag);
    ubpf_register(vm, function_index++, "get_num_rcv_unacked", get_num_rcv_unacked);
    ubpf_register(vm, function_index++, "help_printf_uint8_t", help_printf_uint8_t);
    ubpf_register(vm, function_index++, "custom_htons", custom_htons);
    ubpf_register(vm, function_index++, "custom_ntohs", custom_ntohs);
    ubpf_register(vm, function_index++, "custom_htonl", custom_htonl);
    ubpf_register(vm, function_index++, "custom_ntohl", custom_ntohl);
    ubpf_register(vm, function_index++, "get_tmr", get_tmr);
    ubpf_register(vm, function_index++, "set_opt", set_opt);
    ubpf_register(vm, function_index++, "tcp_get_next_optbyte", tcp_get_next_optbyte);
    ubpf_register(vm, function_index++, "get_rto_max", get_rto_max);
    ubpf_register(vm, function_index++, "set_rto_max", set_rto_max);
    ubpf_register(vm, function_index++, "get_rto", get_rto);
    ubpf_register(vm, function_index++, "help_printf_sint16_t", help_printf_sint16_t);
    ubpf_register(vm, function_index++, "get_pcb", get_pcb);
    ubpf_register(vm, function_index++, "get_input", get_input);





    


    ubpf_register(vm, 63, "membound_fail", membound_fail);
}
