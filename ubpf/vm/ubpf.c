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


int ebpf_is_ack_needed(struct tcp_pcb *pcb) {
    const char *code_filename = "/home/agobeaux/Desktop/M2Q1/MASTER_THESIS/VM_folder/lwip_programs/externals/lwip/ubpf/is_ack_needed.bpf";
    return run_ubpf(code_filename, pcb);
}

/* TODO: change, should return protoop_arg_t, a custom type to return meaningful values */
/* TODO: split this function, have a load part, exec part etc */
int run_ubpf(const char *code_filename, struct tcp_pcb *pcb)
{
    /*
    struct option longopts[] = {
        { .name = "help", .val = 'h', },
        { .name = "mem", .val = 'm', .has_arg=1 },
        { .name = "jit", .val = 'j' },
        { .name = "register-offset", .val = 'r', .has_arg=1 },
        { }
    };
    */

    const char *mem_filename = NULL;
    bool jit = false;

    /*
    int opt;
    while ((opt = getopt_long(argc, argv, "hm:jr:", longopts, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mem_filename = optarg;
            break;
        case 'j':
            jit = true;
            break;
        case 'r':
            ubpf_set_register_offset(atoi(optarg));
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (argc != optind + 1) {
        usage(argv[0]);
        return 1;
    }
    */

    /* hard-coded file */
    /* const char *code_filename = "/home/agobeaux/Desktop/M2Q1/MASTER_THESIS/VM_folder/lwip_programs/externals/lwip/ubpf/test2.bpf"; */
    /*
        const char *code_filename = "/home/agobeaux/Desktop/M2Q1/MASTER_THESIS/VM_folder/lwip_programs/externals/lwip/ubpf/is_ack_needed.bpf";
    */
    size_t code_len;
    void *code;
    
    size_t mem_len = 0;
    void *mem = NULL;

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
        ret = ubpf_exec_with_arg(vm, pcb, mem, mem_len);
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

/*
static uint32_t
sqrti(uint32_t x)
{
    return sqrt(x);
}
*/

static void help_printf_uint8_t(uint8_t val) {
    printf("%u\n", val);
}

static void help_printf_uint32_t(uint32_t val) {
    printf("%u\n", val);
}

static void help_printf_char(char c) {
    printf("%c\n", c);
}

static void help_printf_str(char *s) {
    printf("%s\n", s);
}

static void help_printf_ptr(void *p) {
    printf("%p\n", p);
}

/* TODO: define several functions in other file like getset.c, getset.h for pquic */
/* TODO: use "tcpflags_t", have to include here + in plugin, -> lwip_interal.h ? */
static uint16_t get_flag(struct tcp_pcb *pcb) {
    printf("Returning flags: %u\n", pcb->flags); /* TODO: %u should be PRIu16 technically */
    return pcb->flags;
}

static u32_t get_last_ack(struct tcp_pcb *pcb) {
    printf("Returning last ack seqno sent: %u\n", pcb->lastack); /* TODO: %u should be PRIu32 */
    return pcb->lastack;
}

static u32_t get_next_seqno(struct tcp_pcb *pcb) {
    printf("Returning next seqno to send: %u\n", pcb->snd_nxt); /* TODO: %u should be PRIu32 */
    return pcb->snd_nxt;
}

static void set_delayed_ack_flag(struct tcp_pcb *pcb) {
    printf("Setting delayed ack flag: NOT THIS TIME\n");
    printf("flag %u\n", pcb->flags);
    pcb->flags |= 0x01U; /* TODO: should not be done this way */
}

static u8_t get_num_rcv_unacked(struct tcp_pcb *pcb) {
    printf("Returning num_rcv_unacked: %u\n", pcb->num_rcv_unacked);
    return pcb->num_rcv_unacked;
}

static void membound_fail(uint64_t val, uint64_t mem_ptr, uint64_t stack_ptr) {
    printf("Out of bound access with val 0x%lx, start of mem is 0x%lx, top of stack is 0x%lx\n", val, mem_ptr, stack_ptr);
}

static void
register_functions(struct ubpf_vm *vm)
{
    ubpf_register(vm, 0, "gather_bytes", (void *) gather_bytes);
    ubpf_register(vm, 1, "memfrob", memfrob);
    ubpf_register(vm, 2, "trash_registers", trash_registers);
    /* ubpf_register(vm, 3, "sqrti", sqrti); */
    /* problem, cannot get sqrt ?? */
    ubpf_register(vm, 4, "strcmp_ext", strcmp);
    ubpf_register(vm, 5, "memset", memset);
    ubpf_register(vm, 6, "socket", socket);
    ubpf_register(vm, 7, "bind", bind);
    ubpf_register(vm, 8, "recv", recv);
    ubpf_register(vm, 9, "malloc", malloc);
    ubpf_register(vm, 10, "help_printf_uint32_t", help_printf_uint32_t);
    ubpf_register(vm, 11, "help_printf_char", help_printf_char);
    ubpf_register(vm, 12, "help_printf_str", help_printf_str);
    ubpf_register(vm, 13, "help_printf_ptr", help_printf_ptr);

    /* functions I added */
    ubpf_register(vm, 14, "get_flag", get_flag);
    ubpf_register(vm, 15, "get_last_ack", get_last_ack);
    ubpf_register(vm, 16, "get_next_seqno", get_next_seqno);
    ubpf_register(vm, 17, "set_delayed_ack_flag", set_delayed_ack_flag);
    ubpf_register(vm, 18, "get_num_rcv_unacked", get_num_rcv_unacked);
    ubpf_register(vm, 19, "help_printf_uint8_t", help_printf_uint8_t);

    


    ubpf_register(vm, 63, "membound_fail", membound_fail);
}
