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

int ebpf_should_drop_connection_rto(struct tcp_pcb *pcb) { /* u64_t time_waiting_unacked */
    printf("ebpf_should_drop_connection_rto\n");
    clock_t start = clock();
    if (!ebpf_drop_connection.filename) {
        /* Default behaviour: do not drop */
        return 0;
    }
    (pcb->cnx).current_plugin_name = ebpf_drop_connection.pluginName; /* TODO: modifier pour que ce soit dynamique... Liste de fonctions de timeout et voilà... */
    int ret =  run_ubpf_with_args(pcb, ebpf_drop_connection.filename);// ,NULL);
    clock_t end = clock();
    printf("Time taken by ebpf_should_drop_connection_rto running: %fms\n", ((double) (end-start)) / CLOCKS_PER_SEC * 1000);
    return ret;
}

int ebpf_parse_tcp_option(struct tcp_pcb *pcb, u8_t opt) {
    printf("ebpf_parse_tcp_option: opt %u\n", opt);
    const char *code_filename;
    printf("Checking opt\n");
    u16_t previous_tcp_optidx = tcp_optidx - 1; /* -1 because the option has already been read */
    u8_t option_length = tcp_get_next_optbyte();

    if (option_length < 2) {
        LWIP_DEBUGF(TCP_INPUT_DEBUG, ("tcp_parseopt: bad length\n"));
        /* If the length field is zero, the options are malformed
        and we don't process them further. */
        return ERR_ARG;
    }

    if (opt == 253 || opt == 254) {
        u16_t exID = custom_ntohs(tcp_get_next_optbyte() | (tcp_get_next_optbyte() << 8));
        if (opt == 253 && exID < 256) {
            code_filename = ebpf_options_parser_bpf_code_253[exID].filename;
            (pcb->cnx).current_plugin_name = ebpf_options_parser_bpf_code_253[exID].pluginName;
        } else if (opt == 254 && exID < 256) { /* opt == 254 */
            code_filename = ebpf_options_parser_bpf_code_254[exID].filename;
            (pcb->cnx).current_plugin_name = ebpf_options_parser_bpf_code_254[exID].pluginName;
        }
        if (code_filename) {
            printf("code_filename exp: %s\n", code_filename);
            uint64_t ret = run_ubpf_with_args(pcb, code_filename, option_length);
            if (ret == (uint64_t)-1) {
                /* VM crashed here */
                return ERR_ARG;
            }
            tcp_optidx = previous_tcp_optidx + option_length;
            return ERR_OK;
        }
        else {
            printf("No parser corresponds to opt %u and ExID 0x%x\n", opt, exID);
            /* Skip the option */
            tcp_optidx = previous_tcp_optidx + option_length;
            /* All other options have a length field, so that we easily
              can skip past them. */

            return ERR_VAL; /* Unknown TCP option is being used */
        }
    } else {
        code_filename = ebpf_options_parser_bpf_code[opt].filename;
        (pcb->cnx).current_plugin_name = ebpf_options_parser_bpf_code[opt].pluginName;
        if (code_filename) {
            printf("code_filename non-exp: %s\n", code_filename);
            uint64_t ret = run_ubpf_with_args(pcb, code_filename, option_length);// ,NULL);
            if (ret == (uint64_t)-1) {
                /* VM crashed here */
                return ERR_ARG;
            }
            tcp_optidx = previous_tcp_optidx + option_length;
            return ERR_OK;
        }
        else {
            printf("No parser corresponds to opt %u\n", opt);
            /* Skip the option */
            tcp_optidx = previous_tcp_optidx + option_length;
            /* All other options have a length field, so that we easily
              can skip past them. */

            return ERR_VAL; /* Unknown TCP option is being used */
        }
    }

    /*
    const char *code_filename = "/home/agobeaux/Desktop/M2Q1/MASTER_THESIS/VM_folder/lwip_programs/externals/lwip/ubpf/parse_tcp_option.bpf";
    LWIP_UNUSED_ARG(opt);
    return run_ubpf_with_args(pcb, code_filename); */
}

u32_t *ebpf_write_tcp_options(struct tcp_pcb *pcb, u32_t *opts) {
    if (!pcb) {
        return opts;
    }
    option_writer_node_t *head = ebpf_option_writers_list;
    if (!head) {
        // No option to write
        return opts;
    }
    while (head) {
        (pcb->cnx).current_plugin_name = head->pluginName;
        opts = run_ubpf_with_args(pcb, head->filename, opts);
        head = head->next;
    }
    return opts;
}

u8_t ebpf_get_options_length(struct tcp_pcb *pcb) {
    printf("ebpf_get_options_length\n");
    if (!pcb) {
        printf("NULL PCB -> returning 0 as options length\n");
        return 0;
    }

    if (pcb->state == SYN_RCVD || pcb->state == SYN_SENT || pcb->state == LISTEN) {
        printf("Returning ebpf_options_length (options negotiation): %u\n", ebpf_options_length_options_negotiation);
        return ebpf_options_length_options_negotiation;
    }
    printf("Returning ebpf_options_length: %u\n", ebpf_options_length);
    return ebpf_options_length;
}

int ebpf_is_ack_needed(struct tcp_pcb *pcb) {
    printf("ebpf_is_ack_needed\n");
    if (!ebpf_delayed_ack.filename) {
        /* Default behaviour: frequency = 1 ack / 2 */
        return pcb->num_rcv_unacked > 2;
    }
    (pcb->cnx).current_plugin_name = ebpf_delayed_ack.pluginName;
    return run_ubpf_with_args(pcb, ebpf_delayed_ack.filename);// ,NULL);
}

int ebpf_should_fast_retransmit(struct tcp_pcb *pcb) {
    printf("ebpf_should_fast_retransmit\n");
    if (!ebpf_fast_retransmit.filename) {
        /* Default behaviour */
        return pcb->dupacks >= 3;
    }
    (pcb->cnx).current_plugin_name = ebpf_fast_retransmit.pluginName;
    int ret = run_ubpf_with_args(pcb, ebpf_fast_retransmit.filename);// ,NULL);
    printf("ebpf_should_fast_retransmit returned: %d\n", ret);
    return ret;
}

uint64_t run_ubpf_args(struct tcp_pcb *pcb, const char *code_filename, int n_args, ...) {
    int i;
    va_list ap;
    clock_t start_run_ubpf_args = clock();
    va_start(ap, n_args);
    uint64_t args[n_args]; /* Cast everything to a uint64_t, thus able to contain pointers */

    for (i = 0; i < n_args; ++i) {
        args[i] = va_arg(ap, uint64_t);
        printf("run_ubpf_args: Before calling the function, args[%d] is at %p\n", i, args[i]);
    }

    va_end(ap);
    clock_t end_args_handling = clock();
    printf("Time taken to handle arguments for VM: %fms\n", ((double) (end_args_handling-start_run_ubpf_args)) /CLOCKS_PER_SEC*1000);

    pcb->cnx.inputc = n_args;
    pcb->cnx.inputv = args;

    const char *mem_filename = NULL;
    bool jit = false;

    size_t code_len;
    void *code;

    size_t mem_len = 20000; /* TODO: change this value */
    void *mem = (void*) malloc(20000);
    clock_t end_malloc = clock();
    printf("Time taken to malloc memory for the VM: %fms\n", ((double) (end_malloc-end_args_handling)) /CLOCKS_PER_SEC*1000);

    struct ubpf_vm *vm;

    uint64_t ret;

    printf("Beginning of run_ubpf()\n"); fflush(NULL); /* TODO: erase */
    clock_t start_read_code = clock();
    code = readfile(code_filename, 1024*1024, &code_len);
    if (code == NULL) {
        fprintf(stderr, "run_ubpf_args: readfile had a problem: code = NULL\n");
        if (mem) {
            free(mem);
        }
        return (uint64_t)-1;
    }
    clock_t end_read_code = clock();
    printf("Time taken to read the eBPF program: %fms\n", ((double) (end_read_code-start_read_code)) /CLOCKS_PER_SEC*1000);


    if (mem_filename != NULL) {
        mem = readfile(mem_filename, 1024*1024, &mem_len);
        if (mem == NULL) {
            return (uint64_t)-1;
        }
    }
    clock_t creation_start = clock();
    vm = ubpf_create();
    if (!vm) {
        if (mem) {
            free(mem);
        }
        fprintf(stderr, "Failed to create VM\n");
        return (uint64_t)-1;
    }

    register_functions(vm);
    clock_t register_end = clock();
    printf("Time taken to create VM and register functions: %fms\n", ((double) (register_end-creation_start)) /CLOCKS_PER_SEC*1000);

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
    clock_t loading_end = clock();
    printf("Time taken to load the code in the VM: %fms\n", ((double) (loading_end-register_end)) /CLOCKS_PER_SEC*1000);


    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        if (mem) {
            free(mem);
        }
        ubpf_destroy(vm);
        return (uint64_t)-1;
    }

    printf("Before JIT\n"); fflush(NULL); /* TODO: erase */

    if (jit) {
        printf("jit is true\n"); fflush(NULL); /* TODO: erase */
        fn = ubpf_compile(vm, &errmsg);
        if (fn == NULL) {
            if (mem) {
                free(mem);
            }
            fprintf(stderr, "Failed to compile: %s\n", errmsg);
            free(errmsg);
            return (uint64_t)-1;
        }
        ret = fn(mem, mem_len);
        clock_t exec_jit_end = clock();
        printf("Time taken to execute the code using JIT: %fms\n", ((double) (exec_jit_end-loading_end)) /CLOCKS_PER_SEC*1000);
    } else {
        printf("jit not used\n"); fflush(NULL); /* TODO: erase */
        ret = ubpf_exec_with_arg(vm, pcb, mem, mem_len);
        clock_t exec_nojit_end = clock();
        printf("Time taken to execute the code without using JIT: %fms\n", ((double) (exec_nojit_end-loading_end)) /CLOCKS_PER_SEC*1000);
    }

    printf("0x%"PRIx64"\n", ret);
    clock_t start_destroy_VM = clock();
    if (mem) {
        free(mem);
    }
    ubpf_destroy(vm);
    clock_t end_destroy_VM = clock();
    printf("Time taken to destroy the VM: %fms\n", ((double) (end_destroy_VM-start_destroy_VM))/CLOCKS_PER_SEC*1000);
    printf("Time taken for run_ubpf_args except args handling + mem_len malloc: %fms\n", ((double) (end_destroy_VM-creation_start))/CLOCKS_PER_SEC*1000);

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
    ubpf_register(vm, function_index++, "get_last_acked_seqno", get_last_acked_seqno);
    ubpf_register(vm, function_index++, "get_next_seqno", get_next_seqno);
    ubpf_register(vm, function_index++, "get_mss", get_mss);
    ubpf_register(vm, function_index++, "get_dupacks", get_dupacks);
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
    ubpf_register(vm, function_index++, "get_user_timeout", get_user_timeout);
    ubpf_register(vm, function_index++, "set_user_timeout", set_user_timeout);
    ubpf_register(vm, function_index++, "get_rto", get_rto);
    ubpf_register(vm, function_index++, "help_printf_sint16_t", help_printf_sint16_t);
    ubpf_register(vm, function_index++, "get_cnx", get_cnx);
    ubpf_register(vm, function_index++, "get_input", get_input);
    ubpf_register(vm, function_index++, "get_metadata", get_metadata);
    ubpf_register(vm, function_index++, "set_metadata", set_metadata);







    ubpf_register(vm, 63, "membound_fail", membound_fail);
}

int register_pluglet_function(const char *insertion_point, const char *code_filename, const char *plugin_name, int n_args, ...) {
    printf("WTFWTFregister_pluglet_function: number of args: %u\n", n_args);
    printf("register_pluglet_function: inp: %s, code_filename: %s, pluginN: %s\n", insertion_point, code_filename, plugin_name);
    int i;
    va_list ap;
    va_start(ap, n_args);
    uint64_t args[n_args]; /* Cast everything to a uint64_t, thus able to contain pointers */
    for (i = 0; i < n_args; ++i) {
        args[i] = va_arg(ap, uint64_t);
        printf("register_pluglet_function: Before calling the function, args[%d] is at %p and has value 0x%x\n", i, args[i], args[i]);
    }
    va_end(ap);

    /* Now, compare the insertion point to other strings and run the designated register */
    if (strcmp(insertion_point, "should_drop_connection") == 0) {
        return ubpf_register_should_drop_connection(code_filename, plugin_name);
    } else if (strcmp(insertion_point, "should_fast_retransmit") == 0) {
        return ubpf_register_should_fast_retransmit(code_filename, plugin_name);
    } else if (strcmp(insertion_point, "is_ack_needed") == 0) {
        return ubpf_register_delayed_ack(code_filename, plugin_name);
    } else if (strcmp(insertion_point, "tcp_option_writer") == 0) {
        if (n_args < 1) {
            printf("ERROR: for the tcp option writer, you should specify the length of the option.\n");
            return -1; /* should contain option kind and exID */
        }
        printf("length received as uint: %u, as int :%d, as int casted: %d\n", args[0], args[0], (int)args[0]);
        int length = (int) args[0];
        return ubpf_register_tcp_option_writer(code_filename, plugin_name, length);
    } else if (strcmp(insertion_point, "tcp_option_parser") == 0) {
        if (n_args < 2) {
            printf("ERROR: for the tcp option parser, you should specify an option kind and an exID.\n");
            return -1; /* should contain option kind and exID */
        }
        u8_t option_kind = (u8_t) (args[0] & 0xff);
        u16_t exID = (u16_t) (args[1] & 0xffff);
        return ubpf_register_tcp_option_parser(code_filename, option_kind, exID, plugin_name);
    } else {
        printf("ERROR: no corresponding pluglet register function found.\n");
        return -1;
    }
}

int ubpf_register_should_drop_connection(const char *code_filename, const char *plugin_name) {
    char *drop_connection_filename = malloc(strlen(code_filename) + 1);
    if (!drop_connection_filename) {
        printf("ERROR: Could not malloc drop_connection_filename in ubpf_register_should_drop_connection\n");
        return -1;
    }
    strcpy(drop_connection_filename, code_filename);

    char *pname = malloc(strlen(plugin_name) + 1);
    if (!pname) {
        printf("ERROR: Could not malloc pname in ubpf_register_should_drop_connection\n");
        free(drop_connection_filename);
        return -1;
    }
    strcpy(pname, plugin_name);

    // delete previously registered pluglet, if any
    if (ebpf_drop_connection.filename) {
        free(ebpf_drop_connection.filename);
    }
    if (ebpf_drop_connection.pluginName) {
        free(ebpf_drop_connection.pluginName);
    }
    ebpf_drop_connection.filename = drop_connection_filename;
    ebpf_drop_connection.pluginName = pname;
    return 0;
}

int ubpf_register_should_fast_retransmit(const char *code_filename, const char *plugin_name) {
    char *fretransmit_filename = malloc(strlen(code_filename) + 1);
    if (!fretransmit_filename) {
        printf("ERROR: Could not malloc fretransmit_filename in ubpf_register_should_fast_retransmit\n");
        return -1;
    }
    strcpy(fretransmit_filename, code_filename);

    char *pname = malloc(strlen(plugin_name) + 1);
    if (!pname) {
        printf("ERROR: Could not malloc pname in ubpf_register_should_fast_retransmit\n");
        free(fretransmit_filename);
        return -1;
    }
    strcpy(pname, plugin_name);

    // delete previously registered pluglet, if any
    if (ebpf_fast_retransmit.filename) {
        free(ebpf_fast_retransmit.filename);
    }
    if (ebpf_fast_retransmit.pluginName) {
        free(ebpf_fast_retransmit.pluginName);
    }
    ebpf_fast_retransmit.filename = fretransmit_filename;
    ebpf_fast_retransmit.pluginName = pname;
    return 0;
}

int ubpf_register_delayed_ack(const char *code_filename, const char *plugin_name) {
    char *dack_filename = malloc(strlen(code_filename) + 1);
    if (!dack_filename) {
        printf("ERROR: Could not malloc dack_filename in ubpf_register_delayed_ack\n");
        return -1;
    }
    strcpy(dack_filename, code_filename);

    char *pname = malloc(strlen(plugin_name) + 1);
    if (!pname) {
        printf("ERROR: Could not malloc pname in ubpf_register_delayed_ack\n");
        free(dack_filename);
        return -1;
    }
    strcpy(pname, plugin_name);

    // delete previously registered pluglet, if any
    if (ebpf_delayed_ack.filename) {
        free(ebpf_delayed_ack.filename);
    }
    if (ebpf_delayed_ack.pluginName) {
        free(ebpf_delayed_ack.pluginName);
    }
    ebpf_delayed_ack.filename = dack_filename;
    ebpf_delayed_ack.pluginName = pname;
    return 0;
}

int ubpf_register_tcp_option_writer(const char *code_filename, const char *plugin_name, int opt_len) {
    // add a node to the writer list
    option_writer_node_t *head = ebpf_option_writers_list;
    option_writer_node_t *new_node;
    new_node = malloc(sizeof(option_writer_node_t));
    if (!new_node) {
        printf("ERROR: Could not malloc option_writer_node_t in ubpf_register_tcp_option_writer\n");
        return -1;
    }
    char *writer_filename = malloc(strlen(code_filename) + 1);
    if (!writer_filename) {
        printf("ERROR: Could not malloc writer_filename in ubpf_register_tcp_option_writer\n");
        free(new_node);
        return -1;
    }
    strcpy(writer_filename, code_filename);
    new_node->filename = writer_filename;

    char *pname = malloc(strlen(plugin_name) + 1);
    if (!pname) {
        printf("ERROR: Could not malloc pname in ubpf_register_tcp_option_writer\n");
        free(writer_filename);
        free(new_node);
        return -1;
    }
    strcpy(pname, plugin_name);
    new_node->pluginName = pname;
    new_node->next = NULL;

    // Place the new node
    if (!head) {
        ebpf_option_writers_list = new_node;
    } else {
        while (head->next) {
            head = head->next;
        }
        head->next = new_node;
    }
    ebpf_options_length += opt_len;
    /* authorizing options to be run only during the handshake is not totally done but easily feasible */
    /* This would need having two distinct writer lists, and adding an argument to the register tcp option writer
       to say when this option should run */
    ebpf_options_length_options_negotiation += opt_len;
    return 0;
}

int ubpf_register_tcp_option_parser(const char *code_filename, u8_t opt, u16_t exID, const char *plugin_name) {
    printf("Got registration for opt %u, exID: %x\n", opt, exID);
    if (opt > 255) {
        printf("Error: The option kind must be contained in the [0, 255] interval\n");
        return -1;
    }
    if (exID > 255) {
        printf("Error: The option experimental ID (ExID) must be contained in the [0, 255] interval\n");
        return -1;
    }
    char *parser_filename = malloc(strlen(code_filename) + 1);
    if (!parser_filename) {
        printf("ERROR: Could not malloc parser_filename in ubpf_register_tcp_option_parser\n");
        return -1;
    }
    strcpy(parser_filename, code_filename);

    char *pname = malloc(strlen(plugin_name) + 1);
    if (!pname) {
        printf("ERROR: Could not malloc parser_filename in ubpf_register_tcp_option_parser\n");
        free(parser_filename);
        return -1;
    }
    strcpy(pname, plugin_name);

    printf("Parsed filename: %s, parsed plugin_name: %s\n", parser_filename, pname);
    if (opt == 253) {
        printf("%p\n", &ebpf_options_parser_bpf_code_253[exID]);
        ebpf_options_parser_bpf_code_253[exID].filename = parser_filename;
        ebpf_options_parser_bpf_code_253[exID].pluginName = pname;
    } else if (opt == 254) {
        printf("%p\n", &ebpf_options_parser_bpf_code_254[exID]);
        ebpf_options_parser_bpf_code_254[exID].filename = parser_filename;
        ebpf_options_parser_bpf_code_254[exID].pluginName = pname;
    } else {
        printf("%p\n", &ebpf_options_parser_bpf_code[opt]);
        ebpf_options_parser_bpf_code[opt].filename = parser_filename;
        ebpf_options_parser_bpf_code[opt].pluginName = pname;
    }
    return 0;
}
