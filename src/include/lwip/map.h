/**
 * This file implements a Map Abstract Data Type using a LinkedList.
 * The performances are not good compared to a HashMap but this will be used for a small number of keys.
 * Indeed, this Map will be used for mapping plugins names to memory space for those plugins (usable by sub-plugins)
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

typedef struct plugins_memory {

  struct plugins_memory *next;

  char *plugin_name; /* Map Key */

  /* Map Value */
  uint64_t *mem_array;
  int mem_len;

} plugins_memory_t;


plugins_memory_t *global_plugins_memory_map;


plugins_memory_t *init_plugin_memory_map(void);

int add_plugin_memory(plugins_memory_t *head, const char *pname, int memlen, bool should_allocate_memory);

plugins_memory_t *find_plugin_memory_node(plugins_memory_t *head, char *plugin_name);

plugins_memory_t *clone_plugin_memory_map(plugins_memory_t *head);

void free_plugin_memory_map(plugins_memory_t *head);
