/**
 * This file implements a Map Abstract Data Type using a LinkedList.
 * The performances are not good compared to a HashMap but this will be used for a small number of keys.
 * Indeed, this Map will be used for mapping plugins names to memory space for those plugins (usable by sub-plugins)
 */

#include <lwip/map.h>

plugins_memory_t *init_plugin_memory_map(void) {
  plugins_memory_t *head = (plugins_memory_t *) calloc(1, sizeof(plugins_memory_t));
  if (!head) {
    printf("map.c: could not allocate head of map\n");
  }
  printf("MAP.C: plugin_memory_map initiated\n");
  return head;
}

int add_plugin_memory(plugins_memory_t *head, const char *pname, int memlen, bool should_allocate_memory) {
  plugins_memory_t *newnode;
  plugins_memory_t *runner = head;

  if (!head->plugin_name) {
    /* Empty map: head node will contain the new information */
    newnode = head;
  } else {
    newnode = (plugins_memory_t *) calloc(1, sizeof(plugins_memory_t));
    if (!newnode) {
      printf("Couldn't calloc a new node in plugin_memory_map\n");
      return -1;
    }

    printf("head: %p\n", head);
    printf("head->plugin_name: %p\n", head->plugin_name);
    printf("pname: %p\n", pname);
    /* Add the node to the linked list */
    if (strcmp(head->plugin_name, pname) == 0) {
      printf("Plugin already exists in the map!\n");
      free(newnode);
      return -1;
    }
    while (runner->next) {
      if (strcmp(head->plugin_name, pname) == 0) {
        printf("Plugin already exists in the map!\n");
        free(newnode);
        return -1;
      }
      runner = runner->next;
    }
    runner->next = newnode;
  }

  newnode->plugin_name = (char *) malloc(sizeof(char) * (strlen(pname) + 1));
  if (!(newnode->plugin_name)) {
    printf("Couldn't malloc newnode->plugin_name for the plugin_memory map\n");
    if (head != newnode)
      free(newnode);
    runner->next = NULL;
    return -1;
  }
  strcpy(newnode->plugin_name, pname);

  if (memlen > 0 && should_allocate_memory) {
    /* Should be true as it would be useless to add a plugin without memory to this queue */
    newnode->mem_len = memlen;
    newnode->mem_array = (uint64_t *) malloc(memlen * sizeof(uint64_t));
    if (!(newnode->mem_array)) {
      printf("Couln't malloc the newnode->mem_array for the plugin_memory map\n");
      free(newnode->plugin_name);
      if (head != newnode) {
        runner->next = NULL;
        free(newnode);
      }
      else
        newnode->plugin_name = NULL;
      return -1;
    }
  } else {
    newnode->mem_len = 0;
  }
  return 0;
}

plugins_memory_t *find_plugin_memory_node(plugins_memory_t *head, char *plugin_name) {
  plugins_memory_t *runner = head;
  while (runner) {
    if (strcmp(plugin_name, runner->plugin_name) == 0) {
      return runner;
    }
    runner = runner->next;
  }
  return NULL;
}

plugins_memory_t *clone_plugin_memory_map(plugins_memory_t *head) {
  plugins_memory_t *newMap = (plugins_memory_t *) calloc(1, sizeof(plugins_memory_t));
  if (!newMap) {
    printf("Couldn't calloc new map in clone plugin_memory map function\n");
  }
  if (head->plugin_name) {
    newMap->plugin_name = (char *) malloc(strlen(head->plugin_name) + 1);
    if (!(newMap->plugin_name)) {
      printf("Couldn't malloc plugin name for new map in clone plugin_memory map function\n");
      free(newMap);
      return NULL;
    }
    strcpy(newMap->plugin_name, head->plugin_name);
    newMap->mem_len = head->mem_len;
    if (head->mem_len > 0) {
      newMap->mem_array = (uint64_t *) malloc(head->mem_len * sizeof(uint64_t));
      if (!(newMap->mem_array)) {
        printf("Couldn't malloc mem array for new map in clone plugin_memory map function\n");
        free(newMap->plugin_name);
        free(newMap);
        return NULL;
      }
    } else {
      newMap->mem_array = NULL;
    }
  } else {
    return newMap;
  }

  plugins_memory_t *oldRunner = head;
  plugins_memory_t *newRunner = newMap;

  while (oldRunner) {
    plugins_memory_t *newNode = (plugins_memory_t *) malloc(sizeof(plugins_memory_t));
    if (!newNode) {
      printf("Couldn't malloc new node in clone plugin_memory map function\n");
      free_plugin_memory_map(newMap);
      return NULL;
    }
    newNode->plugin_name = (char *) malloc(strlen(oldRunner->plugin_name) + 1);
    if (!(newNode->plugin_name)) {
      printf("Couldn't malloc plugin name in clone plugin_memory map function\n");
      free_plugin_memory_map(newMap);
      return NULL;
    }
    strcpy(newNode->plugin_name, oldRunner->plugin_name);
    newNode->mem_len = oldRunner->mem_len;
    if (oldRunner->mem_len > 0) {
      newNode->mem_array = (uint64_t *) malloc(oldRunner->mem_len * sizeof(uint64_t));
      if (!(newNode->mem_array)) {
        printf("Couldn't malloc mem array in clone plugin_memory map function\n");
        free_plugin_memory_map(newMap);
        return NULL;
      }
    } else {
      newNode->mem_array = NULL;
    }

    /* Add the new node to the new list */
    newRunner->next = newNode;

    /* Go through both lists */
    newRunner = newNode;
    oldRunner = oldRunner->next;
  }
}


void free_plugin_memory_map(plugins_memory_t *head) {
  while (head) {
    plugins_memory_t *next = head->next;
    if (head->plugin_name) {
      /* Necessary condition as empty map = node with NULL plugin_name */
      free(head->plugin_name);
    }
    if (head->mem_array)
      free(head->mem_array);
    free(head);
    head = next;
  }
}
