#include "vmlinux.h"

#include "bpf_helpers.h"
#include "common_types.h"

#ifndef __MAPS_H_
#define __MAPS_H_

#define BPF_HASH_MAP(name, key_type, value_type, size)                         \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_HASH);                                           \
    __uint(key_size, sizeof(key_type));                                        \
    __uint(value_size, sizeof(value_type));                                    \
    __uint(max_entries, size);                                                 \
  } name SEC(".maps");

#define BPF_PERF_EVENT_ARRAY(name, size)                                       \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);                               \
    __uint(key_size, sizeof(u32));                                             \
    __uint(value_size, sizeof(u32));                                           \
    __uint(max_entries, size);                                                 \
  } name SEC(".maps");

static __always_inline void *bpf_hashmap_pop(void *map, const void *key) {
  void *value = bpf_map_lookup_elem(map, key);
  bpf_map_delete_elem(map, key);
  return value;
}

BPF_HASH_MAP(custom_config_map, u32, struct custom_config_t, 1)
static __always_inline struct custom_config_t *get_config() {
  u32 key = 0;
  struct custom_config_t *config =
      bpf_map_lookup_elem(&custom_config_map, &key);
  return config;
}




#endif // __MAPS_H_
       //
