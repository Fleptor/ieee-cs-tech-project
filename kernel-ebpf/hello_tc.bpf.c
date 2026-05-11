#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

// A single-entry array map to store our packet counter
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} packet_count SEC(".maps");

SEC("tc")
int hello_tc(struct __sk_buff *skb) {
  __u32 key = 0;
  __u64 *count;

  count = bpf_map_lookup_elem(&packet_count, &key);
  if (count) {
    __sync_fetch_and_add(count, 1);
  }

  bpf_printk("Packet seen! Total so far: %llu\n", count ? *count : 0);

  return TC_ACT_OK; // Let the packet through — never drop in hello world
}

char LICENSE[] SEC("license") = "GPL";
