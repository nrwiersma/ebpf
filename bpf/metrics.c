#include <stddef.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps/count") count_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u64),
	.max_entries = 4,
};

SEC("cgroup/skb")
int metrics(struct __sk_buff *skb)
{
    int packets_key = 0, bytes_key = 1;
    __u64 *packets = NULL;
    __u64 *bytes = NULL;

    packets = bpf_map_lookup_elem(&count_map, &packets_key);
    if (packets == NULL)
        return 0;

    *packets += 1;

    bytes = bpf_map_lookup_elem(&count_map, &bytes_key);
    if (bytes == NULL)
        return 0;

    __u16 dest = 0;
    bpf_skb_load_bytes(skb, sizeof(struct iphdr) + offsetof(struct tcphdr, dest), &dest, sizeof(dest));

    if (dest == __constant_ntohs(80))
        *bytes += skb->len;

    // don't drop
    return 1;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;