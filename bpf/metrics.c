#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include "bpf_helpers.h"

#define KEEP 1
#define DROP 0

#define PACKETS_KEY 0
#define SYN_KEY 1
#define ACK_KEY 2
#define BYTES_KEY 3

struct bpf_map_def SEC("maps/count") count_map = {
	.type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u64),
    .max_entries = 1024,
};

SEC("cgroup/skb")
int metrics(struct __sk_buff *skb)
{
    struct ethhdr *eth;

    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
//     uint64_t nh_off = 0;

    if (data + sizeof(*eth) > data_end)
        return KEEP;

    // TODO: handle ipv6
    eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6))
        return KEEP;

    int packets_key = PACKETS_KEY, bytes_key = BYTES_KEY;
    __u64 *packets = 0;
    __u64 *bytes = 0;

    packets = bpf_map_lookup_elem(&count_map, &packets_key);
    if (packets == 0)
        return DROP;

    *packets += 1;

    bytes = bpf_map_lookup_elem(&count_map, &bytes_key);
    if (bytes == 0)
        return DROP;

    __u16 dest = 0;
    bpf_skb_load_bytes(skb, sizeof(struct iphdr) + offsetof(struct tcphdr, dest), &dest, sizeof(dest));

    if (dest == __constant_ntohs(80))
        *bytes += skb->len;

    // don't drop
    return KEEP;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0;