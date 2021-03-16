#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <arpa/inet.h>
#include "bpf_helpers.h"
#include "metrics.h"

#define KEEP 1
#define DROP 0

#define PACKETS_KEY 0
#define SYN_KEY 1
#define ACK_KEY 2
#define BYTES_KEY 3

struct bpf_map_def SEC("maps/events") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 1024 * 64,
};

SEC("cgroup/skb")
int metrics(struct __sk_buff *skb)
{
    __u32 hdrlen;
    struct iphdr *ip4;
    struct tcphdr *tcp;
    struct event_t event = {};

    __u32 len = skb->len;
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;

    // TODO: handle ipv6
    if (skb->protocol != __constant_htons(ETH_P_IP))
        return KEEP;

    if (data + sizeof(*ip4) > data_end)
        return KEEP;

    // TODO: handle udp
    ip4 = data;
    if (ip4->protocol != IPPROTO_TCP)
        return KEEP;

    event.ts = bpf_ktime_get_ns();
    event.src_ip = __constant_ntohl(ip4->saddr);
    event.dest_ip = __constant_ntohl(ip4->daddr);

    hdrlen = ip4->ihl << 2;
    len -= hdrlen;
    data += hdrlen;

    if (data + sizeof(*tcp) > data_end)
        return KEEP;

    tcp = data;

    event.src_port = __constant_ntohs(tcp->source);
    event.dest_port = __constant_ntohs(tcp->dest);
    event.seq = __constant_ntohl(tcp->seq);
    event.ack_seq = __constant_ntohl(tcp->ack_seq);
    event.flags = 0;
    if (tcp->syn)
        event.flags += 1;
    if (tcp->ack)
        event.flags += 2;
    if (tcp->fin)
        event.flags += 4;

    hdrlen = tcp->doff << 2;
    len -= hdrlen;

    event.len = len;
    bpf_perf_event_output(skb, &events, 0 /* flags */, &event, sizeof(event));

    return KEEP;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0;