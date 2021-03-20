#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <arpa/inet.h>
#include "bpf_helpers.h"
#include "metrics.h"

#define KEEP 1
#define DROP 0

struct bpf_map_def SEC("maps/events") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 1024 * 64,
};

#define advance(skb, var_off, hdr)                      \
({                                                      \
	void *data = (void *)(long)skb->data + var_off;     \
	void *data_end = (void *)(long)skb->data_end;       \
                                                        \
	if (data + sizeof(*hdr) > data_end)                 \
		return KEEP;                                    \
                                                        \
	hdr = (void *)(data);                               \
})

__attribute__((always_inline))
int process(struct __sk_buff *skb, __u16 direction)
{
    __u32 len = skb->len;
    __u32 nh_off;
    __u32 hdrlen;
    struct iphdr *ip4;
    struct tcphdr *tcp;
    struct event_t event = {};

    // TODO: handle ipv6
    if (skb->protocol != __constant_htons(ETH_P_IP)) {
        return KEEP;
    }

    advance(skb, 0, ip4);

    // TODO: handle udp
    if (ip4->protocol != IPPROTO_TCP)
        return KEEP;

    event.ts = bpf_ktime_get_ns();
    event.src_ip = __constant_ntohl(ip4->saddr);
    event.dest_ip = __constant_ntohl(ip4->daddr);

    hdrlen = ip4->ihl << 2;
    len -= hdrlen;
    nh_off = hdrlen;

    advance(skb, nh_off, tcp);

    event.src_port = __constant_ntohs(tcp->source);
    event.dest_port = __constant_ntohs(tcp->dest);
    event.seq = __constant_ntohl(tcp->seq);
    event.ack_seq = __constant_ntohl(tcp->ack_seq);
    event.direction = direction;
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

SEC("cgroup/skb/ingress")
int metrics_ingress(struct __sk_buff *skb)
{
    return process(skb, 1);
}

SEC("cgroup/skb/egress")
int metrics_egress(struct __sk_buff *skb)
{
    return process(skb, 2);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0;