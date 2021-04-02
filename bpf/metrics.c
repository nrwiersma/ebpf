#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
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

struct bpf_map_def SEC("maps/stash") stash = {
	.type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct stash_tuple),
    .value_size = sizeof(struct pkt_entry),
    .max_entries = 1024 * 4,
};

struct bpf_map_def SEC("maps/packets") packets = {
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

static __always_inline
void ipv4tov6(__be32 ipv6[4], __be32 ip) {
    // Assume the ipv6 is zeroed.
    ipv6[2] = 0xffff;
    ipv6[3] = __constant_htonl(ip);
}

static __always_inline
int process(struct __sk_buff *skb, __u16 direction) {
    __u32 len = skb->len;
    __u32 nh_off;
    __u32 hdrlen;
    struct iphdr *ip4;
    struct tcphdr *tcp;
    struct pkt_entry pkt = {};

    // TODO: handle ipv6
    if (skb->protocol != __constant_htons(ETH_P_IP)) {
        return KEEP;
    }

    advance(skb, 0, ip4);

    pkt.ts = bpf_ktime_get_ns();
    ipv4tov6(pkt.src_ip, ip4->saddr);
    ipv4tov6(pkt.dest_ip, ip4->daddr);

    hdrlen = ip4->ihl << 2;
    len -= hdrlen;
    nh_off = hdrlen;

    // TODO: handle udp
    if (ip4->protocol != IPPROTO_TCP)
        return KEEP;

    advance(skb, nh_off, tcp);

    hdrlen = tcp->doff << 2;
    len -= hdrlen;

    pkt.src_port = __constant_ntohs(tcp->source);
    pkt.dest_port = __constant_ntohs(tcp->dest);
    pkt.protocol = PROTO_TCP;
    pkt.flags = direction;
    if (tcp->syn)
        pkt.flags += TYPE_SYN;
    else if (tcp->fin)
        pkt.flags += TYPE_FIN;
    pkt.len = len;

    if (tcp->syn || tcp->fin || len != 0) {
        switch (direction) {
        case DIR_OUT:
        {
            // In this case we need to stash to packet to wait for ACK.
            struct stash_tuple key = {
                .port       = pkt.src_port,
                .seq        = __constant_ntohl(tcp->ack_seq),
            };
            memcpy(key.ip, pkt.src_ip, sizeof(key.ip));

            bpf_map_update_elem(&stash, &key, &pkt, 0);
            break;
        }

        case DIR_IN:
            // In this case we received the packet, we can just send it.
            bpf_perf_event_output(skb, &packets, 0 /* flags */, &pkt, sizeof(pkt));
            break;
        }
    }

    if (direction == DIR_IN && tcp->ack) {
        // We received an ack, look for the packet to send.
        struct pkt_entry *found;
        struct stash_tuple key = {
            .port       = pkt.dest_port,
            .seq        = __constant_ntohl(tcp->seq),
        };
        memcpy(key.ip, pkt.dest_ip, sizeof(key.ip));
        if (tcp->syn && tcp->ack)
            // If it was the initial SYN, the AckSYN would be 0.
            key.seq = 0;

        found = bpf_map_lookup_elem(&stash, &key);
        if (found != NULL) {
            bpf_map_delete_elem(&stash, &key);

            found->rtt = pkt.ts - found->ts;
            found->ts = pkt.ts;

            bpf_perf_event_output(skb, &packets, 0 /* flags */, found, sizeof(*found));
        }
    }

    return KEEP;
}

SEC("cgroup/skb/ingress")
int metrics_ingress(struct __sk_buff *skb)
{
    return process(skb, DIR_IN);
}

SEC("cgroup/skb/egress")
int metrics_egress(struct __sk_buff *skb)
{
    return process(skb, DIR_OUT);
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0;