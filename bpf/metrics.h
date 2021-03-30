#ifndef __METRICS_H
#define __METRICS_H

struct stash_tuple {
    __be32 ip[4];
    __u16 port;
    __u32 seq;
};

struct pkt_entry {
    __u64 ts;
    __be32 src_ip[4];
    __be32 dest_ip[4];
    __u16 src_port;
    __u16 dest_port;
    __u32 len;
    __u32 rtt;
    __u16 protocol;
    __u16 flags;
};

#endif