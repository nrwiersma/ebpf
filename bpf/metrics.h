#ifndef __METRICS_H
#define __METRICS_H

struct event_t {
    __u64 ts;
    __u32 src_ip[4];
    __u32 dest_ip[4];
    __u16 src_port;
    __u16 dest_port;
    __u32 seq;
    __u32 ack_seq;
    __u32 len;
    __u16 direction;
    __u16 flags;
};

#endif