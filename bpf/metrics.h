#ifndef __METRICS_H
#define __METRICS_H

struct event_t {
    unsigned long long ts;
    unsigned long src_ip;
    unsigned long dest_ip;
    unsigned int src_port;
    unsigned int dest_port;
    unsigned long seq;
    unsigned long ack_seq;
    unsigned long len;
    unsigned int direction;
    unsigned int flags;
};

#endif