#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// This code is taken from: https://github.com/iovisor/bcc/blob/master/tools/tcpretrans.py
//
// Copyright 2016 Netflix, Inc. 
// Licensed under the Apache License, Version 2.0 (the "License")
 
#define RETRANSMIT  1
#define TLP         2

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u32 pid;
    u64 ip;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    u64 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv6_events);

static int trace_event(struct pt_regs *ctx, struct sock *skp, int type)
{
    if (skp == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // pull in details
    u16 family = skp->__sk_common.skc_family;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    char state = skp->__sk_common.skc_state;

    if (family == AF_INET) {
        struct ipv4_data_t data4 = {};
        data4.pid = pid;
        data4.ip = 4;
        data4.type = type;
        data4.saddr = skp->__sk_common.skc_rcv_saddr;
        data4.daddr = skp->__sk_common.skc_daddr;
        // lport is host order
        data4.lport = lport;
        data4.dport = ntohs(dport);
        data4.state = state; 
        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    } else if (family == AF_INET6) {
        struct ipv6_data_t data6 = {};
        data6.pid = pid;
        data6.ip = 6;
        data6.type = type;
        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
                       skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
                       skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        // lport is host order
        data6.lport = lport;
        data6.dport = ntohs(dport);
        data6.state = state;
        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
    }
    // else drop

    return 0;
}

int trace_retransmit(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk, RETRANSMIT);
    return 0;
}

int trace_tlp(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk, TLP);
    return 0;
}
