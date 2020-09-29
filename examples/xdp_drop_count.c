// This code is taken from: https://github.com/iovisor/bcc/blob/master/examples/networking/xdp/xdp_drop_count.py
//
// Copyright 2016 Netflix, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#define KBUILD_MODNAME "rust-bcc-xdp-drop"

#include<uapi/linux/bpf.h>
#include<linux/in.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>
#include<linux/if_vlan.h>
#include<linux/ip.h>
#include<linux/ipv6.h>

BPF_HASH(dropcnt, uint32_t, long);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void *)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void *)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

int xdp_prog1(struct CTXTYPE *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    // drop packets
    int rc = RETURNCODE; // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;
    uint16_t nh_off = 0;
    uint32_t index;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return rc;

    h_proto = eth->h_proto;

    // parse double vlans
    #pragma unroll
    for (int i=0; i<2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr;

            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                return rc;

            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    if (h_proto == htons(ETH_P_IP))
        index = parse_ipv4(data, nh_off, data_end);
    else if (h_proto == htons(ETH_P_IPV6))
        index = parse_ipv6(data, nh_off, data_end);
    else
        index = 0;

    long zero = 0;
    value = dropcnt.lookup_or_init(&index, &zero);
    if (value)
        *value += 1;

    return rc;
}

