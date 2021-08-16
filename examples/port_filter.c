#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// This code is inspired from: https://github.com/iovisor/bcc/blob/master/examples/networking/http_filter/http-parse-simple.c
//
// Licensed under the Apache License, Version 2.0 (the "License")

#define IP_TCP 	6

#define DST_PORT 80

int port_filter(struct __sk_buffer *skb) {
	u8 *cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	//filter IP packets (ethernet type = 0x0800)
	if (!(ethernet->type == 0x0800)) {
		goto DROP;
	}

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	//filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP) {
		goto DROP;
	}

    u32  tcp_header_length = 0;
    u32  ip_header_length = 0;
    u32  payload_offset = 0;
    u32  payload_length = 0;

    //calculate ip header length
    //value to multiply * 4
    //e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
    ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply

    //check ip header length against minimum
    if (ip_header_length < sizeof(*ip)) {
            goto DROP;
    }

    //shift cursor forward for dynamic ip header size
    void *_ = cursor_advance(cursor, (ip_header_length-sizeof(*ip)));

    struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    if(tcp->dst_port == DST_PORT) {
        goto END;
    } 

DROP:
    return 0;

END:
    // indicates that the packet can be passed to userspace
    return -1;
}