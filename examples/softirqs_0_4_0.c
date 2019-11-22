#include <uapi/linux/ptrace.h>

// This code is taken from: https://github.com/iovisor/bcc/tools/softirqs.py
//
// Copyright (c) 2015 Brendan Gregg.
// Licensed under the Apache License, Version 2.0 (the "License")

typedef struct irq_key {
    u32 vec;
    u64 slot;
} irq_key_t;

typedef struct account_val {
    u64 ts;
    u32 vec;
} account_val_t;

BPF_HASH(start, u32, account_val_t);
BPF_HISTOGRAM(dist, irq_key_t);

int softirq_entry(struct tracepoint__irq__softirq_entry *args)
{
    u32 pid = bpf_get_current_pid_tgid();
    account_val_t val = {};
    val.ts = bpf_ktime_get_ns();
    val.vec = args->vec;
    start.update(&pid, &val);
    return 0;
}

// for use with bcc 0.4.0 - 0.6.1
int softirq_exit(struct tracepoint__irq__softirq_exit *args)
{
    u64 delta;
    u32 vec;
    u32 pid = bpf_get_current_pid_tgid();
    account_val_t *valp;
    irq_key_t key = {0};
    // fetch timestamp and calculate delta
    valp = start.lookup(&pid);
    if (valp == 0) {
        return 0;   // missed start
    }
    delta = bpf_ktime_get_ns() - valp->ts;
    vec = valp->vec;

    // store as sum
    key.vec = valp->vec;
    u64 zero = 0,
    *vp = dist.lookup_or_init(&key, &zero);
    (*vp) += delta;

    start.delete(&pid);
    return 0;
}
