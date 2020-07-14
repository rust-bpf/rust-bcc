#include <uapi/linux/ptrace.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

// This code is taken from: https://github.com/iovisor/bcc/blob/master/tools/hardirqs.py
//
// Copyright (c) 2015 Brendan Gregg.
// Licensed under the Apache License, Version 2.0 (the "License")

typedef struct irq_key {
    char name[32];
    u64 slot;
} irq_key_t;

BPF_HASH(start, u32);
BPF_HASH(irqdesc, u32, struct irq_desc *);
BPF_HISTOGRAM(dist, irq_key_t);

// time IRQ
int hardirq_entry(struct pt_regs *ctx, struct irq_desc *desc)
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    irqdesc.update(&pid, &desc);
    return 0;
}

int hardirq_exit(struct pt_regs *ctx)
{
    u64 *tsp, delta;
    struct irq_desc **descp;
    u32 pid = bpf_get_current_pid_tgid();
    
    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    descp = irqdesc.lookup(&pid);
    if (tsp == 0 || descp == 0) {
        return 0;   // missed start
    }
    struct irq_desc *desc = *descp;
    struct irqaction *action = desc->action;
    char *name = (char *)action->name;
    delta = bpf_ktime_get_ns() - *tsp;

    // store as sum
    irq_key_t key = {.slot = 0 /* ignore */};
    bpf_probe_read_kernel(&key.name, sizeof(key.name), name);
    dist.increment(key, delta);

    start.delete(&pid);
    irqdesc.delete(&pid);
    return 0;
}