// Copyright 2019-2020 Twitter, Inc.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

#ifdef PERCPU
struct key_t {
    int cpu;
    int pid;
};
BPF_HASH(count, struct key_t);
#else
BPF_HASH(count, u32);
#endif

int do_count(struct bpf_perf_event_data *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;

    if (##PID_FILTER##) {
        return 0;
    }

    u32 tgid = id >> 32;
    if (##TGID_FILTER##) {
        return 0;
    }

#ifdef PERCPU
    struct key_t key = {};
    key.cpu = bpf_get_smp_processor_id();
    key.pid = bpf_get_current_pid_tgid();
#else
    u32 key = pid;
#endif

    count.increment(key);
    return 0;
}
