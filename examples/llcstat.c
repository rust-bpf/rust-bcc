#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

// Taken from https://github.com/iovisor/bcc/blob/master/tools/llcstat.py
//
// Copyright (c) 2016 Facebook, Inc.

struct key_t {
    int cpu;
    int pid;
    char name[TASK_COMM_LEN];
};

BPF_HASH(ref_count, struct key_t);
BPF_HASH(miss_count, struct key_t);

static inline __attribute__((always_inline)) void get_key(struct key_t* key) {
    key->cpu = bpf_get_smp_processor_id();
    key->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&(key->name), sizeof(key->name));
}

int on_cache_miss(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    miss_count.increment(key, ctx->sample_period);
    return 0;
}

int on_cache_ref(struct bpf_perf_event_data *ctx) {
    struct key_t key = {};
    get_key(&key);
    ref_count.increment(key, ctx->sample_period);
    return 0;
}
