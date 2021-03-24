// Copyright 2021 Twitter, Inc.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

// Must provide the number of CPUs on the machine
BPF_PERF_ARRAY(loads_perf, NUM_CPU);

// Previously seen values
BPF_ARRAY(loads_prev, u64, NUM_CPU);

// Tables which are read in user space
BPF_ARRAY(loads, u64, NUM_CPU);

int do_count(struct bpf_perf_event_data *ctx) {
    u32 cpu = bpf_get_smp_processor_id();

    u64 loads_cnt = loads_perf.perf_read(CUR_CPU_IDENTIFIER);
    if (((s64)loads_cnt < 0) && ((s64)loads_cnt > -256))
        return 0;

    u64* prev = loads_prev.lookup(&cpu);

    u64 vLoads = 0;
    if (prev) {
        vLoads = loads_cnt - *prev;
    }

    loads_prev.update(&cpu, &loads_cnt);

    loads.increment(cpu, vLoads);

    return 0;
}
