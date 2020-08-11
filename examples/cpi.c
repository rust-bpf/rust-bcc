// Copyright 2019-2020 Twitter, Inc.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

// Must provide the number of CPUs in the server
BPF_PERF_ARRAY(cycle_perf, NUM_CPU);
BPF_PERF_ARRAY(instr_perf, NUM_CPU);

BPF_HASH(cycle, u32);
BPF_HASH(instr, u32);

BPF_HASH(cyc_tot, u64, 1);
BPF_HASH(ins_tot, u64, 1);

int do_count(struct bpf_perf_event_data *ctx) {
    u32 cpu = bpf_get_smp_processor_id();
    int zero = 0;

    u64 cycle_cnt = cycle_perf.perf_read(CUR_CPU_IDENTIFIER);
    if (((s64)cycle_cnt < 0) && ((s64)cycle_cnt > -256))
        return 0;

    u64 instr_cnt = instr_perf.perf_read(CUR_CPU_IDENTIFIER);
    if (((s64)instr_cnt < 0) && ((s64)instr_cnt > -256))
        return 0;

    cyc_tot.update(&zero, cycle_cnt);
    ins_tot.update(&zero, instr_cnt);

    cycle.update(&cpu, cycle_cnt);
    instr.update(&cpu, instr_cnt);

    return 0;
}