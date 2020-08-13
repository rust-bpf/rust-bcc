// Copyright 2019-2020 Twitter, Inc.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

// Must provide the number of CPUs on the machine
BPF_PERF_ARRAY(cycle_perf, NUM_CPU);
BPF_PERF_ARRAY(instr_perf, NUM_CPU);

// Previously seen values
BPF_ARRAY(cycle_prev, u64, NUM_CPU);
BPF_ARRAY(instr_prev, u64, NUM_CPU);

// Tables which are read in user space
BPF_ARRAY(cycle, u64, NUM_CPU);
BPF_ARRAY(instr, u64, NUM_CPU);

int do_count(struct bpf_perf_event_data *ctx) {
    u32 cpu = bpf_get_smp_processor_id();

    u64 cycle_cnt = cycle_perf.perf_read(CUR_CPU_IDENTIFIER);
    if (((s64)cycle_cnt < 0) && ((s64)cycle_cnt > -256))
        return 0;
    u64 instr_cnt = instr_perf.perf_read(CUR_CPU_IDENTIFIER);
    if (((s64)instr_cnt < 0) && ((s64)instr_cnt > -256))
        return 0;

    u64* cyc_prev = cycle_prev.lookup(&cpu);
    u64* ins_prev = instr_prev.lookup(&cpu);

    u64 vCyc = 0;
    if (cyc_prev) {
        vCyc = cycle_cnt - *cyc_prev;
    }

    u64 vIns = 0;
    if (ins_prev) {
        vIns = instr_cnt - *ins_prev;
    }

    cycle_prev.update(&cpu, &cycle_cnt);
    instr_prev.update(&cpu, &instr_cnt);

    cycle.increment(cpu, vCyc);
    instr.increment(cpu, vIns);

    return 0;
}
