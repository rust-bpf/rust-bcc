#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct start_timestamp_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char host[80];
    u64 ts;
};
struct latency_event_t {
    u32 pid;
    u64 delta;
    char comm[TASK_COMM_LEN];
    char host[80];
};
BPF_HASH(start, u32, struct start_timestamp_t);
BPF_PERF_OUTPUT(events);
int do_entry(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
    struct start_timestamp_t val = {};
    u32 pid = bpf_get_current_pid_tgid();
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        bpf_probe_read_user(&val.host, sizeof(val.host),
                       (void *)PT_REGS_PARM1(ctx));
        val.pid = bpf_get_current_pid_tgid();
        val.ts = bpf_ktime_get_ns();
        start.update(&pid, &val);
    }
    return 0;
}
int do_return(struct pt_regs *ctx) {
    struct start_timestamp_t *start_timestamp;
    struct latency_event_t perf_event = {};
    u64 delta;
    u32 pid = bpf_get_current_pid_tgid();
    u64 finish_timestamp = bpf_ktime_get_ns();
    start_timestamp = start.lookup(&pid);
    if (start_timestamp == 0)
        return 0; // missed start
    bpf_probe_read_kernel(&perf_event.comm, sizeof(perf_event.comm), start_timestamp->comm);
    bpf_probe_read_kernel(&perf_event.host, sizeof(perf_event.host), (void *)start_timestamp->host);
    perf_event.pid = start_timestamp->pid;
    perf_event.delta = finish_timestamp - start_timestamp->ts;
    events.perf_submit(ctx, &perf_event, sizeof(perf_event));
    start.delete(&pid);
    return 0;
}