#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

typedef struct pid_key {
    u64 id;    // work around
    u64 slot;
} pid_key_t;

typedef struct pidns_key {
    u64 id;    // work around
    u64 slot;
} pidns_key_t;

BPF_HASH(start, u32);
BPF_HISTOGRAM(dist);
struct rq;

// record enqueue timestamp
static int trace_enqueue(u32 tgid, u32 pid)
{
    if (pid == 0)
        return 0;
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{
    return trace_enqueue(p->tgid, p->pid);
}
int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p,
    int wake_flags)
{
    return trace_enqueue(p->tgid, p->pid);
}
// calculate latency
int trace_run(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid, tgid;
    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (pid != 0) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }
    tgid = bpf_get_current_pid_tgid() >> 32;
    pid = bpf_get_current_pid_tgid();
    if (pid == 0)
        return 0;
    u64 *tsp, delta;
    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000; // microseconds
    // store as histogram
    dist.increment(bpf_log2l(delta));
    start.delete(&pid);
    return 0;
}

#define FEATURE_SUPPORT_RAW_TP
#ifdef FEATURE_SUPPORT_RAW_TP
int raw_tp__sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

int raw_tp__sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx->args[0];
    return trace_enqueue(p->tgid, p->pid);
}

int raw_tp__sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    // TP_PROTO(bool preempt, struct task_struct *prev, struct task_struct *next)
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    u32 pid, tgid;

    // ivcsw: treat like an enqueue event and store timestamp
    if (prev->state == TASK_RUNNING) {
        tgid = prev->tgid;
        pid = prev->pid;
        if (pid != 0) {
            u64 ts = bpf_ktime_get_ns();
            start.update(&pid, &ts);
        }
    }

    tgid = next->tgid;
    pid = next->pid;
    if (pid == 0)
        return 0;
    u64 *tsp, delta;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;   // missed enqueue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000; // microseconds
    // store as histogram
    dist.increment(bpf_log2l(delta));
    start.delete(&pid);
    return 0;
}
#endif
