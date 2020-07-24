#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>
struct data_t {
    u64 ts;
    u64 cpu;
    u64 len;
};
BPF_PERF_OUTPUT(events);
// Declare enough of cfs_rq to find nr_running, since we can't #import the
// header. This will need maintenance. It is from kernel/sched/sched.h:
struct cfs_rq_partial {
    struct load_weight load;
    unsigned long runnable_weight;
    unsigned int nr_running, h_nr_running;
};

int do_perf_event(struct bpf_perf_event_data *ctx)
{
    int cpu = bpf_get_smp_processor_id();
    u64 now = bpf_ktime_get_ns();
    /*
     * Fetch the run queue length from task->se.cfs_rq->nr_running. This is an
     * unstable interface and may need maintenance. Perhaps a future version
     * of BPF will support task_rq(p) or something similar as a more reliable
     * interface.
     */
    unsigned int len = 0;
    struct task_struct *task = NULL;
    struct cfs_rq_partial *my_q = NULL;
    task = (struct task_struct *)bpf_get_current_task();
    my_q = (struct cfs_rq_partial *)task->se.cfs_rq;
    len = my_q->nr_running;
    struct data_t data = {.ts = now, .cpu = cpu, .len = len};
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}