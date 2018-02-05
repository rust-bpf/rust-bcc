#include <uapi/linux/ptrace.h>
#include <uapi/linux/limits.h>
#include <linux/sched.h>
struct val_t {
    u64 id;
    u64 ts;
    char comm[TASK_COMM_LEN];
    const char *fname;
};
struct data_t {
    u64 id;
    u64 ts;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[NAME_MAX];
};
BPF_HASH(infotmp, u64, struct val_t);
BPF_PERF_OUTPUT(events);
int trace_entry(struct pt_regs *ctx, int dfd, const char __user *filename)
{
    struct val_t val = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        val.id = id;
        val.ts = bpf_ktime_get_ns();
        val.fname = filename;
        infotmp.update(&id, &val);
    }
    return 0;
};
int trace_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct val_t *valp;
    struct data_t data = {};
    u64 tsp = bpf_ktime_get_ns();
    valp = infotmp.lookup(&id);
    if (valp == 0) {
        // missed entry
        return 0;
    }
    bpf_probe_read(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)valp->fname);
    data.id = valp->id;
    data.ts = tsp / 1000;
    data.ret = PT_REGS_RC(ctx);
    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);
    return 0;
}
