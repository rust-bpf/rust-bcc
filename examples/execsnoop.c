#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE 128
enum event_type {
    EVENT_ARG,
    EVENT_RET,
};

struct data_t {
    u32 pid;  // PID as in the userspace term (i.e. task->tgid in kernel)
    u32 ppid; // Parent PID as in the userspace term (i.e task->real_parent->tgid in kernel)
    u32 uid; // User ID
    char comm[TASK_COMM_LEN]; // Program name
    enum event_type type; // Event type enum
    char argv[ARGSIZE]; // Argument vector array
    int retval; // System call return value
    u32 maxarg; // Maximum command-line argument's length
    u64 argmap_ptr; // Pointer to userland's arguments map
};

#if CGROUPSET
BPF_TABLE_PINNED("hash", u64, u64, cgroupset, 1024, "CGROUPPATH");
#endif
BPF_PERF_OUTPUT(events);

static int __submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    bpf_probe_read_user(data->argv, sizeof(data->argv), ptr);
    events.perf_submit(ctx, data, sizeof(struct data_t));
    return 1;
}

static int submit_arg(struct pt_regs *ctx, void *ptr, struct data_t *data)
{
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), ptr);
    if (argp) {
        return __submit_arg(ctx, (void *)(argp), data);
    }
    return 0;
}

int syscall_execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    UID_FILTER
#if CGROUPSET
    u64 cgroupid = bpf_get_current_cgroup_id();
    if (cgroupset.lookup(&cgroupid) == NULL) {
      return 0;
    }
#endif
    // create data here and pass to submit_arg to save stack space (#555)
    struct data_t data = {};
    struct task_struct *task;
    // store pointer to initialized arguments map in userland
    data.argmap_ptr = ARGMAP_PTR;
    data.pid = bpf_get_current_pid_tgid() >> 32;
#if PIDSET
    if ($PID != data.pid) {
        return 0;
    }
#endif
    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;
#if PPIDSET
    if ($PPID != data.ppid) {
        return 0;
    }
#endif
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_ARG;
    // set max argument width
    data.maxarg = MAXARG;
    __submit_arg(ctx, (void *)filename, &data);
    // skip first arg, as we submitted filename
    #pragma unroll
    for (int i = 1; i < MAXARG; i++) {
        if (submit_arg(ctx, (void *)&__argv[i], &data) == 0)
             goto out;
    }
    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, &data);
out:
    return 0;
}

int ret_sys_execve(struct pt_regs *ctx)
{
#if CGROUPSET
    u64 cgroupid = bpf_get_current_cgroup_id();
    if (cgroupset.lookup(&cgroupid) == NULL) {
      return 0;
    }
#endif
    struct data_t data = {};
    struct task_struct *task;
    // store pointer to initialized arguments map in userland
    data.argmap_ptr = ARGMAP_PTR;
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    data.uid = uid;
    UID_FILTER
    data.pid = bpf_get_current_pid_tgid() >> 32;
#if PIDSET
    if ($PID != data.pid) {
        return 0;
    }
#endif
    task = (struct task_struct *)bpf_get_current_task();
    // Some kernels, like Ubuntu 4.13.0-generic, return 0
    // as the real_parent->tgid.
    // We use the get_ppid function as a fallback in those cases. (#1883)
    data.ppid = task->real_parent->tgid;
#if PPIDSET
    if ($PPID != data.ppid) {
        return 0;
    }
#endif
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.type = EVENT_RET;
    data.retval = PT_REGS_RC(ctx);
    // set max argument width
    data.maxarg = MAXARG;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
