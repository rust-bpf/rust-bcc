extern crate bcc;
extern crate byteorder;
extern crate libc;
extern crate failure;

use bcc::core::BPF;
use bcc::perf::init_perf_map;
use failure::Error;

/*
 * Rust clone of `opensnoop`, from the iovisor tools.
 *
 * Current status: quite buggy, seems to get all the `open` events but half the time prints a
 * corrupted filename.
 */

// Define the struct the BPF code writes in Rust
#[repr(C)]
struct data_t {
    id: u64,
    ts: u64,
    cpu: libc::c_int,
    ret: libc::c_int,
    comm: [u8; 16], // TASK_COMM_LEN
    fname: [u8; 255], // NAME_MAX
}

fn do_main() -> Result<(), Error> {
    // BPF code here copied from
    // https://github.com/iovisor/bcc/blob/master/tools/opensnoop.py
    let code = "
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
    int cpu;
    int ret;
    char comm[TASK_COMM_LEN];
    char fname[255];
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
    data.cpu = bpf_get_smp_processor_id();
    events.perf_submit(ctx, &data, sizeof(data));
    infotmp.delete(&id);
    return 0;
}
    ";
    let mut module = BPF::new(code)?;
    let return_probe = module.load_kprobe("trace_return")?;
    let entry_probe = module.load_kprobe("trace_entry")?;
    module.attach_kprobe("do_sys_open", entry_probe)?;
    module.attach_kretprobe("do_sys_open", return_probe)?;
    let table = module.table("events");
    let mut map = init_perf_map(table, closure)?;
    println!("{:-5} {:-7} {:-16} {}", "CPU", "RET", "COMM", "FILENAME");
    loop {
        map.poll(1000);
    }
}

fn closure() -> Box<Fn(Vec<u8>)> {
    Box::new(|x| {
        let mut data = unsafe {std::mem::uninitialized::<data_t>()};
        unsafe {libc::memcpy(&mut data as *mut data_t as *mut libc::c_void, x.as_slice().as_ptr() as *const u8 as *const libc::c_void, std::mem::size_of::<data_t>())};
        println!("{:-5} {:-7} {:-16} {}", data.cpu, data.ret, get_string(&data.comm), get_string(&data.fname));
    })
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}


fn main() {
    match do_main() {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}
