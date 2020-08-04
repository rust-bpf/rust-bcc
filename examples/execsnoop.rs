extern crate bcc;
extern crate byteorder;
extern crate libc;
extern crate multimap;

use bcc::perf_event::init_perf_map;
use bcc::BccError;
use bcc::{Kprobe, Kretprobe, BPF};
use clap::{App, Arg};
use core::sync::atomic::{AtomicBool, Ordering};

use std::ptr;
use std::sync::Arc;
use std::sync::Mutex;

use multimap::MultiMap;

/*
    Snoop on execve() system calls
*/
#[repr(C)]
#[allow(dead_code)]
enum event_type {
    EventArg,
    EventRet,
}

#[repr(C)]
struct data_t {
    pid: u32,          // process-id
    ppid: u32,         // parent process-id
    uid: u32,          // user-id
    comm: [u8; 16],    // command name
    etype: event_type, // event type
    argv: [u8; 128],   // arguments vector
    retval: u8,        // returned value
    maxarg: u32,       // maximum argument length
    argmap_ptr: u64,   // pointer to user-land's argmap
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("execsnoop")
        .about("Prints out new processes created via execve() system calls.")
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .value_name("seconds")
                .help("The total duration to run this tool")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("maxarg")
                .long("maxarg")
                .value_name("max arguments length")
                .help("The maximum command-line arguments length")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("uid")
                .long("uid")
                .value_name("user id")
                .help("Only print system calls running under the given user")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .value_name("process id")
                .help("Only print system calls from given process")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ppid")
                .long("ppid")
                .value_name("parent process id")
                .help("Only print system calls from process(es) with given parent process")
                .takes_value(true),
        )
        .get_matches();

    let duration: Option<std::time::Duration> = matches
        .value_of("duration")
        .map(|v| std::time::Duration::new(v.parse().expect("Invalid argument for duration"), 0));
    let maxarg = matches.value_of("maxarg").unwrap_or("20");
    let userid = matches
        .value_of("uid")
        .map(|v| v.parse::<u32>().expect("Invalid user id"));
    let pid: Option<u32> = matches
        .value_of("pid")
        .map(|v| v.parse().expect("Invalid process id"));
    let ppid: Option<u32> = matches
        .value_of("ppid")
        .map(|v| v.parse().expect("Invalid parent process id"));
    // modify bpf program source code
    let code = include_str!("execsnoop.c");
    // replace variables with runtime information
    let mut c = code.replace("MAXARG", maxarg);
    if let Some(uid) = userid {
        let uid_filter = format!("if (uid != {}) {{ return 0; }}", uid);
        c = c.replace("UID_FILTER", &uid_filter);
    } else {
        c = c.replace("UID_FILTER", "");
    }
    c = c.replace("CGROUPSET", "0"); // hard-coded (non-implemented)
    if let Some(p) = pid {
        c = c.replace("PIDSET", "1");
        c = c.replace("$PID", &p.to_string());
    }
    if let Some(p) = ppid {
        c = c.replace("PPIDSET", "1");
        c = c.replace("$PPID", &p.to_string());
    }

    // initialize "shared" multimap on the heap (experimental)
    let arg_map: Arc<Mutex<MultiMap<u32, String>>> = Arc::new(Mutex::new(MultiMap::new()));
    let arg_map_c = arg_map.clone();
    let argmap_sptr = format!("{:?}", &&arg_map_c as *const _);
    c = c.replace("ARGMAP_PTR", &argmap_sptr);

    // compile the above BPF code
    let mut module = BPF::new(&c)?;
    // load and attach kprobes
    let execve_funcname = module.get_syscall_fnname("execve");
    Kprobe::new()
        .handler("syscall_execve")
        .function(&execve_funcname)
        .attach(&mut module)?;
    Kretprobe::new()
        .handler("ret_sys_execve")
        .function(&execve_funcname)
        .attach(&mut module)?;

    // the "events" table is where the "execve" events get sent
    let table = module.table("events");
    // install a callback to print out file events when they happen
    let mut perf_map = init_perf_map(table, perf_data_callback)?;

    // print a header
    let marg = maxarg.parse::<usize>().unwrap_or(20);
    println!(
        "{:-7} {:>7} {:>7}  {:<16} {:>4}  {:width$}",
        "UID",
        "PID",
        "PPID",
        "CMD",
        "RET",
        "ARG",
        width = marg
    );
    let start = std::time::Instant::now();
    // this `.poll()` loop is what makes our callback get called
    while runnable.load(Ordering::SeqCst) {
        perf_map.poll(200);
        if let Some(d) = duration {
            if std::time::Instant::now() - start >= d {
                break;
            }
        }
    }

    Ok(())
}

// Performance Data Callback Function
fn perf_data_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    let skip = false;

    Box::new(move |x| {
        // initialize command-line argument text String
        let mut argv_txt = String::new();

        // parse data structure of type data_t
        let data = parse_struct(x);

        // read stored argmap raw pointer
        let argmap_ptr = data.argmap_ptr as *const u64;
        // read data structure from raw pointer
        let m_argmap: &Arc<Mutex<MultiMap<u32, String>>> =
            unsafe { ptr::read(argmap_ptr as *mut &Arc<Mutex<MultiMap<u32, String>>>) };
        let m_argmap_c = m_argmap.clone();
        let mut arg_map = m_argmap_c.lock().unwrap();

        match data.etype {
            event_type::EventArg => {
                arg_map.insert(data.pid, get_string(&data.argv));
            }
            event_type::EventRet => {
                match arg_map.get_vec(&data.pid) {
                    Some(v) => {
                        argv_txt = v.join(" ");
                    }
                    None => {}
                }
                if !skip {
                    println!(
                        "{:<7} {:>7} {:>7}  {:<16} {:>4}  {:width$}",
                        data.uid,
                        data.pid,
                        data.ppid,
                        get_string(&data.comm),
                        data.retval,
                        argv_txt,
                        width = data.maxarg as usize,
                    );
                }
            }
        }
    })
}

fn parse_struct(x: &[u8]) -> data_t {
    unsafe { ptr::read(x.as_ptr() as *const data_t) }
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    if let Err(x) = do_main(runnable) {
        eprintln!("Error: {}", x);
        std::process::exit(1);
    }
}

