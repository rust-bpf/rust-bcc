extern crate bcc;
extern crate byteorder;
extern crate failure;
extern crate libc;

use bcc::core::BPF;
use bcc::perf::init_perf_map;
use clap::{App, Arg};
use failure::Error;

use core::sync::atomic::{AtomicBool, Ordering};
use std::ptr;
use std::sync::Arc;

/*
 * Basic Rust clone of `opensnoop`, from the iovisor tools.
 * https://github.com/iovisor/bcc/blob/master/tools/opensnoop.py
 *
 * Prints out the filename + PID every time a file is opened
 */

/*
 * Define the struct the BPF code writes in Rust
 * This must match the struct in `opensnoop.c` exactly.
 * The important thing to understand about the code in `opensnoop.c` is that it creates structs of
 * type `data_t` and pushes them into a buffer where our Rust code can read them.
 */
#[repr(C)]
struct data_t {
    id: u64,
    ts: u64,
    ret: libc::c_int,
    comm: [u8; 16],   // TASK_COMM_LEN
    fname: [u8; 255], // NAME_MAX
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let matches = App::new("opensnoop")
        .about("Prints out filename + PID every time a file is opened")
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .value_name("Seconds")
                .help("The total duration to run this tool")
                .takes_value(true),
        )
        .get_matches();

    let duration: Option<std::time::Duration> = matches
        .value_of("duration")
        .map(|v| std::time::Duration::new(v.parse().expect("Invalid argument for duration"), 0));

    let code = include_str!("opensnoop.c");
    // compile the above BPF code!
    let mut module = BPF::new(code)?;
    // load + attach kprobes!
    let return_probe = module.load_kprobe("trace_return")?;
    let entry_probe = module.load_kprobe("trace_entry")?;
    module.attach_kprobe("do_sys_open", entry_probe)?;
    module.attach_kretprobe("do_sys_open", return_probe)?;
    // the "events" table is where the "open file" events get sent
    let table = module.table("events");
    // install a callback to print out file open events when they happen
    let mut perf_map = init_perf_map(table, perf_data_callback)?;
    // print a header
    println!("{:-7} {:-16} {}", "PID", "COMM", "FILENAME");
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

fn perf_data_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        // This callback
        let data = parse_struct(x);
        println!(
            "{:-7} {:-16} {}",
            data.id >> 32,
            get_string(&data.comm),
            get_string(&data.fname)
        );
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

    match do_main(runnable) {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}
