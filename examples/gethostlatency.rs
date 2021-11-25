use bcc::perf_event::PerfMapBuilder;
use bcc::BccError;
use bcc::{Uprobe, Uretprobe, BPF};
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{fmt, ptr};

/*
 * Basic Rust clone of `gethostlatency`, from the iovisor tools.
 * https://github.com/iovisor/bcc/blob/master/tools/gethostlatency.py
 *
 * Prints the latency for getaddrinfo/gethostbyname(3) calls, which are a common part of DNS lookups.
 */

/*
 * Define the struct the BPF code writes in Rust
 * This must match the struct in `gethostlatency.c` exactly.
 * The important thing to understand about the code in `gethostlatency.c` is that it creates structs of
 * type `latency_event_t` and pushes them into a buffer where our Rust code can read them.
 */
#[repr(C)]
struct latency_event_t {
    pid: u32,
    delta: u64,
    comm: [u8; 16], // TASK_COMM_LEN
    host: [u8; 80],
}

impl fmt::Display for latency_event_t {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let now = time::OffsetDateTime::now_utc();
        let date = now.date();
        let time = now.time();
        let dt_string = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            date.year(),
            date.month() as u8,
            date.day(),
            time.hour(),
            time.minute(),
            time.second(),
            time.nanosecond(),
        );
        write!(
            f,
            "{:<9} {:<6} {:<16} {:>10.2} {}",
            dt_string,
            self.pid,
            get_string(&self.comm),
            (self.delta as f32) / 1e6,
            get_string(&self.host)
        )
    }
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("gethostlatency")
        .about("Prints the latency for getaddrinfo/gethostbyname(2) calls")
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .short("p")
                .help("Only trace calls from this PID")
                .takes_value(true),
        )
        .get_matches();

    let pid: Option<i32> = matches
        .value_of("pid")
        .map(|v| v.parse::<i32>().expect("Invalid argument for PID"));

    // attach entry and return probes for common host lookup functions
    let libc_so_path = "/lib/x86_64-linux-gnu/libc.so.6";
    let code = include_str!("gethostlatency.c");
    let mut module = BPF::new(code)?;
    for symbol in &["getaddrinfo", "gethostbyname", "gethostbyname2"] {
        Uprobe::new()
            .handler("do_entry")
            .binary(libc_so_path)
            .symbol(symbol)
            .pid(pid)
            .attach(&mut module)?;
        Uretprobe::new()
            .handler("do_return")
            .binary(libc_so_path)
            .symbol(symbol)
            .pid(pid)
            .attach(&mut module)?;
    }

    // the "events" table is where the "function was called" events get sent
    let table = module.table("events")?;
    // install a callback to print out latency events when they happen
    let mut perf_map = PerfMapBuilder::new(table, perf_data_callback).build()?;
    // print a header
    println!(
        "{:<9} {:<6} {:<16} {:>10} {}",
        "TIME", "PID", "COMM", "LATms", "HOST"
    );
    // this `.poll()` loop is what makes our callback get called
    while runnable.load(Ordering::SeqCst) {
        perf_map.poll(200);
    }
    Ok(())
}

fn perf_data_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        println!("{}", parse_struct(x));
    })
}

fn parse_struct(x: &[u8]) -> latency_event_t {
    unsafe { ptr::read_unaligned(x.as_ptr() as *const latency_event_t) }
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
            std::process::exit(1);
        }
        _ => {}
    }
}
