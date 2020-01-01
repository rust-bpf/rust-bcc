use bcc::core::BPF;
extern crate chrono;
use chrono::Utc;
use clap::{App, Arg};
use failure::Error;

use core::sync::atomic::{AtomicBool, Ordering};
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::ptr;
use std::sync::Arc;

// A simple tool for tracing tcp retransmits.
//
// Based on: https://github.com/iovisor/bcc/blob/master/tools/tcpretrans.py

#[repr(C)]
struct ipv4_data_t {
    pid: u32,
    ip: u64,
    saddr: u32,
    daddr: u32,
    lport: u16,
    dport: u16,
    state: u64,
    type_: u64,
}

#[repr(C)]
struct ipv6_data_t {
    pid: u32,
    ip: u64,
    saddr: u128,
    daddr: u128,
    lport: u16,
    dport: u16,
    state: u64,
    type_: u64,
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let matches = App::new("biosnoop")
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

    let code = include_str!("tcpretrans.c");
    // compile the above BPF code!
    let mut bpf = BPF::new(&code)?;

    let trace_retransmit = bpf.load_kprobe("trace_retransmit")?;
    bpf.attach_kprobe("tcp_retransmit_skb", trace_retransmit)?;

    let table = bpf.table("ipv4_events");
    bpf.init_perf_map(table, print_ipv4_event)?;
    let table = bpf.table("ipv6_events");
    bpf.init_perf_map(table, print_ipv6_event)?;

    println!(
        "{:<-8} {:<-6} {:<-2} {:<-20} {:>-1} {:<-20} {:<-4}",
        "TIME", "PID", "IP", "LADDR:LPORT", "T", "RADDR:RPORT", "STATE"
    );
    let start = std::time::Instant::now();
    while runnable.load(Ordering::SeqCst) {
        bpf.perf_map_poll(200);
        if let Some(d) = duration {
            if std::time::Instant::now() - start >= d {
                break;
            }
        }
    }
    Ok(())
}

fn print_ipv4_event() -> Box<FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let event = parse_ipv4_struct(x);
        println!(
            "{:<-8} {:<-6} {:<-2} {:<-20} {:->1}> {:<-20} {:>-4}",
            Utc::now().format("%T"),
            event.pid,
            event.ip,
            format!("{}:{}", Ipv4Addr::from(event.saddr), event.lport),
            event.type_,
            format!("{}:{}", Ipv4Addr::from(event.daddr), event.dport),
            event.state,
        );
    })
}

fn print_ipv6_event() -> Box<FnMut(&[u8]) + Send> {
    Box::new(|x| {
        let event = parse_ipv6_struct(x);
        println!(
            "{:<-8} {:<-6} {:<-2}  {:<-20} {:->1}> {:<-20} {:>-4}",
            Utc::now().format("%T"),
            event.pid,
            event.ip,
            format!("{}:{}", Ipv6Addr::from(event.saddr), event.lport),
            event.type_,
            format!("{}:{}", Ipv6Addr::from(event.daddr), event.dport),
            event.state,
        );
    })
}

fn parse_ipv4_struct(x: &[u8]) -> ipv4_data_t {
    unsafe { ptr::read(x.as_ptr() as *const ipv4_data_t) }
}

fn parse_ipv6_struct(x: &[u8]) -> ipv6_data_t {
    unsafe { ptr::read(x.as_ptr() as *const ipv6_data_t) }
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
        eprintln!("{}", x.backtrace());
        std::process::exit(1);
    }
}
