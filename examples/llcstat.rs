use bcc::core::BPF;
use bcc::perf::{PerfType, PerfHardwareConfig};
use bcc::BccError;
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time, ptr, mem};

const DEFAULT_SAMPLE_PERIOD: u64 = 100;
const DEFAULT_DURATION: u64 = 10;

#[repr(C)]
struct key_t {
    cpu: i32,
    pid: i32,
    name: Vec<char>,
}

fn do_main() -> Result<(), BccError> {
    let matches = App::new("cpudist")
        .arg(
            Arg::with_name("sample_period")
                .long("sample_period")
                .short("c")
                .help("Sample one in this many number of cache reference / miss events")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .short("d")
                .help("Duration in seconds to run")
                .takes_value(true),
        )
        .get_matches();

    let sample_period: u64 = matches
        .value_of("sample_period")
        .map(|v| v.parse().expect("Invalid sample period"))
        .unwrap_or(DEFAULT_SAMPLE_PERIOD);

    let duration: u64 = matches
        .value_of("duration")
        .map(|v| v.parse().expect("Invalid duration"))
        .unwrap_or(DEFAULT_DURATION);
        
    let code = include_str!("llcstat.c").to_string();
    let mut bpf = BPF::new(&code)?;
    bpf.attach_perf_event("on_cache_miss", PerfType::Hardware as u32, PerfHardwareConfig::CacheMisses as u32 , Some(sample_period), None, None, None, None)?;
    bpf.attach_perf_event("on_cache_ref", PerfType::Hardware as u32, PerfHardwareConfig::CacheReferences as u32 , Some(sample_period), None, None, None, None)?;

    println!("Running for {} seconds", duration);
    thread::sleep(time::Duration::new(duration, 0));

    // Count misses
    let miss_table = bpf.table("miss_count");
    for entry in miss_table.iter() {
        let key = parse_struct(&entry.key);
        let value = parse_u64(entry.value);

        
    }


    Ok(())
}

fn parse_u64(x: Vec<u8>) -> u64 {
    let mut v = [0_u8; 8];
    for i in 0..8 {
        v[i] = *x.get(i).unwrap_or(&0);
    }

    unsafe { mem::transmute(v) }
}

fn parse_struct(x: &[u8]) -> key_t {
    unsafe { ptr::read(x.as_ptr() as *const key_t) }
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    if let Err(x) = do_main() {
        eprintln!("Error: {}", x);
        std::process::exit(1);
    }
}