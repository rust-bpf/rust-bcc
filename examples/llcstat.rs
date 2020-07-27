use bcc::core::BPF;
use bcc::perf::{PerfHardwareConfig, PerfType};
use bcc::BccError;
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Arc;
use std::{mem, ptr, thread, time};

// Summarize cache reference and cache misses
//
// Based on https://github.com/iovisor/bcc/blob/master/tools/llcstat.py

const DEFAULT_SAMPLE_PERIOD: u64 = 100;
const DEFAULT_DURATION: u64 = 10;

#[repr(C)]
struct key_t {
    cpu: i32,
    pid: i32,
    name: Vec<u8>,
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
    bpf.attach_perf_event(
        "on_cache_miss",
        PerfType::Hardware as u32,
        PerfHardwareConfig::CacheMisses as u32,
        Some(sample_period),
        None,
        None,
        None,
        None,
    )?;
    bpf.attach_perf_event(
        "on_cache_ref",
        PerfType::Hardware as u32,
        PerfHardwareConfig::CacheReferences as u32,
        Some(sample_period),
        None,
        None,
        None,
        None,
    )?;

    println!("Running for {} seconds", duration);
    thread::sleep(time::Duration::new(duration, 0));

    // Count misses
    let mut miss_table = bpf.table("miss_count");
    let miss_map = to_map(&mut miss_table);
    let mut ref_table = bpf.table("ref_table");
    let ref_map = to_map(&mut ref_table);

    println!(
        "{:<-8} {:<-16} {:<-4} {:>-12} {:>-12} {:>6}",
        "PID", "NAME", "CPU", "REFERENCE", "MISS", "HIT%"
    );
    for (key, value) in ref_map.iter() {
        let miss = miss_map.get(key).unwrap_or(&0);
        let hit = if value > miss { value - miss } else { 0 };
        println!(
            "{:<-8} {:<-16} {:<-4} {:>-12} {:>-12} {:>6}%",
            key.1, // PID
            key.2, // NAME
            key.0, // CPU
            value,
            miss,
            hit as f64 / (*value) as f64 * 100.0
        );
    }

    Ok(())
}

fn to_map(table: &mut bcc::table::Table) -> HashMap<(i32, i32, String), u64> {
    let mut map = HashMap::new();

    for entry in table.iter() {
        let key = parse_struct(&entry.key);
        let value = parse_u64(entry.value);
        let name = parse_string(&key.name);

        map.insert((key.cpu, key.pid, name), value);
    }

    map
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

fn parse_string(x: &[u8]) -> String {
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

    if let Err(x) = do_main() {
        eprintln!("Error: {}", x);
        std::process::exit(1);
    }
}
