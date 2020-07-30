use bcc::{PerfEvent};
use bcc::BPF;
use bcc::perf_event::{Event, HardwareEvent};
use bcc::BccError;
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Arc;
use std::{mem, ptr, str, thread, time};

// Summarize cache reference and cache misses
//
// Based on https://github.com/iovisor/bcc/blob/master/tools/llcstat.py

const DEFAULT_SAMPLE_PERIOD: u64 = 100; // Events (Aka every 100 events)
const DEFAULT_DURATION: u64 = 10; // Seconds

#[repr(C)]
struct key_t {
    cpu: i32,
    pid: i32,
    name: [u8; 16],
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
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
    PerfEvent::new()
        .name("on_cache_miss")
        .event(Event::Hardware(HardwareEvent::CacheMisses))
        .sample_period(Some(sample_period))
        .attach(&mut bpf)?;
    PerfEvent::new()
        .name("on_cache_ref")
        .event(Event::Hardware(HardwareEvent::CacheReferences))
        .sample_period(Some(sample_period))
        .attach(&mut bpf)?;

    println!("Running for {} seconds", duration);

    let mut elapsed = 0;
    while runnable.load(Ordering::SeqCst) {
        if elapsed == duration {
            break;
        }
        thread::sleep(time::Duration::new(1, 0));
        elapsed += 1;
    }

    // Count misses
    let mut miss_table = bpf.table("miss_count");
    let miss_map = to_map(&mut miss_table);
    let mut ref_table = bpf.table("ref_count");
    let ref_map = to_map(&mut ref_table);

    let mut total_hit = 0;
    let mut total_miss = 0;

    println!(
        "{:<-8} {:<-16} {:<-4} {:>-12} {:>-12} {:>6}",
        "PID", "NAME", "CPU", "REFERENCE", "MISS", "HIT%"
    );
    for (key, value) in ref_map.iter() {
        let miss = miss_map.get(key).unwrap_or(&0);
        let hit = if value > miss { value - miss } else { 0 };
        total_hit += hit;
        total_miss += miss;
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

    println!("Total hit: {}\nTotal miss: {}", total_hit, total_miss);

    Ok(())
}

fn to_map(table: &mut bcc::table::Table) -> HashMap<(i32, i32, String), u64> {
    let mut map = HashMap::new();

    for entry in table.iter() {
        let key = parse_struct(&entry.key);
        let value = parse_u64(entry.value);
        let name = str::from_utf8(&key.name).unwrap_or("").to_string();

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
