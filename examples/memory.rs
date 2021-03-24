// Copyright 2021 Twitter, Inc.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

use bcc::perf_event::{Event, SoftwareEvent};
use bcc::BccError;
use bcc::{PerfEvent, PerfEventArray, BPF};
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Arc;
use std::{thread, time};

// Both consants are arbitrary
const DEFAULT_SAMPLE_FREQ: u64 = 99; // Hertz
const DEFAULT_DURATION: u64 = 10; // Seconds

#[cfg(any(
    feature = "v0_4_0",
    feature = "v0_5_0",
    feature = "v0_6_0",
    feature = "v0_6_1"
))]
fn do_main(_runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    panic!("requires bcc >= 0.7.0");
}

#[cfg(not(any(
    feature = "v0_4_0",
    feature = "v0_5_0",
    feature = "v0_6_0",
    feature = "v0_6_1"
)))]
fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("memory")
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .short("d")
                .help("How long to run this trace for (in seconds)")
                .takes_value(true),
        )
        .get_matches();

    let duration: u64 = matches
        .value_of("duration")
        .map(|v| v.parse().expect("Invalid duration"))
        .unwrap_or(DEFAULT_DURATION);

    let cpus = bcc::cpuonline::get()?.len() as u32;

    let code = format!(
        "{}\n{}",
        format!("#define NUM_CPU {}", cpus),
        include_str!("memory.c").to_string()
    );

    let mut bpf = BPF::new(&code)?;
    PerfEventArray::new()
        .table("loads_perf")
        .event(Event::Raw {
            event_code: 0x0E,
            umask: 0x0F,
            counter_mask: 0x00,
            invert: false,
            any_thread: false,
            edge_detect: false,
        })
        .attach(&mut bpf)?;

    println!("Running for {} seconds", duration);

    let mut elapsed = 0;
    while runnable.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::new(1, 0));

        if elapsed == duration {
            break;
        }
        elapsed += 1;
    }

    // Count misses
    let mut loads = bpf.table("loads")?;
    let loads_map = to_map(&mut loads);

    let mut total_loads = 0;

    for i in 0..cpus {
        let loads = loads_map.get(&i).unwrap_or(&0);

        total_loads += *loads;
    }

    println!("{:<-12}", "TOTAL_LOADS");
    println!("{:<-12}", total_loads,);

    Ok(())
}

fn to_map(table: &mut bcc::table::Table) -> HashMap<u32, u64> {
    let mut map = HashMap::new();

    for entry in table.iter() {
        let key = parse_u32(entry.key);
        let value = parse_u64(entry.value);

        map.insert(key, value);
    }

    map
}

fn parse_u32(x: Vec<u8>) -> u32 {
    let mut v = [0_u8; 4];
    for (i, byte) in v.iter_mut().enumerate() {
        *byte = *x.get(i).unwrap_or(&0);
    }

    u32::from_ne_bytes(v)
}

fn parse_u64(x: Vec<u8>) -> u64 {
    let mut v = [0_u8; 8];
    for (i, byte) in v.iter_mut().enumerate() {
        *byte = *x.get(i).unwrap_or(&0);
    }

    u64::from_ne_bytes(v)
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
