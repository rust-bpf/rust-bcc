// Copyright 2019-2020 Twitter, Inc.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

use bcc::perf_event::{Event, HardwareEvent, SoftwareEvent};
use bcc::BccError;
use bcc::{PerfEvent, PerfEventArray, BPF};
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Arc;
use std::{thread, time};

// Both consants are arbitrary
const DEFAULT_SAMPLE_FREQ: u64 = 50; // Hertz
const DEFAULT_DURATION: u64 = 120; // Seconds

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("cpi")
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .short("d")
                .help("How long to run this trace for (in seconds)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cpu")
                .long("cpu")
                .help("Number of cpus in your system. Required")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let duration: u64 = matches
        .value_of("duration")
        .map(|v| v.parse().expect("Invalid duration"))
        .unwrap_or(DEFAULT_DURATION);

    let cpus: u32 = matches
        .value_of("cpu")
        .unwrap()
        .parse()
        .expect("cpu attribute is required");

    let code = format!(
        "{}\n{}",
        format!("#define NUM_CPU {}", cpus),
        include_str!("cpi.c").to_string()
    );

    let mut bpf = BPF::new(&code)?;
    PerfEventArray::new()
        .table("cycle_perf")
        .event(Event::Hardware(HardwareEvent::Instructions))
        .open(&mut bpf)?;
    PerfEventArray::new()
        .table("instr_perf")
        .event(Event::Hardware(HardwareEvent::RefCpuCycles))
        .open(&mut bpf)?;
    PerfEvent::new()
        .handler("do_count")
        .event(Event::Software(SoftwareEvent::CpuClock))
        .sample_frequency(Some(DEFAULT_SAMPLE_FREQ))
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
    let mut cycles = bpf.table("cycle");
    let cycles_map = to_map(&mut cycles);
    let mut instructions = bpf.table("instr");
    let instructions_map = to_map(&mut instructions);

    let mut total_instr = 0;
    let mut total_cycles = 0;
    println!(
        "{:<-4} {:>12} {:>12} {:>8}",
        "CPU", "CYCLES", "INSTR", "CPI"
    );
    for (key, value) in instructions_map.iter() {
        if *value == 0 {
            continue;
        }

        let cycles = cycles_map.get(&key).unwrap_or(&0);
        let cpi = *cycles as f32 / *value as f32;

        total_instr += *value;
        total_cycles += *cycles;

        println!("{:<-4} {:>12} {:>12} {:>8}", key, cycles, value, cpi);
    }
    println!(
        "\n{:<-12} {:<-12} {:<-12}",
        "TOTAL_CYCLES", "TOTAL_INSTR", "CPI"
    );
    println!(
        "{:<-12} {:<-12} {:<-12}",
        total_cycles,
        total_instr,
        total_cycles as f32 / total_instr as f32
    );

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
