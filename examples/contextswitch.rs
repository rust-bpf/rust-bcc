// Copyright 2019-2020 Twitter, Inc.
// Licensed under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

use bcc::core::BPF;
use bcc::perf::{EventType, SoftwareEvent};
use bcc::BccError;
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{ptr, thread, time};

// Both consants are arbitrary
const DEFAULT_SAMPLE_FREQ: u64 = 50; // Hertz
const DEFAULT_DURATION: u64 = 120; // Seconds

#[repr(C)]
struct key_t {
    cpu: i32,
    pid: i32,
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("contextswitch")
        .arg(
            Arg::with_name("sample_frequency")
                .long("frequency")
                .short("F")
                .help("Sample frequency, Hertz")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sample_period")
                .long("sample_period")
                .short("P")
                .help("Sample period, every P events")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .short("d")
                .help("How long to run this trace for (in seconds)")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("pid")
                .long("pid")
                .help("Only track this PID")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tid")
                .long("tid")
                .help("Only track this TID")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("percpu")
                .long("percpu")
                .help("Display context switches per cpu")
                .takes_value(false),
        )
        .get_matches();

    let mut sample_frequency: Option<u64> = matches
        .value_of("sample_frequency")
        .map(|v| v.parse().expect("Invalid sample frequency"));

    let sample_period: Option<u64> = matches
        .value_of("sample_period")
        .map(|v| v.parse().expect("Invalid sample period"));

    if sample_frequency.is_none() && sample_period.is_none() {
        sample_frequency = Some(DEFAULT_SAMPLE_FREQ);
    }

    let duration: u64 = matches
        .value_of("duration")
        .map(|v| v.parse().expect("Invalid duration"))
        .unwrap_or(DEFAULT_DURATION);

    let mut code = include_str!("contextswitch.c").to_string();
    code = match matches.value_of("pid") {
        Some(pid) => code.replace("##PID_FILTER##", &format!("pid != {}", pid)),
        _ => code.replace("##PID_FILTER##", "0"),
    };
    code = match matches.value_of("tgid") {
        Some(tgid) => code.replace("##TGID_FILTER##", &format!("tgid != {}", tgid)),
        _ => code.replace("##TGID_FILTER##", "0"),
    };
    if matches.is_present("percpu") {
        code = format!("{}\n{}", "#define PERCPU", code);
    }

    let mut bpf = BPF::new(&code)?;
    bpf.attach_perf_event(
        "do_count",
        EventType::Software as u32,
        SoftwareEvent::ContextSwitches as u32,
        sample_period,
        sample_frequency,
        None,
        None,
        None,
    )?;

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
    let count_table = bpf.table("count");

    if matches.is_present("percpu") {
        println!("{:<-8} {:<-4} {:>12}", "PID", "CPU", "COUNT");
        for entry in count_table.iter() {
            let key = parse_struct(&entry.key);
            let value = parse_u64(entry.value);

            println!("{:<-8} {:<-4} {:>12}", key.pid, key.cpu, value);
        }
    } else {
        println!("{:<-8} {:>12}", "PID", "COUNT");
        for entry in count_table.iter() {
            let key = parse_u32(entry.key);
            let value = parse_u64(entry.value);

            println!("{:<-8} {:>12}", key, value);
        }
    }

    Ok(())
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
