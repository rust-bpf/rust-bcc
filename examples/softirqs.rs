use bcc::core::BPF;
use clap::{App, Arg};
use failure::Error;

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{fmt, mem, ptr, thread, time};

// A simple tool for reporting on time spent in softirq handlers
//
// Based on: https://github.com/iovisor/bcc/blob/master/tools/softirqs.py

#[repr(C)]
struct irq_key_t {
    vec: u32,
    slot: u64,
}

#[allow(non_camel_case_types)]
enum SoftIRQ {
    HI,
    TIMER,
    NET_TX,
    NET_RX,
    BLOCK,
    IRQ_POLL,
    TASKLET,
    SCHED,
    HRTIMER,
    RCU,
    UNKNOWN,
}

impl From<u32> for SoftIRQ {
    fn from(val: u32) -> Self {
        match val {
            0 => SoftIRQ::HI,
            1 => SoftIRQ::TIMER,
            2 => SoftIRQ::NET_TX,
            3 => SoftIRQ::NET_RX,
            4 => SoftIRQ::BLOCK,
            5 => SoftIRQ::IRQ_POLL,
            6 => SoftIRQ::TASKLET,
            7 => SoftIRQ::SCHED,
            8 => SoftIRQ::HRTIMER,
            9 => SoftIRQ::RCU,
            _ => SoftIRQ::UNKNOWN,
        }
    }
}

impl SoftIRQ {
    fn name(&self) -> String {
        match *self {
            SoftIRQ::HI => "HI".to_owned(),
            SoftIRQ::TIMER => "TIMER".to_owned(),
            SoftIRQ::NET_TX => "NET_TX".to_owned(),
            SoftIRQ::NET_RX => "NET_RX".to_owned(),
            SoftIRQ::BLOCK => "BLOCK".to_owned(),
            SoftIRQ::IRQ_POLL => "IRQ_POLL".to_owned(),
            SoftIRQ::TASKLET => "TASKLET".to_owned(),
            SoftIRQ::SCHED => "SCHED".to_owned(),
            SoftIRQ::HRTIMER => "HRTIMER".to_owned(),
            SoftIRQ::RCU => "RCU".to_owned(),
            SoftIRQ::UNKNOWN => "UNKNOWN".to_owned(),
        }
    }
}

impl fmt::Display for SoftIRQ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let matches = App::new("softirqs")
        .about("Reports time spent in IRQ Handlers")
        .arg(
            Arg::with_name("interval")
                .long("interval")
                .value_name("Seconds")
                .help("Integration window duration and period for stats output")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("windows")
                .long("windows")
                .value_name("Count")
                .help("The number of intervals before exit")
                .takes_value(true),
        )
        .get_matches();

    let interval: usize = matches
        .value_of("interval")
        .unwrap_or("1")
        .parse()
        .expect("Invalid argument for interval");
    let windows: Option<usize> = matches
        .value_of("windows")
        .map(|v| v.parse().expect("Invalid argument for windows"));

    let code = if cfg!(any(
        feature = "v0_4_0",
        feature = "v0_5_0",
        feature = "v0_6_0",
        feature = "v0_6_1",
    )) {
        include_str!("softirqs_0_4_0.c")
    } else {
        include_str!("softirqs_0_7_0.c")
    };

    // compile the above BPF code!
    let mut module = BPF::new(code)?;

    // load + attach tracepoints!
    let softirq_entry = module.load_tracepoint("softirq_entry")?;
    let softirq_exit = module.load_tracepoint("softirq_exit")?;
    
    module.attach_tracepoint("irq", "softirq_entry", softirq_entry)?;
    module.attach_tracepoint("irq", "softirq_exit", softirq_exit)?;
    
    let table = module.table("dist");
    let mut window = 0;

    while runnable.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::new(interval as u64, 0));
        println!("======");
        for entry in table.iter() {
            let data = parse_struct(&entry.key);
            let value = entry.value;
            let id = data.vec;

            let mut v = [0_u8; 8];
            for i in 0..8 {
                v[i] = *value.get(i).unwrap_or(&0);
            }
            let time: u64 = unsafe { mem::transmute(v) };

            if time > 0 {
                let softirq = SoftIRQ::from(id);
                println!("softirq: {} time (ns): {}", softirq, time);
            }
        }
        if let Some(windows) = windows {
            window += 1;
            if window >= windows {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn parse_struct(x: &[u8]) -> irq_key_t {
    unsafe { ptr::read(x.as_ptr() as *const irq_key_t) }
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
