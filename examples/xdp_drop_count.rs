use bcc::XDPMode::{XDP_FLAGS_HW_MODE, XDP_FLAGS_SKB_MODE};
use bcc::{BPFBuilder, BccError, XDP};
use byteorder::{LittleEndian, ReadBytesExt};
use clap::{App, Arg};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("xdpdropcount")
        .about("Drop incoming packets on XDP layer and count for which protocol type")
        .arg(
            Arg::with_name("device")
                .long("device")
                .short("d")
                .help("Device name to attach the XDP program")
                .default_value("eth0")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("hardware-offload-mode")
                .long("hw-offload-mode")
                .short("h")
                .help("Run the XDP program in hardware offload mode XDP_FLAGS_HW_MODE")
                .takes_value(true),
        )
        .get_matches();

    let hw_offload_mode_enabled = matches.is_present("hw-offload-mode");
    let mode = if hw_offload_mode_enabled {
        XDP_FLAGS_HW_MODE
    } else {
        XDP_FLAGS_SKB_MODE
    };

    let device = matches
        .value_of("device")
        .expect("safe since `device` has a default value");

    let code = include_str!("xdp_drop_count.c");
    let cflags = &["-w", "-DRETURNCODE=XDP_DROP", "-DCTXTYPE=xdp_md"];
    let builder = {
        let builder = BPFBuilder::new(code)?.cflags(cflags)?;
        if hw_offload_mode_enabled {
            builder.device(device)?
        } else {
            builder
        }
    };
    let mut bpf = builder.build()?;

    XDP::new()
        .handler("xdp_prog1")
        .device(device)
        .mode(mode)
        .attach(&mut bpf)?;

    let table = bpf.table("dropcnt")?;

    println!("Printing drops per IP protocol-number, hit CTRL+C to stop");
    let mut state = HashMap::new();
    while runnable.load(Ordering::SeqCst) {
        for entry in table.iter() {
            let protocol = Cursor::new(entry.key).read_u32::<LittleEndian>().unwrap();
            let current_count = Cursor::new(entry.value).read_u64::<LittleEndian>().unwrap();

            let delta = match state.entry(protocol) {
                Entry::Vacant(entry) => {
                    entry.insert(current_count);
                    current_count
                }
                Entry::Occupied(mut entry) => {
                    let delta = current_count - *entry.get();
                    entry.insert(current_count);
                    delta
                }
            };

            println!("{:?} => {:?}pkts/s", protocol, delta);
        }

        sleep(Duration::from_secs(1));
    }

    Ok(())
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    if let Err(err) = do_main(runnable) {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}
