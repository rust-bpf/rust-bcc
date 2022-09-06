use bcc::SocketBuilder;
use bcc::BPF;
use clap::{App, Arg};
use std::io::Read;
use std::{thread, time};

const DEFAULT_DURATION: u64 = 120; // Seconds

pub fn recv_loop(mut socket_wrapper: bcc::SocketWrapper) {
    loop {
        let mut buf: [u8; 2048] = [0; 2048];
        match socket_wrapper.socket.read(&mut buf) {
            Ok(bytes) => println!(
                "read {} bytes on interface {}",
                bytes, &socket_wrapper.iface
            ),
            Err(err) => panic!("error whild reading from socket: {}", err),
        }
    }
}

fn main() {
    let matches = App::new("port_filter")
        .arg(
            Arg::with_name("ifaces")
                .long("ifaces")
                .short("i")
                .help("interface to listen to")
                .use_delimiter(true)
                .default_value("eth0"),
        )
        .arg(
            Arg::with_name("duration")
                .long("duration")
                .value_name("Seconds")
                .help("The total duration to run this tool")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .short("p")
                .help("The port to filter")
                .takes_value(true)
                .default_value("8080"),
        )
        .get_matches();

    if cfg!(any(
        feature = "v0_4_0",
        feature = "v0_5_0",
        feature = "v0_6_0",
        feature = "v0_6_1",
        feature = "v0_7_0",
        feature = "v0_8_0",
        feature = "v0_9_0",
        feature = "v0_10_0",
        feature = "v0_11_0",
        feature = "v0_12_0",
        feature = "v0_13_0",
        feature = "v0_14_0",
        feature = "v0_15_0",
        feature = "v0_16_0",
        feature = "v0_17_0",
        feature = "v0_18_0",
        feature = "v0_19_0",
        feature = "v0_20_0",
    )) {
        println!("not supported for bcc < 0.21.0");
        std::process::exit(2);
    }

    let ifaces = matches
        .values_of("ifaces")
        .unwrap()
        .map(String::from)
        .collect::<Vec<String>>();

    let duration: u64 = matches
        .value_of("duration")
        .map(|v| v.parse().expect("Invalid duration"))
        .unwrap_or(DEFAULT_DURATION);

    let port: &str = matches.value_of("port").unwrap();

    println!("Running for {} seconds", duration);

    let code = include_str!("port_filter.c").replace("{dst_port}", port);

    let mut bpf = BPF::new(&code).unwrap();

    let sockets = SocketBuilder::new()
        .handler("port_filter")
        .add_interfaces(&ifaces)
        .attach(&mut bpf)
        .unwrap();

    sockets
        .into_iter()
        .for_each(|socket_wrapper: bcc::SocketWrapper| {
            thread::spawn(|| recv_loop(socket_wrapper));
        });

    println!(
        "Attached sockets to interfaces {:?} and looking for tcp packets to port {}",
        &ifaces, port
    );

    let mut elapsed = 0;
    while elapsed < duration {
        thread::sleep(time::Duration::new(1, 0));
        elapsed += 1;
    }
}
