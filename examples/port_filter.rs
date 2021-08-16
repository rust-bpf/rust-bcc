use bcc::Socket;
use bcc::BPF;
use clap::{App, Arg};
use std::{thread, time};

const DEFAULT_DURATION: u64 = 120; // Seconds

pub fn configure_socket(socket_fd: i32) {
    let mut flags = unsafe { libc::fcntl(socket_fd, libc::F_GETFL) };
    flags = flags & !libc::O_NONBLOCK;
    unsafe {
        libc::fcntl(socket_fd, libc::F_SETFL, flags);
    }
}

pub fn recv_loop(iface: String, fd: i32) {
    loop {
        let mut buf: [u8; 2048] = [0; 2048];
        unsafe {
            libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 2048);
        }
        println!("Packet on interface {}", &iface)
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
        .get_matches();

    let ifaces = matches
        .values_of("ifaces")
        .unwrap()
        .map(String::from)
        .collect::<Vec<_>>();

    let duration: u64 = matches
        .value_of("duration")
        .map(|v| v.parse().expect("Invalid duration"))
        .unwrap_or(DEFAULT_DURATION);

    println!("Running for {} seconds", duration);

    let code = include_str!("port_filter.c");
    let mut bpf = BPF::new(&code).unwrap();

    Socket::new()
        .handler("port_filter")
        .ifaces(&ifaces)
        .attach(&mut bpf)
        .unwrap();

    println!("Attached sockets to interfaces {:?}", &ifaces);

    // configure all sockets
    bpf.sockets.iter().for_each(|(_, fd)| configure_socket(*fd));

    bpf.sockets
        .iter()
        .map(|(iface, fd)| (iface.clone(), fd.clone()))
        .for_each(|(iface, fd)| {
            thread::spawn(move || {
                recv_loop(iface, fd);
            });
        });

    let mut elapsed = 0;
    while elapsed < duration {
        thread::sleep(time::Duration::new(1, 0));
        elapsed += 1;
        println!("{}", elapsed);
    }
}
