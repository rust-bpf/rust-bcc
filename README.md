# rust-bcc

Crate with user-friendly rust bindings for the bpf compiler collection. The goal is to more or less
mimic the Python bindings in https://github.com/iovisor/bcc in a way that's idiomatic for Rust.

This is currently a partial port of gobpf: https://github.com/iovisor/gobpf/.

### Examples

* [examples/strlen.rs](https://github.com/jvns/rust-bcc/blob/master/examples/strlen.rs) uses a BPF hashmap to count frequences of every string that `strlen` is run on. Port of [strlen_count.py](https://github.com/iovisor/bcc/blob/master/examples/tracing/strlen_count.py) to Rust.
* [examples/opensnoop.rs](https://github.com/jvns/rust-bcc/blob/master/examples/opensnoop.rs) uses perf events to track every time a file is opened on the system. Port of [opensnoop.py](https://github.com/iovisor/bcc/blob/master/examples/tracing/opensnoop.py) to Rust.
