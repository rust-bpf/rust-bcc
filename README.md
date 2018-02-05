# rust-bcc

Crate with user-friendly rust bindings for the bpf compiler collection. The goal is to more or less
mimic the Python bindings in https://github.com/iovisor/bcc in a way that's idiomatic for Rust.

This is currently a partial port of gobpf: https://github.com/iovisor/gobpf/.

This crate is currently experimental. Pull requests very much appreciated.

### Examples

The best way to learn about how to use this crate right now is to read the examples. The exciting
thing about these examples is that the Rust version isn't really more verbose than the Python
version. In some ways the Rust code is more legible because it's much more natural to work with C
data structure in Rust than it is in Python.

* [examples/strlen.rs](https://github.com/jvns/rust-bcc/blob/master/examples/strlen.rs) uses a BPF hashmap to count frequences of every string that `strlen` is run on. Port of [strlen_count.py](https://github.com/iovisor/bcc/blob/master/examples/tracing/strlen_count.py) to Rust.
* [examples/opensnoop.rs](https://github.com/jvns/rust-bcc/blob/master/examples/opensnoop.rs) uses perf events to track every time a file is opened on the system. Port of [opensnoop.py](https://github.com/iovisor/bcc/blob/master/examples/tracing/opensnoop.py) to Rust.
