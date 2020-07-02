# rust-bcc

Idiomatic Rust bindings for the BPF compiler collection. The goal is to mimic the
Python BCC bindings in https://github.com/iovisor/bcc in a Rusty way.

The C bcc API (as exposed in `bcc-sys`) is very powerful, but it's fairly nontrivial to try to use
it by itself and manage all the resources it allocates safely.

This crate is currently experimental and has several things in it which are either unsafe or not
particularly idiomatic for Rust. Pull requests very much appreciated.

## Prerequisites

* bcc v0.4.0-v0.14.0

## Getting Started

The best way to learn about how to use this crate right now is to read the examples. The exciting
thing about these examples is that the Rust version isn't really more verbose than the Python
version. In some ways the Rust code is more legible because it's much more natural to work with C
data structure in Rust than it is in Python.

### Building

This library uses features to allow support for multiple versions of bcc. Depending on what version
of bcc you have installed, you may need to use a feature flag while building the examples in-order
to match the expected version of bcc with the version you have installed on your system.

### Examples

* [examples/strlen.rs](https://github.com/rust-bpf/rust-bcc/blob/master/examples/strlen.rs) uses a BPF hashmap to count frequencies of every string that `strlen` is run on. Port of [strlen_count.py](https://github.com/iovisor/bcc/blob/master/examples/tracing/strlen_count.py) to Rust.
* [examples/opensnoop.rs](https://github.com/rust-bpf/rust-bcc/blob/master/examples/opensnoop.rs) uses perf events to track every time a file is opened on the system. Port of [opensnoop.py](https://github.com/iovisor/bcc/blob/master/tools/opensnoop.py) to Rust.
* [examples/softirq.rs](https://github.com/rust-bpf/rust-bcc/blob/master/examples/softirqs.rs) uses
  kernel tracepoints to report time spent in softirq handlers. Port of [softirqs.py](https://github.com/iovisor/bcc/blob/master/tools/softirqs.py) to Rust.
