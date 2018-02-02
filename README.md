# rust-bcc

Crate with user-friendly rust bindings for the bpf compiler collection. The goal is to more or less
mimic the Python bindings in https://github.com/iovisor/bcc, instead of the C API, but in a way
that's idiomatic for Rust.

This is currently a partial port of gobpf: https://github.com/iovisor/gobpf/.

### Examples

There's an example of how to use this crate in [examples/strlen.rs](https://github.com/jvns/rust-bcc/blob/master/examples/strlen.rs). It's a port of [this Python program](https://github.com/iovisor/bcc/blob/master/examples/tracing/strlen_count.py) to Rust.
