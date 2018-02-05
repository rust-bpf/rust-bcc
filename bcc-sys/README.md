Rust binding for [bcc](https://github.com/iovisor/bcc).

You need to install bcc first before using this binding.

To format the generated bindings, you need to have rustfmt installed. 

Install `rustfmt` with:
```
$ rustup update nightly
$ rustup run nightly cargo install -f rustfmt-nightly
```
The generated binding reflects the nightly bcc build.
