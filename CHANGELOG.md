# [Unreleased]

# [0.0.34] - 2023-10-25
## Changed
- Update readme to indicate that crate is not actively maintained and that users
  should consider libbpf-rs instead

## Fixed
- Bugfix (byte ordering) in the tcpretrans example

# [0.0.33] - 2022-09-09
## Added
- Support to dump BPF program instructions. (#181)
- Support for attaching BPF programs to sockets. (#191)

## Fixed
- Removes potential segfault in safe code by making `Table::new()` inaccessible
  outside of this crate. (#192)
- Various fixes to support running in CI environment. (#194)

# [0.0.32] - 2021-11-23
## Added
- Adds support for bcc 0.19.0
- Adds support for bcc 0.20.0
- Adds support for bcc 0.21.0
- Adds support for bcc 0.22.0
- Adds support for bcc 0.23.0

## Changed
- Default bcc version is now 0.23.0

# [0.0.31] - 2021-03-29
## Fixed
- Fixed a few examples to use unaligned pointer reads.

## Added
- Adds support for bcc 0.18.0
- Adds raw perf event support.
- Adds User Statically-Defined Tracing (USDT) support.

# [0.0.30] - 2020-11-23
## Fixed
- `biosnoop` and `opensnoop` examples now use the new builder pattern for
  creating `PerfMap`s.

## Added
- Support for bcc 0.17.0
- Now supporting BPF `RingBuf` data structures.

## Changed
- Default bcc version is now 0.17.0
- Marked `init_perf_map` function as deprecated. `PerfMapBuilder` should be used
  instead.

# [0.0.29] - 2020-10-20
## Fixed
- `get_syscall_fnname` now returns proper prefix.

# [0.0.28] - 2020-10-06
## Added
- Adds BPF debug level to remaining load methods.

## Changed
- Setting the debug level on the `BPFBuilder` no-longer returns a result, as it
  cannot fail. Improves ergonomics.

# [0.0.27] - 2020-10-01
## Added
- Support for loading BPF programs with `load_func()`, which enables BPF
  tail-calls.
- Support for setting BPF debug level.
- Support for XDP programs, used for packet processing.

# [0.0.26] - 2020-09-23
## Fixed
- Resolved collisions between uprobes and uretprobes when the same symbol is
  used for each.

# [0.0.25] - 2020-09-15
## Added
- Support for bcc 0.16.0
- Builder-pattern construction of `BPF` struct.
- Support for passing `CFLAGS` to BPF module creation.
- Builder-pattern construction of `PerfMap`s.
- Support for setting the size of the `PerfMap` ring buffer.

## Changed
- Default bcc version is now 0.16.0
- Some function signatures now return `Result`s to enable better error handling
  and reduce internal `unwrap()` usage.
- Some error types now include additional messaging.

## Fixed
- Builds on `aarch64` by correcting the internal representation of `char` types.

# [0.0.24] - 2020-08-20
## Fixed
- `Kprobe`s and `Uprobe`s are now properly closed on drop. Fixed #44

# [0.0.23] - 2020-08-13
## Added
- Support for `BPF_PERF_ARRAY`.

## Fixed
- `PerfEvent`s are not properly closed on drop.
- BPF `Table` now returns the value for the first entry instead of always
  returning zero for the first entry.

# [0.0.22] - 2020-08-03
## Added
- Support for attaching probes to perf events and related examples.
- Implementation of `get_syscall_fnname` to support in resolving system calls to
  function names.

## Changed
- Converted probe construction to a builder-style pattern with new public types
  to initialize and attach probes.
- Changed `bcc::core` to now be internal only. Public interface to core
  functionality is now in the root of the module.

# [0.0.21] - 2020-07-24
## Fixed
- Iterating on an empty table would improperly return an entry (#100)
- Fixed some issues with static linking by pulling in a newer version of bcc-sys

## Changed
- LLVM 9 is now the default expected toolchain for static builds

# [0.0.20] - 2020-07-06
## Added
- Added support for bcc 0.15.0

## Changed
- Changed default bcc version to 0.15.0

# [0.0.19] - 2020-07-02
## Added
- Added support for bcc 0.14.0

## Changed
- Changed default bcc version to 0.14.0

# [0.0.18] - 2020-06-29
## Changed
- Changed error handling to use `thiserror` instead of `failure`

# [0.0.17] - 2020-03-20
## Added
- Added support for bcc 0.13.0

## Changed
- Changed default bcc version to 0.13.0
- Updated dependencies

# [0.0.16] - 2020-02-03
## Added
- Makes BPF struct both `Send` and `Sync` by using `AtomicPtr`s instead of bare
  pointers

# [0.0.15] - 2020-01-10
## Added
- Added support for bcc 0.12.0, making it the new default version

# [0.0.14] - 2019-12-10
## Added
- Added support for bcc 0.11.0, making it the new default version
- Added support for raw tracepoints

# [0.0.13] - 2019-10-07
## Added
- Added support to pull multiple perf buffers at once

# [0.0.12] - 2019-09-16
## Added
- Added `biosnoop` example which traces block device IO and is used to test the 
  `get_kprobe_functions()` function in CI

## Fixed
- Use explicit `dyn` on trait objects
- Fixed segfault caused by passing non-null buffer to `bpf_prog_load()`

# [0.0.11] - 2019-09-07
## Added
- Added `runqlat` example to get the distribution of runqueue latency and
  exercise kprobes during CI
- Added `get_kprobe_functions()` which exists in the Python API

## Fixed
- Fixed the 'oh no' bug which would cause panic when using rust-bcc for perf
  events on some systems. Particularly, this would trigger if some CPUs were
  offline

# [0.0.10] - 2019-07-08
## Added
- Added bcc 0.10.0 support
- Added signal handler to examples for `SIGINT`/`SIGTERM` so that `Drop`
  implementations are invoked on `ctrl-c`

# [0.0.9] - 2019-05-22
## Fixed
- Fixed an issue with static linking by updating the `bcc-sys` dependency

# [0.0.7] - 2019-05-14
## Added
- Added bcc 0.9.0 support

# [0.0.6] - 2019-03-15
## Added
- Added support for multiple bcc versions via feature flags
- Added support for bcc versions 0.5.0, 0.6.0, 0.6.1, 0.7.0, 0.8.0
- Added static linking via feature flag

# [0.0.5] - 2019-02-17
## Added
- Updates to Rust 2018 edition

# [0.0.4] - 2018-05-07
## Added
- Added support for tracepoints
- Added `softirqs` example using tracepoints to track time spent in each softirq
  handler

## Fixed
- Fixed missing LICENSE file
- Fixed hardcoded CPU IDs

# [0.0.3] - 2018-02-08
## Fixed
- Fixed safety issues around perf closure API
- Improved error messages for probe attach failures

# [0.0.2] - 2018-02-06
## Fixed
- Fixed unnecessary clone in perf event callback
- Grab bag of idiomatic rust cleanup

# [0.0.1] - 2018-02-05

Initial release.

[Unreleased]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.34...HEAD
[0.0.34]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.33...v0.0.34
[0.0.33]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.32...v0.0.33
[0.0.32]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.31...v0.0.32
[0.0.31]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.30...v0.0.31
[0.0.30]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.29...v0.0.30
[0.0.29]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.28...v0.0.29
[0.0.28]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.27...v0.0.28
[0.0.27]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.26...v0.0.27
[0.0.26]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.25...v0.0.26
[0.0.25]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.24...v0.0.25
[0.0.24]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.23...v0.0.24
[0.0.23]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.22...v0.0.23
[0.0.22]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.21...v0.0.22
[0.0.21]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.20...v0.0.21
[0.0.20]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.19...v0.0.20
[0.0.19]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.18...v0.0.19
[0.0.18]: https://github.com/rust-bpf/rust-bcc/compare/0.0.17...v0.0.18
[0.0.17]: https://github.com/rust-bpf/rust-bcc/compare/0.0.16...0.0.17
[0.0.16]: https://github.com/rust-bpf/rust-bcc/compare/0.0.15...0.0.16
[0.0.15]: https://github.com/rust-bpf/rust-bcc/compare/0.0.14...0.0.15
[0.0.14]: https://github.com/rust-bpf/rust-bcc/compare/0.0.13...0.0.14
[0.0.13]: https://github.com/rust-bpf/rust-bcc/compare/0.0.12...0.0.13
[0.0.12]: https://github.com/rust-bpf/rust-bcc/compare/0.0.11...0.0.12
[0.0.11]: https://github.com/rust-bpf/rust-bcc/compare/0.0.10...0.0.11
[0.0.10]: https://github.com/rust-bpf/rust-bcc/compare/0.0.9...0.0.10
[0.0.9]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.7...0.0.9
[0.0.7]: https://github.com/rust-bpf/rust-bcc/compare/v0.0.6...v0.0.7
[0.0.6]: https://github.com/rust-bpf/rust-bcc/compare/a4e90dff2b47a8e058a933647d1653321fd287ad...v0.0.6
[0.0.5]: https://github.com/rust-bpf/rust-bcc/compare/0a5a09a4ce7f825bcb226f16bfe30abed858bba1...a4e90dff2b47a8e058a933647d1653321fd287ad
[0.0.4]: https://github.com/rust-bpf/rust-bcc/compare/cc0a36fb8f885cdb95e6a5073548b8514948b336...0a5a09a4ce7f825bcb226f16bfe30abed858bba1
[0.0.3]: https://github.com/rust-bpf/rust-bcc/compare/f647dcbc6b3d00f1d7a2e605652ab9c8893a0687...cc0a36fb8f885cdb95e6a5073548b8514948b336
[0.0.2]: https://github.com/rust-bpf/rust-bcc/compare/f7aa684f4da7902104cdbf009738c1ed6288bd13...f647dcbc6b3d00f1d7a2e605652ab9c8893a0687
[0.0.1]: https://github.com/rust-bpf/rust-bcc/tree/f7aa684f4da7902104cdbf009738c1ed6288bd13
