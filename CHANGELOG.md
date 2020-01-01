# [Unreleased]

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

[Unreleased]: https://github.com/rust-bpf/rust-bcc/compare/0.0.14...HEAD
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
