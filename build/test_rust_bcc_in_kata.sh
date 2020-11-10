#! /bin/sh
set -exu

# debugfs is used by tracepoints in BPF
mount -t debugfs none /sys/kernel/debug/

BCC=${BCC:-"0.17.0"}
BUILD_BCC_INSIDE_KATA=${BUILD_BCC_INSIDE_KATA:-false}
FEATURES=${FEATURES:-"v0_17_0"}
LLVM=${LLVM:-"9"}
RUST_BCC_DIR=${RUST_BCC_DIR:-"."}
STATIC=${STATIC:-"true"}

# Build and install BCC
cd $RUST_BCC_DIR
if [ $BUILD_BCC_INSIDE_KATA = "true" ]; then
    mkdir -p bcc/build
    cd bcc/build
    git checkout tags/v$BCC
    cmake ..
    make
else
    cd bcc/build
    echo "BCC should have been built outside Kata"
fi
make install
find . -name "*.a" -exec cp -v {} /usr/lib/ \;

# for rust-bcc compiling
export RUSTFLAGS="-L /usr/lib -L /usr/lib64 -L /usr/lib/x86_64-linux-gnu -L /usr/lib/llvm-$LLVM/lib"

# Add cargo repo to speed up crate download
#tee $CARGO_HOME/config <<EOF
#[source.crates-io]
#registry = "https://github.com/rust-lang/crates.io-index"
#replace-with = 'ustc'
#[source.ustc]
#registry = "git://mirrors.ustc.edu.cn/crates.io-index"
#EOF

# Build and test rust-bcc
cd $RUST_BCC_DIR

if [ $STATIC = "true" ]; then
    #cargo build --features "${FEATURES} static llvm_${LLVM}"
    cargo test --features "${FEATURES} static llvm_${LLVM}"
else
    #cargo build --features "${FEATURES} static llvm_${LLVM}"
    cargo test --features "${FEATURES} static llvm_${LLVM}"
fi
target/debug/examples/smoketest
target/debug/examples/runqlat --interval 1 --windows 5
target/debug/examples/opensnoop --duration 5
target/debug/examples/biosnoop --duration 5
target/debug/examples/tcpretrans --duration 5
target/debug/examples/contextswitch --duration 5
target/debug/examples/ringbuf_submit
