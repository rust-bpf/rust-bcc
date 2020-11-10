#! /bin/sh
set -exu

# debugfs is used by tracepoints in BPF
mount -t debugfs none /sys/kernel/debug/

BCC=${BCC:-"0.17.0"}
FEATURES=${FEATURES:-"v0_17_0"}
LLVM=${LLVM:-"9"}
RUST_BCC_DIR=${RUST_BCC_DIR:-"/tmp/rust-bcc"}
STATIC=${STATIC:-"true"}

# Install kernel headers
#dpkg -i build/linux-headers-5.9.0-050900*.deb

# Add symlink to kernel header folder
#cd /lib/modules
#ln -s `ls $KERNEL_VERSION*` `uname -r`

# Build and install BCC
cd $RUST_BCC_DIR
#[ ! -d $RUST_BCC_DIR/bcc ] && git clone --single-branch https://github.com/iovisor/bcc.git
#mkdir -p bcc/build
cd bcc/build
#git checkout tags/v$BCC
#cmake ..
#make
make install
find . -name "*.a" -exec cp -v {} /usr/lib/ \;

# for rust-bcc compiling
export RUSTFLAGS="-L /usr/lib -L /usr/lib64 -L /usr/lib/x86_64-linux-gnu -L /usr/lib/llvm-$LLVM/lib"

# Add cargo repo to speed up crate download
#cat >>$CARGO_HOME/config <<EOF
#[source.crates-io]
#registry = "https://github.com/rust-lang/crates.io-index"
#replace-with = 'ustc'
#[source.ustc]
#registry = "git://mirrors.ustc.edu.cn/crates.io-index"
#EOF

# Build and test rust-bcc
cd $RUST_BCC_DIR

if [[ $STATIC == true ]]; then
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
