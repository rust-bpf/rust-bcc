#!/bin/bash -ev

set -e

## Functions
function test {
    runner="$1"

    echo "smoketest"
    sudo $runner target/release/examples/smoketest
    echo "runqlat"
    sudo $runner target/release/examples/runqlat --interval 1 --windows 5
    echo "opensnoop"
    sudo $runner target/release/examples/opensnoop --duration 5
    echo "contextswitch"
    sudo $runner target/release/examples/contextswitch --duration 5
}

## Update apt
sudo apt-get update

## Determine version number format for CLANG/LLVM packages
LLVM=${LLVM:-9}

if [[ "${LLVM}" == "6" ]]; then
    export LLVM_PACKAGE="6.0";
else
    export LLVM_PACKAGE="${LLVM}"
fi

## Install kernel headers and dependencies
sudo apt-get --yes install linux-headers-"$(uname -r)"
sudo apt-get --yes remove *llvm* *clang* *gtk*
sudo apt-get --yes install clang-"${LLVM_PACKAGE}" \
    libclang-"${LLVM_PACKAGE}"-dev libelf-dev libfl-dev \
    llvm-"${LLVM_PACKAGE}"-dev libz-dev llvm-"${LLVM_PACKAGE}"

## Install Valgrind and libc debugging symbols
sudo apt-get --yes install libc6-dbg

mkdir -p deps
cd deps

curl -L -O https://sourceware.org/pub/valgrind/valgrind-3.16.1.tar.bz2
tar xjf valgrind-3.16.1.tar.bz2
cd valgrind-3.16.1
./configure
sudo make -j2 install
cd ..

# For static builds, we need to compile the following
if [[ $STATIC == true ]]; then
    export CPPFLAGS="-P"
    export CFLAGS="-fPIC"

    ## Installing make dependencies
    sudo apt-get --yes install autoconf libtool pkg-config

    echo "build binutils"
    curl -L -O ftp://sourceware.org/pub/binutils/snapshots/binutils-2.34.90.tar.xz
    tar xf binutils-2.34.90.tar.xz
    cd binutils-2.34.90
    ./configure --prefix=/usr
    make -j2
    sudo make install
    cd ..

    echo "build zlib"
    curl -L -O https://zlib.net/zlib-1.2.11.tar.gz
    tar xzf zlib-1.2.11.tar.gz
    cd zlib-1.2.11
    ./configure --prefix=/usr
    make -j2
    sudo make install
    cd ..

    echo "build xz"
    curl -L -O https://tukaani.org/xz/xz-5.2.5.tar.gz
    tar xzf xz-5.2.5.tar.gz
    cd xz-5.2.5
    ./configure --prefix=/usr
    make -j2
    sudo make install
    cd ..

    echo "build ncurses"
    curl -L -O ftp://ftp.invisible-island.net/ncurses/ncurses-6.2.tar.gz
    tar xzf ncurses-6.2.tar.gz
    cd ncurses-6.2
    ./configure --prefix=/usr --with-termlib
    make -j2
    sudo make install
    cd ..

    echo "build libxml2"
    if [[ ! -d libxml2 ]]; then
        git clone https://gitlab.gnome.org/GNOME/libxml2
    fi
    cd libxml2
    git checkout 41a34e1f4ffae2ce401600dbb5fe43f8fe402641
    autoreconf -fvi
    ./configure --prefix=/usr --without-python
    make -j2
    sudo make install
    cd ..

    echo "build elfutils"
    curl -L -O ftp://sourceware.org/pub/elfutils/0.180/elfutils-0.180.tar.bz2
    tar xjf elfutils-0.180.tar.bz2
    cd elfutils-0.180
    ./configure --prefix=/usr --disable-debuginfod
    make -j2
    sudo make install
    cd ..
fi

## build/install BCC
if [[ ! -d bcc ]]; then
    git clone https://github.com/iovisor/bcc
fi
cd bcc
git checkout master
git pull
if [[ "${BCC}" == "0.4.0" ]]; then
    git checkout remotes/origin/tag_v0.4.0
elif [[ "${BCC}" == "0.5.0" ]]; then
    git checkout remotes/origin/tag_v0.5.0
elif [[ "${BCC}" == "0.6.0" ]]; then
    git checkout remotes/origin/tag_v0.6.0
elif [[ "${BCC}" == "0.6.1" ]]; then
    git checkout remotes/origin/tag_v0.6.1
elif [[ "${BCC}" == "0.7.0" ]]; then
    git checkout remotes/origin/tag_v0.7.0
elif [[ "${BCC}" == "0.8.0" ]]; then
    git checkout remotes/origin/tag_v0.8.0
elif [[ "${BCC}" == "0.9.0" ]]; then
    git checkout remotes/origin/tag_v0.9.0
elif [[ "${BCC}" == "0.10.0" ]]; then
    git checkout remotes/origin/tag_v0.10.0
elif [[ "${BCC}" == "0.11.0" ]]; then
    git checkout 0fa419a64e71984d42f107c210d3d3f0cc82d59a
elif [[ "${BCC}" == "0.12.0" ]]; then
    git checkout 368a5b0714961953f3e3f61607fa16cb71449c1b
elif [[ "${BCC}" == "0.13.0" ]]; then
    git checkout 942227484d3207f6a42103674001ef01fb5335a0
elif [[ "${BCC}" == "0.14.0" ]]; then
    git checkout ceb458d6a07a42d8d6d3c16a3b8e387b5131d610
elif [[ "${BCC}" == "0.15.0" ]]; then
    git checkout e41f7a3be5c8114ef6a0990e50c2fbabea0e928e
elif [[ "${BCC}" == "0.16.0" ]]; then
    git checkout fecd934a9c0ff581890d218ff6c5101694e9b326
elif [[ "${BCC}" == "0.17.0" ]]; then
    git checkout ad5b82a5196b222ed2cdc738d8444e8c9546a77f
elif [[ "${BCC}" == "0.18.0" ]]; then
    git checkout b1ab869032611d9fcdaea56851cd6126cca2eba8
elif [[ "${BCC}" == "0.19.0" ]]; then
    git checkout 4c561d037e2798563c2e87edcc5a406b020a458c
elif [[ "${BCC}" == "0.20.0" ]]; then
    git checkout 14278bf1a52dd76ff66eed02cc9db7c7ec240da6
elif [[ "${BCC}" == "0.20.0" ]]; then
    git checkout 321c9c979889abce48d0844b3d539ec9a01e6f3c
fi
## Installing BCC dependencies
sudo apt-get --yes install cmake bison

mkdir -p _build
cd _build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make -j2
sudo make install
find . -name "*.a" -exec sudo cp -v {} /usr/lib/ \;
cd ../../..

## Build and test
if [ -n "${FEATURES}" ]; then
    cargo build --release --features "${FEATURES}"
    cargo test --release --features "${FEATURES}"
else
    cargo build --release
    cargo test --release
fi
test

if [[ $STATIC == true ]]; then
    export RUSTFLAGS="-L /usr/lib -L /usr/lib64 -L /usr/lib/llvm-${LLVM}/lib"
    if [ -n "${FEATURES}" ]; then
        cargo build --release --features "${FEATURES} static llvm_${LLVM}"
        cargo test --release --features "${FEATURES} static llvm_${LLVM}"
    else
        cargo build --release --features "static llvm_${LLVM}"
        cargo test --release --features "static llvm_${LLVM}"
    fi
    test
fi

# Run tests with Valgrind
test "valgrind --suppressions=build/valgrind-suppressions.supp --error-exitcode=1"
