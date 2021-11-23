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

VALGRIND_VERSION="3.16.1"

echo "build valgrind"
date -u
if [ ! -d valgrind-${VALGRIND_VERSION} ]; then
    curl -L -O https://sourceware.org/pub/valgrind/valgrind-${VALGRIND_VERSION}.tar.bz2
    tar xjf valgrind-${VALGRIND_VERSION}.tar.bz2
fi
cd valgrind-${VALGRIND_VERSION}
if [ ! -f Makefile ]; then
    ./configure >/dev/null 2>&1
fi
sudo make -j2 install >/dev/null 2>&1
cd ..

# For static builds, we need to compile the following
if [[ $STATIC == true ]]; then
    ## Installing make dependencies
    sudo apt-get --yes install autoconf libtool pkg-config

    export CPPFLAGS="-P"
    export CFLAGS="-fPIC"

    BINUTILS_VERSION="2.34.90"
    ZLIB_VERSION="1.2.11"
    XZ_VERSION="5.2.5"
    NCURSES_VERSION="6.2"
    LIBXML2_SHA="41a34e1f4ffae2ce401600dbb5fe43f8fe402641"
    ELFUTILS_VERSION="0.180"

    echo "build binutils"
    date -u
    if [ ! -d binutils-${BINUTILS_VERSION} ]; then
        curl -L -O ftp://sourceware.org/pub/binutils/snapshots/binutils-${BINUTILS_VERSION}.tar.xz
        tar xf binutils-${BINUTILS_VERSION}.tar.xz
    fi
    cd binutils-${BINUTILS_VERSION}
    if [ ! -f Makefile ]; then
        ./configure --prefix=/usr >/dev/null 2>&1
    fi
    make -j2 >/dev/null 2>&1
    sudo make install >/dev/null 2>&1
    cd ..

    echo "build zlib"
    date -u
    if [ ! -d zlib-${ZLIB_VERSION} ]; then
        curl -L -O https://zlib.net/zlib-${ZLIB_VERSION}.tar.gz
        tar xzf zlib-${ZLIB_VERSION}.tar.gz
    fi
    cd zlib-${ZLIB_VERSION}
    ./configure --prefix=/usr >/dev/null 2>&1
    make -j2 >/dev/null 2>&1
    sudo make install >/dev/null 2>&1
    cd ..

    echo "build xz"
    date -u
    if [ ! -d xz-${XZ_VERSION} ]; then
        curl -L -O https://tukaani.org/xz/xz-${XZ_VERSION}.tar.gz
        tar xzf xz-${XZ_VERSION}.tar.gz
    fi
    cd xz-${XZ_VERSION}
    if [ ! -f Makefile ]; then
        ./configure --prefix=/usr >/dev/null 2>&1
    fi
    make -j2 >/dev/null 2>&1
    sudo make install >/dev/null 2>&1
    cd ..

    echo "build ncurses"
    date -u
    if [ ! -d ncurses-${NCURSES_VERSION} ]; then
        curl -L -O ftp://ftp.invisible-island.net/ncurses/ncurses-${NCURSES_VERSION}.tar.gz
        tar xzf ncurses-${NCURSES_VERSION}.tar.gz
    fi
    cd ncurses-${NCURSES_VERSION}
    if [ ! -f Makefile ]; then
        ./configure --prefix=/usr --with-termlib >/dev/null 2>&1
    fi
    make -j2 >/dev/null 2>&1
    sudo make install >/dev/null 2>&1
    cd ..

    echo "build libxml2"
    date -u
    if [ ! -d libxml2 ]; then
        git clone https://gitlab.gnome.org/GNOME/libxml2
    fi
    cd libxml2
    git checkout ${LIBXML2_SHA}
    if [ ! -f Makefile ]; then
        autoreconf -fvi >/dev/null 2>&1
        ./configure --prefix=/usr --without-python >/dev/null 2>&1
    fi
    make -j2 >/dev/null 2>&1
    sudo make install >/dev/null 2>&1
    cd ..

    echo "build elfutils"
    date -u
    if [ ! -d elfutils-${ELFUTILS_VERSION} ]; then
        curl -L -O ftp://sourceware.org/pub/elfutils/0.180/elfutils-${ELFUTILS_VERSION}.tar.bz2
        tar xjf elfutils-${ELFUTILS_VERSION}.tar.bz2
    fi
    cd elfutils-${ELFUTILS_VERSION}
    if [ ! -f Makefile ]; then
        ./configure --prefix=/usr --disable-debuginfod >/dev/null 2>&1
    fi
    make -j2 >/dev/null 2>&1
    sudo make install >/dev/null 2>&1
    cd ..
fi


## Installing BCC dependencies
sudo apt-get --yes install cmake bison

## build/install BCC
echo "build bcc"
date -u
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
elif [[ "${BCC}" == "0.21.0" ]]; then
    git checkout 321c9c979889abce48d0844b3d539ec9a01e6f3c
else
    echo "unsupported bcc version: ${BCC}"
    exit 1
fi
mkdir -p _build
cd _build
if [ ! -f Makefile ]; then
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr >/dev/null 2>&1
fi
make -j2 >/dev/null 2>&1
sudo make install >/dev/null 2>&1
find . -name "*.a" -exec sudo cp -v {} /usr/lib/ \;
cd ../../..

echo "prerequisite build complete"
date -u

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
