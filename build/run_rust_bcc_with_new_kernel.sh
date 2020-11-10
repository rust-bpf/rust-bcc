#! /bin/sh
set -eux

BCC=${BCC:-"0.17.0"}
DOCKER_RUNTIME=${DOCKER_RUNTIME:-"kata-runtime"}
DIST=${DIST:-"bionic"}
FEATURES=${FEATURES:-"v0_17_0"}
KERNEL_VERSION=${KERNEL_VERSION:-"5.9.6"}
LLVM=${LLVM:-9}
STATIC=${STATIC:-"true"}

RUST_BCC_DIR=`pwd`
export GOPATH=$RUST_BCC_DIR/go # Used when build kernel for Kata

# Configure Kata repo
ARCH=`arch`
KATA_BRANCH=master
echo "deb http://download.opensuse.org/repositories/home:/katacontainers:/releases:/${ARCH}:/${KATA_BRANCH}/xUbuntu_$(lsb_release -rs)/ /" \
    | sudo tee /etc/apt/sources.list.d/kata-containers.list
curl -sL  http://download.opensuse.org/repositories/home:/katacontainers:/releases:/${ARCH}:/${KATA_BRANCH}/xUbuntu_$(lsb_release -rs)/Release.key \
    | sudo apt-key add -

# Install Docker and Kata components
sudo apt-get update && sudo apt-get --yes install \
    docker.io \
    kata-proxy \
    kata-runtime \
    kata-shim \
    ;
# Config Docker to use Kata runtime
sudo mkdir -p /etc/docker
sudo cat >/etc/docker/daemon.json <<EOF
{
  "runtimes": {
    "kata-runtime": {
      "path": "/usr/bin/kata-runtime"
    }
  }
}
EOF

# Restart Docker with new OCI driver
sudo systemctl daemon-reload
sudo systemctl restart docker

# Install tools to build kernel
sudo apt-get --yes install \
    bison \
    build-essential \
    flex \
    libelf-dev \
    libncurses-dev \
    libssl-dev \
    ;

# Clone Kata packaging code to build kernel
KATA_DIR=$GOPATH/src/github.com/kata-containers
mkdir -p $KATA_DIR
cd $KATA_DIR
[ ! -d $KATA_DIR/packaging ] && git clone --depth 1 https://github.com/kata-containers/packaging
cd packaging/kernel
# Copy BPF related kernel config
cp $RUST_BCC_DIR/build/bpf.conf ./configs/fragments/common/
# Add following kernel config flag to whitelist, since it's not supported in new kernel
echo CONFIG_MEMCG_SWAP_ENABLED >> configs/fragments/whitelist.conf
# Build new kernel
./build-kernel.sh -v $KERNEL_VERSION -f -d setup
./build-kernel.sh -v $KERNEL_VERSION -d build
# Install new kernel for kata-container, target install path is $DESTDIR/$PREFIX
sudo -E ./build-kernel.sh -v $KERNEL_VERSION -d install

# Verify the new kernel installed for kata-container
sudo docker run \
        -it \
        --rm \
        --runtime=$DOCKER_RUNTIME \
        ubuntu uname -r \
    | grep $KERNEL_VERSION \
    || (echo "Failed to load new kernel $KERNEL_VERSION in Kata" && false)

# Install BCC dependencies
sudo apt-get --yes install \
    bison \
    build-essential \
    cmake \
    flex \
    git \
    libclang-$LLVM-dev \
    libedit-dev \
    libelf-dev \
    libfl-dev \
    libz-dev \
    llvm-$LLVM-dev \
    llvm-$LLVM-dev \
    python \
    ;
# Build BCC
cd $RUST_BCC_DIR
[ ! -d $RUST_BCC_DIR/bcc ] && git clone --single-branch https://github.com/iovisor/bcc.git
mkdir -p bcc/build
cd bcc/build
git checkout tags/v$BCC
cmake ..
make

DOCKER_BUILD_DIR=/tmp/docker_build
mkdir -p $DOCKER_BUILD_DIR
# Use host apt sources to speed up apt install in Kata
cp /etc/apt/sources.list $DOCKER_BUILD_DIR
# Build rust-bcc test environment container
RUST_BCC_DOCKER_NAME=rust-bcc-test-env
sudo docker build $DOCKER_BUILD_DIR \
    --build-arg DIST=$DIST \
    --build-arg WORKDIR=$RUST_BCC_DIR \
    --file $RUST_BCC_DIR/build/Dockerfile.test_env \
    --tag $RUST_BCC_DOCKER_NAME \
    ;

# Test rust-bcc with new kernel in Kata
sudo -E docker run \
    --privileged \
    --rm \
    --runtime=$DOCKER_RUNTIME \
    -it \
    -v $RUST_BCC_DIR:$RUST_BCC_DIR \
    -e BCC=$BCC \
    -e FEATURES=$FEATURES \
    -e LLVM=$LLVM \
    -e RUST_BCC_DIR=$RUST_BCC_DIR \
    -e STATIC=$STATIC \
    $RUST_BCC_DOCKER_NAME \
    /bin/bash -e build/test_rust_bcc_in_kata.sh \
    ;
