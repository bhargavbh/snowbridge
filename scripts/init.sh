#!/usr/bin/env bash

set -e

echo "Checkout polkadot-sdk Snowfork fork"
pushd ..
if [ ! -d "polkadot-sdk" ]; then
  git clone https://github.com/Snowfork/polkadot-sdk.git
fi
pushd  polkadot-sdk
git checkout snowbridge
popd
popd

ln -sf ../polkadot-sdk polkadot-sdk

echo "Setting up submodules"
git submodule update --init --recursive || true

echo "Setting up git hooks"
git config --local core.hooksPath hooks/

echo "Installing Rust nightly toolchain"
rustup install --profile minimal $RUST_NIGHTLY_VERSION
rustup component add --toolchain $RUST_NIGHTLY_VERSION rustfmt

echo "Installing sszgen"
go install github.com/ferranbt/fastssz/sszgen@v0.1.3

echo "Installing cargo fuzz"
cargo install cargo-fuzz

echo "Installing web packages"
(cd web && pnpm install)

echo "Download geth to replace the nix version"
OS=$(uname -s | tr A-Z a-z)
MACHINE_TYPE=$(uname -m | tr A-Z a-z)
geth_package=geth-$OS-$MACHINE_TYPE-1.13.11-8f7eb9cc
curl https://gethstore.blob.core.windows.net/builds/$geth_package.tar.gz -o /tmp/geth.tar.gz
mkdir -p $GOPATH/bin
tar -xvf /tmp/geth.tar.gz -C $GOPATH
cp $GOPATH/$geth_package/geth $GOPATH/bin
