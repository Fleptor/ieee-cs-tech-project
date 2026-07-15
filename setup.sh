#!/bin/bash
# Project_CIPHER Linux (Ubuntu/Debian) Development Dependencies
# Run this with: bash setup.sh

echo "🔄 Updating package list..."
sudo apt-get update

echo "🛠️ Installing LLVM, Clang, and Kernel Headers for eBPF..."
# libbpf-dev and linux-headers are crucial for compiling C code that talks to the Linux kernel
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)

echo "📦 Installing FlatBuffers compiler..."
sudo apt-get install -y flatbuffers-compiler

echo "🦀 Checking for Rust toolchain..."
if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
else
    echo "Rust is already installed!"
fi

echo "✅ Setup complete! You can now run 'make' to build Project_CIPHER."