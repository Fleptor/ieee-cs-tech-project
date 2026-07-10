# Project_CIPHER Master Build Pipeline

.PHONY: all ebpf daemon clean flatbuffers

all: ebpf daemon

# 1. Compile the C code into eBPF Bytecode
ebpf:
	@echo "🧠 Compiling Data Plane (eBPF C Code)..."
	@mkdir -p ebpf/target
	
	# We use clang with the BPF target. 
	# -O2 is strictly required for the Linux Kernel Verifier to accept the eBPF loops/jumps
	clang -O2 -g -target bpf -Wall -Werror \
		-c ebpf/src/kernel_space.c \
		-o ebpf/target/cipher_ebpf.o
	
	@echo "✅ eBPF Compilation complete! (Saved to ebpf/target/cipher_ebpf.o)"

# 2. Compile the Rust User-Space Daemon
daemon:
	@echo "🛡️ Compiling Control Plane (Rust Daemon)..."
	cd daemon && cargo build --release
	@echo "✅ Rust Daemon Compilation complete!"

# 3. Optional: Re-generate the schema_generated.rs from your FlatBuffer schema
flatbuffers:
	@echo "📦 Generating FlatBuffers Rust code..."
	flatc --rust -o daemon/src/ schema/router.fbs
	@echo "✅ FlatBuffers updated!"

# 4. Clean the workspace
clean:
	@echo "🧹 Cleaning up..."
	rm -rf ebpf/target
	cd daemon && cargo clean
	@echo "✅ Workspace clean."