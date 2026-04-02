.PHONY: build-ebpf build-loader install clean help

# Default target
all: build-ebpf build-loader

help:
	@echo "Usage:"
	@echo "  make              - Build both eBPF and Loader"
	@echo "  make install      - Build and install as a systemd service"
	@echo "  make clean        - Remove build artifacts"

build-ebpf:
	@echo "--- Building eBPF (Kernel) ---"
	cd certes-interceptor-ebpf && cargo +nightly build --release -Z build-std=core --target bpfel-unknown-none

build-loader:
	@echo "--- Building Loader (User-space) ---"
	cargo build --release

install: all
	@echo "--- Installing Binary to /usr/local/bin ---"
	sudo cp target/release/certes-interceptor /usr/local/bin/
	@echo "--- Installing Systemd Service ---"
	sudo cp certes-interceptor.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable certes-interceptor
	sudo systemctl restart certes-interceptor
	@echo "Done! Interceptor is now active and persistent."

clean:
	cargo clean
	rm -f target/bpfel-unknown-none/release/certes-interceptor-ebpf