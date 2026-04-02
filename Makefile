.PHONY: build-ebpf build-loader install clean help

all: build-ebpf build-loader

help:
	@echo "Usage:"
	@echo "  make              - Build both eBPF and Loader"
	@echo "  make install      - Build and safely install or update the systemd service"
	@echo "  make clean        - Remove build artifacts"

build-ebpf:
	@echo "--- Building eBPF (Kernel) ---"
	cd certes-interceptor-ebpf && cargo +nightly build --release -Z build-std=core --target bpfel-unknown-none

build-loader:
	@echo "--- Building Loader (User-space) ---"
	cargo build --release

install: all
	@echo "--- Stopping service (if running) ---"
	-sudo systemctl stop certes-interceptor
	@echo "--- Installing Binary to /usr/local/bin ---"
	# Using 'install' instead of 'cp' is safer for active binaries
	sudo install -m 755 target/release/certes-interceptor /usr/local/bin/certes-interceptor
	@echo "--- Installing Systemd Service ---"
	sudo cp certes-interceptor.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable certes-interceptor
	sudo systemctl start certes-interceptor
	@echo "Done! Interceptor has been updated and restarted."

clean:
	cargo clean