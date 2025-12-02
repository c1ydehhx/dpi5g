#!/bin/bash

clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -c xdp_kernel.c -o xdp_kernel.o -g

set -e

DEV=enp1s0f0
PIN_DIR=/sys/fs/bpf/xdp
PROG_NAME=xdp_prog_simple

# 1. Detach any existing XDP program
echo "[*] Detaching any existing XDP..."
ip link set $DEV xdp off 2>/dev/null || true

# 2. Remove previous pinned object (only AFTER detaching)
if [ -e $PIN_DIR/$PROG_NAME ]; then
    echo "[*] Removing old pinned XDP program..."
    rm -f $PIN_DIR/$PROG_NAME
fi

# 3. Clean pinned maps if needed
echo "[*] Cleaning pinned maps..."
for MAP in dns_allow_map xsks_map; do
    if [ -e /sys/fs/bpf/$MAP ]; then
        rm -f /sys/fs/bpf/$MAP
    fi
done

# 4. Load program (this triggers libbpf pinning)
echo "[*] Loading XDP program via libbpf..."
bpftool prog loadall xdp_kernel.o $PIN_DIR

# 5. Attach program
echo "[*] Attaching XDP to NIC..."
bpftool net attach xdp pinned $PIN_DIR/$PROG_NAME dev $DEV

echo "[*] Finished!"
