#!/bin/sh
# Note the generated opensnoop executable must be run with sudo.
set -e
python opensnoop.py
gcc -O3 -lbcc_bpf  opensnoop.c -o opensnoop -lbcc_bpf -lelf -lz --static
#clang opensnoop.c -lelf -O3 -o opensnoop /usr/lib/x86_64-linux-gnu/libbcc_bpf.a 
#libbpf.so
