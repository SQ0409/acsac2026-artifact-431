# Fuzzer core

This directory contains only the AFLNet execution core needed for the public NGAP example. Replay utilities, QEMU mode, original AFL helper binaries, and prebuilt objects are intentionally omitted. Build with `make clean all` on Linux. The local compatibility headers keep DOT state output available without requiring Graphviz or libcap development headers.
