# Fuzzer core

This directory contains only the network-fuzzing execution core needed for the public NGAP example. Replay utilities, QEMU mode, original helper binaries, and prebuilt objects are intentionally omitted. Build with `make clean all` on Linux. The local compatibility headers keep DOT state output available without requiring Graphviz or libcap development headers.
