# Build compatibility headers

The fuzzer uses a small local DOT writer and no-op libcap declarations so the minimum build does not depend on optional Graphviz/libcap development packages. The generated `output/ipsm.dot` remains compatible with standard Graphviz tools when installed.
