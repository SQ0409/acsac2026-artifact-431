# NGSetupRequest seed generator

This directory is the public NGSetupRequest seed generator used by the artifact. `main.c` constructs one NGAP-PDU/NGSetupRequest and prints the APER encoding as hexadecimal. `generate_seed.sh` converts that output to the binary `../input/seed.bin` consumed by the fuzzer.

The retained generated source set is about 11 MB and is below the artifact upload limit. It is the smallest dependency-closed distribution validated with the current Makefile; do not delete additional files from these two directories.

## Build and regenerate

On Ubuntu:

```bash
sudo apt-get install build-essential xxd
make clean all
./generate_seed.sh
```

Reviewers may edit the marked public PLMN, gNB ID, RAN node name, TAC, SST, SD, and paging values in `main.c`, rebuild, and regenerate the seed.
