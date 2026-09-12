# NGSetupRequest seed generator

This directory is the public NGSetupRequest seed generator used by the artifact. `main.c` constructs one NGAP-PDU/NGSetupRequest with asn1c-generated types and prints the APER encoding as hexadecimal. `generate_seed.sh` converts that output to the binary `../input/seed.bin` consumed by the fuzzer.

## Files to publish

- `main.c`, `Makefile`, and `generate_seed.sh` are the hand-maintained generator entry points.
- `asn/asn1c/` contains the 44 runtime `.c` files and 43 runtime headers required by this generator. The optional `converter-example.c` demonstration is omitted.
- `asn/ngap/` contains a dependency-closed public subset: 985 generated `.c`/`.h` pairs selected from the full NGAP schema. NGAP open-type and protocol-IE descriptors reference types outside the four IEs visible in `main.c`, so this subset was computed recursively and then verified with a clean link.
- `README.md` files document the generated-source boundary. Do not publish `.o` files or the `encode_ngsetup` binary; they are ignored and rebuilt locally.

The retained generated source set is about 11 MB and is below the artifact upload limit. It is the smallest dependency-closed distribution validated with the current Makefile; do not delete additional files from these two directories.

## Build and regenerate

On Ubuntu/Debian:

```bash
sudo apt-get install build-essential xxd
make clean all
./generate_seed.sh
```

Reviewers may edit the marked public PLMN, gNB ID, RAN node name, TAC, SST, SD, and paging values in `main.c`, rebuild, and regenerate the seed. No subscriber credentials or Open5GS installation is embedded here.
