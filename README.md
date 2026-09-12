# Public evaluation artifact

This repository contains a small, testable evaluation package for the paper. Some implementation details of the original tool cannot be publicly released. To let reviewers exercise the released workflow, the releasable parts are provided on top of the AFLNet execution substrate: NGAP/NAS message handling, a public knowledge-guided mutation example, and a reproducible NGSetupRequest seed generator.

The package does not include Open5GS, private subscriber credentials, or experiment outputs. Install and configure Open5GS separately, then set its SCTP address in `config/local.env` (or `SCTP_ENDPOINT`). The endpoint must exactly match the AMF `ngap.server.address` and port in `/etc/open5gs/amf.yaml`; it is not necessarily `127.0.0.1`. `targets/dummy` is only a convenient placeholder executable required by the AFL-style command line; it does not send a second SCTP connection and may be replaced by any executable.

## Quick start (Linux)

```bash
sudo apt-get install build-essential libssl-dev xxd       # package names vary
bash scripts/build.sh
cp config/config.example.env config/local.env
# Edit SCTP_ENDPOINT if your AMF uses another address or port.
bash scripts/run_aflnet.sh
```

The build produces `aflnet/afl-fuzz`, the equivalent `targets/dummy` and `targets/sctp_send` placeholders, `seed-generator/encode_ngsetup`, and `input/seed.bin`. The fuzzer's `-N` option is the component that communicates with Open5GS. The `-Z` option loads the single public rule in `config/knowledge.json`; the parser and mutation hooks remain in `aflnet/aflnet.c`.

The fuzzer build requires OpenSSL development headers (`libssl-dev` on Debian/Ubuntu). The seed generator is self-contained and does not require Open5GS. Graphviz and libcap development headers are optional because the artifact includes small compatibility headers for the required DOT/capability interfaces.

## Verification workflow

First run the offline check in the VM:

```bash
bash scripts/validate.sh
```

This rebuilds every component, regenerates `input/seed.bin`, validates the JSON rule, checks both placeholder targets, and verifies the AFLNet entry point. It does not contact Open5GS.

For the network test, install and configure Open5GS separately. Start its AMF and confirm that it listens on the configured SCTP endpoint. For example, with an AMF configured as `ngap.server.address: 127.0.0.5` and the default NGAP port `38412`:

```bash
cp config/config.example.env config/local.env
# edit SCTP_ENDPOINT if the AMF uses a different address or port
sudo ss -lnp -A sctp | grep 38412
bash scripts/run_aflnet.sh
```

On systems where AFLNet stops at `Pipe at the beginning of 'core_pattern'`, temporarily use `echo core | sudo tee /proc/sys/kernel/core_pattern` and rerun the command. This changes only crash-dump handling for the current boot.

If the run reports `Connection refused` or `No server states have been detected`, check the endpoint first. Those messages mean that AFLNet could not establish SCTP communication; they are not caused by the mutation rule. Restart the AMF and compare `ss -lnp -A sctp` with `SCTP_ENDPOINT`. The artifact does not install or start Open5GS for the reviewer.

The initial seed is an NGSetupRequest. Its PLMN, TAC, SST, and optional SD must be compatible with the AMF's `guami`, `tai`, and `plmn_support` values. Edit the marked constants in `seed-generator/main.c`, regenerate the seed, and rerun the fuzzer when using a different Open5GS profile. A PLMN mismatch can result in an NGSetupFailure even when SCTP connectivity is correct.

The script uses `targets/sctp_send` only as a harmless executable argument. AFLNet's `-N` option is the sole SCTP communication path. Stop with `Ctrl-C`; the run data and `output/ipsm.dot` remain under `output/`.

To use a different executable, set `AFLNET_TARGET=/absolute/path/to/program` before starting the script.

## Custom seed

`seed-generator/main.c` is a self-contained NGSetupRequest example using the bundled asn1c-generated NGAP sources. Edit the clearly marked PLMN, gNB ID, RAN node name, TAC, SST, SD, or paging values, then run:

```bash
make -C seed-generator clean all
./seed-generator/generate_seed.sh
```

The resulting binary is always written to `input/seed.bin`.

## Optional analysis

The scripts in `analysis/` are intentionally separate from the minimum run. `capture_worker.py` and the coverage/state analyzers expect a reviewer-provided capture setup and write results under `output/`; no private IPs or credentials are embedded.

Each subdirectory has a README describing its scope and dependencies.
