# Public evaluation artifact

This repository contains a small, testable evaluation package for the paper. Some implementation details of the original tool cannot be publicly released, so a minimal runnable and inspectable version is presented on the AFLNet execution substrate for reviewer use. The package exposes the NGAP/NAS handling, one public knowledge-guided mutation example, and a reproducible NGSetupRequest seed generator needed to exercise the workflow.

The package does not include Open5GS, private subscriber credentials, or experiment outputs. Install and configure Open5GS separately, then set its SCTP address in `config/local.env` (or `SCTP_ENDPOINT`). The endpoint must exactly match the AMF `ngap.server.address` and port in `/etc/open5gs/amf.yaml`. `targets/dummy` is only a convenient placeholder executable required by the AFL-style command line.

## Quick start (Linux)

```bash
sudo apt-get install build-essential libssl-dev xxd       # package names vary
bash scripts/build.sh
cp config/config.example.env config/local.env
# Edit SCTP_ENDPOINT if your AMF uses another address or port.
bash scripts/run_NGeniusFuzz.sh
```

## Verification workflow

First run the offline check in the VM:

```bash
bash scripts/validate.sh
```

This rebuilds every component, regenerates `input/seed.bin`, validates the JSON rule, checks both placeholder targets, and verifies the fuzzer entry point. 

For the network test, install and configure Open5GS separately. Start its AMF and confirm that it listens on the configured SCTP endpoint. For example, with an AMF configured as `ngap.server.address: 127.0.0.5` and the default NGAP port `38412`:

```bash
cp config/config.example.env config/local.env
# edit SCTP_ENDPOINT if the AMF uses a different address or port
sudo ss -lnp -A sctp | grep 38412
bash scripts/run_NGeniusFuzz.sh
```

The initial seed is an NGSetupRequest. Its PLMN, TAC, SST, and optional SD must be compatible with the AMF's `guami`, `tai`, and `plmn_support` values. Edit the marked constants in `seed-generator/main.c`, regenerate the seed, and rerun the fuzzer when using a different profile. Stop with `Ctrl-C`; the run data and `output/ipsm.dot` remain under `output/`.

## Custom seed

`seed-generator/main.c` is a NGSetupRequest example. Edit the clearly marked PLMN, gNB ID, RAN node name, TAC, SST, SD, or paging values, then run:

```bash
make -C seed-generator clean all
./seed-generator/generate_seed.sh
```

The resulting binary is always written to `input/seed.bin`.

## Optional analysis

The scripts in `analysis/` are intentionally separate from the minimum run. `capture_worker.py` and the coverage/state analyzers expect a reviewer-provided capture setup and write results under `output/`.

Coverage is a two-terminal workflow rather than an automatic post-run step:
start `python3 analysis/capture_worker.py` first, run `bash scripts/run_NGeniusFuzz.sh` in a second terminal, stop the capture worker with `Ctrl-C` after the campaign, and then invoke the analyzers on `logs/capture_summary.log`. If the worker is started after the fuzzer, the earlier packets cannot be reconstructed.

Each subdirectory has a README describing its scope and dependencies.

## F1 illustrative data

`examples/f1/` contains a compact, sanitized evidence package for the F1 workflow. The full packet captures and private run logs are not included. The summaries are supplied for inspection and visualization of the reported message-coverage trend, not as a complete reproduction archive.
