# Submission form text

## Abstract

This artifact accompanies ACSAC 2026 submission #431 and provides a public evaluation package for the NGAP/NAS fuzzing workflow used in the paper. It includes the runnable AFLNet-based execution core, NGAP/NAS protocol dictionary, one public knowledge-guided mutation rule, an APER-encoded NGSetupRequest seed generator, and optional packet/state analysis scripts. The artifact is intended to support the paper's protocol-aware fuzzing and seed-construction evaluation; it does not claim the Functional or Reproduced badge. A minimal offline build and seed generation take approximately 1--5 minutes on a two-core Linux VM. Live SCTP/NGAP evaluation additionally requires an externally installed and configured Open5GS AMF; Open5GS is not redistributed. Some implementation details of the original tool and real subscriber credentials cannot be publicly released. They are replaced by compileable placeholders, sanitized example parameters, and a documented placeholder executable so reviewers can build the package, generate their own seed, and connect it to their own Open5GS test profile.

## Hardware requirements

Linux x86_64 machine or VM; at least 2 CPU cores and 4 GB RAM for the offline build. 8 GB RAM is recommended when Open5GS and packet capture run on the same host. No GPU is required. Reserve at least 2 GB free disk space for source/build files and additional space for fuzzing output. Live evaluation requires SCTP connectivity to the reviewer's Open5GS AMF.

## Software requirements

Ubuntu 20.04/22.04 (or another modern Linux distribution), GCC 9+, GNU Make, OpenSSL development headers (`libssl-dev`), `xxd`, and Python 3.8+ for optional analysis. Install the baseline dependencies with `sudo apt-get install build-essential libssl-dev xxd python3`. Open5GS is not needed for offline compilation, seed generation, or configuration checks; it is required only for the live SCTP/NGAP evaluation and must be installed/configured separately by the reviewer. Optional analysis uses `pyshark`, `networkx`, and `pydot` (plus `tshark`).

## VM information commands

Run these commands in the evaluation VM if the form asks for the actual machine rather than the minimum requirements:

```bash
cat /etc/os-release
uname -m
nproc
free -h
df -h .
gcc --version | head -n 1
python3 --version
```

Do not report private IP addresses, subscriber identifiers, keys, or Open5GS credentials in the submission form.
