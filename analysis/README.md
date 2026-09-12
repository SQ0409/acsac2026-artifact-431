# Optional analysis helpers

These Python helpers support packet capture, state tracking, and message/coverage summaries after a run. They are not required to build or launch the minimum fuzzer. Configure capture interfaces and addresses for the local Open5GS deployment before use.

## Capture and message statistics

Install the optional dependencies from `requirements.txt` (and `tshark` for
PyShark), then start the capture worker in one terminal:

```bash
export CAPTURE_INTERFACE=any
export GNB_IP=127.0.0.1
export AMF_IP=127.0.0.5
python3 analysis/capture_worker.py
```

Run the fuzzer in a second terminal. Stop the worker with `Ctrl-C` after the
campaign. To create summaries from its `logs/capture_summary.log`:

```bash
cd analysis
python3 coverage_analyzer.py base ../logs/capture_summary.log
python3 coverage_analyzer.py comp ../logs/capture_summary.log
```

The analyzer writes `message_stats_base.txt` or `message_stats_comp.txt` in
the current directory. The `msg:` value is the number of distinct decoded
message types. It is a protocol-message coverage measure, not source-code
coverage. The compact examples in `../examples/f1/` show the expected report
format.

## State-transition coverage

`state_tracker.py` converts a reviewer-provided `AMF.dot` graph to
`amf_transitions_clean.json`; the graph is deployment-specific and is not
bundled. `coverage_analyzer.py` and `visualize_coverage.py` therefore require
the corresponding transition/report files when a reviewer wants transition
coverage. This optional analysis is separate from the AFLNet run and from the
JSON mutation counters printed by the fuzzer.
