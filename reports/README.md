# Reports

Each run writes a Markdown scorecard and a JSON file with every trial's raw output here.
Run outputs are git-ignored by default. Commit the ones you want to publish.

`examples/mock-echo-selftest.*` is a **harness self-test** against the offline mock target that
repeats its whole context. It shows the report format and proves the detectors fire. It says
nothing about any real model.
