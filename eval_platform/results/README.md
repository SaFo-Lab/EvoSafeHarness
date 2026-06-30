# results/ — your run outputs land here

This directory is intentionally **empty** in the release. It is the output target
for the evaluation platform: every `platform.py run` / `compare` writes a
`results/<run_name>/` folder here with the scored trajectories, a
`comparison.md` (utility, ASR split into direct/indirect, gate true-positives,
gate-caused benign false-positives), and the per-call cost log.

We do **not** ship our own measured numbers or our searched defense bundles —
this release is the **method and the data**, so you reproduce the results on your
own victim model rather than reading ours off disk. Point a config at your DTAP
env and run; your results will appear next to this file.
