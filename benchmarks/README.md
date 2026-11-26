# Controlled lab benchmarks

`../scripts/benchmark_lab.py` scores a completed scan report against a
versioned, manually maintained ground-truth manifest. It is offline and
does not launch scanners or contact the target.

## Workflow

1. Deploy a deliberately vulnerable application in an isolated lab.
2. Record its exact application/version and known vulnerable and safe cases.
3. Copy `manifest.example.json` to a new manifest and replace the example
   category/title/endpoint values with the actual expected findings.
4. Run the 15-stage analyzer only against the lab's explicitly allowed scope.
5. Score the generated report:

```bash
python scripts/benchmark_lab.py \
  --report output/<scan_id>/reports/security_report.json \
  --scan-state output/<scan_id>/scan_state.json \
  --manifest benchmarks/<lab-version>.json \
  --output output/<scan_id>/reports/benchmark_metrics.json
```

The output includes true positives, false positives, false negatives,
precision, recall, endpoint coverage, potential findings, human-review
items, and the sum of recorded stage durations.

## Measurement constraints

- Maintain a separate manifest for each lab application version.
- Include known-safe controls in the manifest design and review unmatched
  confirmed findings manually before treating them as false positives.
- Do not compare benchmark scores across different target versions,
  configurations, scope policies, or scanner-template versions without
  recording those differences.
- Stage-duration sums are not wall-clock runtime, particularly for resumed
  scans. Record wall-clock start/end times separately when publishing
  performance results.
- The script does not claim benchmark quality until the manifest is
  complete and the same controlled dataset is used across runs.
