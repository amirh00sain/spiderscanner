# SpiderScanner Version 1

- iSH/Alpine installer accepts Python 3.9+ and checks Python before dependency installation.
- Railway TCP scan targets the observed proxy block `66.33.22.220` through `66.33.22.250`, inclusive.
- The CLI and Advanced Railway scanner use the same TCP target range.

## 2026-09-30 — Fastly Q-stop / score-table fix
- `Q`/Ctrl+C now stops the live scan without starting the long post-scan loss/speed pass.
- The stop watcher remains active through the quality stage and is closed only after results are ready.
- Stopped scans now return immediately with partial scores based only on metrics already measured.
- Normal scans still run the full packet-loss, jitter, reliability, and throughput scoring pipeline.
- Fastly/Cloudflare result tables now appear after a stopped scan and clearly mark partial scores.
