# Benchmarks

OniOps has three levels of measurement. Each one answers a different question.

| Command | What it measures | What it does not measure |
| --- | --- | --- |
| `oniops selftest` | The validators accept real proof and reject known false-positive shapes | Anything about real targets |
| `oniops benchmark --demo-evaluation` | The full pipeline against the bundled practice app (fully labeled) | Real-world recall |
| `oniops benchmark --suite <id>` | An ordinary assessment against a **public vulnerable app**, scored against labeled bugs | Bugs outside the label set, or production apps |

## Running a public-app benchmark

1. **Start a lab target you control.** Juice Shop and VAmPI:

   ```bash
   docker compose -f benchmarks/docker-compose.yml up -d
   ```

   crAPI has its own multi-service stack. Follow
   [crAPI's setup guide](https://github.com/OWASP/crAPI#docker-compose) and keep it on a lab network.

2. **Put the lab in scope.** Add its address to `scope.allowed_cidrs` in `config.yaml`.
   Nothing about the benchmark bypasses the scope engine.

3. **Run a normal assessment.** Use whatever profile, model and auth headers you want to measure.
   Note the start time so you can score only this run:

   ```bash
   START=$(date -u +%Y-%m-%dT%H:%M:%S)
   python -m oniops assess 10.10.0.5 --profile web_app_pt \
       --auth-header "Authorization: Bearer <user A>" \
       --low-priv-header "Authorization: Bearer <user B>"
   ```

4. **Score it.**

   ```bash
   python -m oniops benchmark --suite vampi --target 10.10.0.5 --since "$START" \
       --profile-label web_app_pt --model-label qwen2.5-coder:7b \
       --output results/vampi.json --markdown
   ```

   `python -m oniops benchmark --list-suites` shows the bundled suites.

## How scoring works

- **Only `VERIFIED` findings count.** A finding that matches a label but was not verified is listed
  under `unverified_matches` and does not count as a detection.
- **One-to-one.** Each finding can satisfy at most one label, and duplicates are not credited twice.
- **Recall** = labeled bugs found ÷ labeled bugs. It covers the label set only. Public apps have
  more bugs than any label set.
- **Precision is a range until you triage.** A verified finding that matches no label might be a
  real bug the labels don't cover, or a false positive. These findings are listed under `needs_triage`
  and precision is reported as `precision_min`–`precision_max`. To get a final number, classify them
  in a triage file and pass `--triage`:

  ```yaml
  # triage/vampi-2026-11-12.yaml
  findings:
    41: true    # real bug, not in the labels
    42: false   # false positive
  ```

- **Negative checks** are things the app does correctly. A verified finding there is a known false positive.
- **Informational** patterns (for example "Exposed HTTP service on port") are excluded from scoring.

## Publishing results

Publish the JSON file with the table row. It records the OniOps version, suite version, target
version, profile and model, so anyone can rerun it. Include misses as well as hits, and don't
publish a precision figure while findings are still untriaged.

## Adding or fixing labels

Suites live in [`oniops/bench_suites/`](../oniops/bench_suites). Each label has an `id`, a short `title`,
and `match` patterns (case-insensitive regex):

- `any` matches the finding title and evidence.
- `title` and `evidence` match one field each.
- `category` matches one or more finding categories.

All patterns given must match. Tie patterns to the endpoint so a generic finding cannot satisfy a
specific label. Bump the suite `version` whenever labels change, because results from different
label versions aren't comparable.

> [!NOTE]
> The bundled labels are a first version written from each project's public challenge list. They
> haven't been checked against a full manual run yet. Corrections are very welcome.
