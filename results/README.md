# Results

Raw logs from the experiment runs, plus the tables and figures produced from them by `analysis/analyze_results.py`.

## Raw logs

`detection_log_<condition>_<scenario>_t<trial>.csv` is the detector's log for one run. Conditions are `baseline` and `protected`, scenarios are `normal_only` and `normal_plus_attack`, trials are numbered 1 to 4.

`block_events.csv` is the controller and monitor event log for the protected runs. Its first rows are from the pre-experiment verification (`run_id` `block_verification_test`).

`master_detection_log_cumulative.csv` is the cumulative detection log kept alongside the per-trial files.

`pre-experiment/` has the logs from the check that block requests reach the switch before the trials started. `pre-experiment/detection_log.csv` is the detection log as it stood before the first run.

## Processed output

| File | Content |
|------|---------|
| `results_per_run.csv` | one row per run with connection counts, detection time and block timings |
| `results_summary.csv` | median, minimum and maximum per metric |
| `fig_detection_time.png` | detection time for each attack run |
| `fig_blocking_time.png` | breakdown of the time from first attack connection to DROP rule |

## Columns

Detection logs:

| Column | Meaning |
|--------|---------|
| event | `connection` or `alert` |
| epoch_time | time of the event in seconds |
| source_ip | source address of the connection |
| count | connections from that source inside the window |
| first_in_window | timestamp of the oldest connection still in the window |

Block events:

| Column | Meaning |
|--------|---------|
| run_id, condition, scenario, trial | which trial the row belongs to |
| source_ip | the address being blocked |
| event | `block_requested`, `drop_installed` or `block_removed` |
| epoch_time | time of the event in seconds |

## How the logs are read

For trials 1 to 3 each detection log is a snapshot of everything logged so far, so the analysis recovers each run's own rows by removing the previous snapshot. Trial 4 logs already hold one run each. Rows with timestamps below 1e9 come from earlier replay tests and are ignored. Client-side success rate and PONG latency were not recorded for these runs, so they are not part of the analysis.
