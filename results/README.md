# Results

Raw logs from the experiment runs. Nothing here is processed.

## Files

`detection_log_<condition>_<scenario>_t<trial>.csv` is the detector's log for one trial. Conditions are `baseline` and `protected`, scenarios are `normal_only` and `normal_plus_attack`, trials are numbered 1 to 4.

`block_events.csv` is the controller and monitor event log for the protected runs. Its first rows are from the pre-experiment verification (`run_id` `block_verification_test`).

`master_detection_log_cumulative.csv` is the cumulative detection log kept alongside the per-trial files.

`pre-experiment/` has the logs from the check that block requests reach the switch before the trials started.

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

## Timestamps

The trial 4 detection logs and `block_events.csv` use wall-clock epoch times. The trial 1 to 3 detection logs and the master log use relative timestamps starting at 1000.
