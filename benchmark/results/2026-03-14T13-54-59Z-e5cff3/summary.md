# Benchmark Evaluation Summary

- Run ID: 2026-03-14T13-54-59Z-e5cff3
- Benchmark Root: /Users/wudazi/Beforeinstall/benchmark
- Started: 2026-03-14T13:54:59.361Z
- Finished: 2026-03-14T13:57:47.864Z
- Total Samples: 85
- Analyzed Samples: 85
- Failed Samples: 0
- Effective Coverage Rate: 100.00% (85/85)
- Average Score: 51.21
- Median Score: 48.00
- Verdict Accuracy: 29.41% (matched verdict / labeled samples)
- Score Range Match Rate: 15.07% (matched range / samples with expected range)
- False Positive Rate: 59.57% (28/expected_clean)
- False Negative Rate: 18.42% (7/expected_suspicious_or_malicious)
- Clean FP Rate: 61.90%
- Noisy Benign FP Rate: 71.43%
- Suspicious Hit Rate: 85.71%
- Replay Malicious Detection Rate: 60.00%
- Replay Malicious Detail: total=5, analyzed=5, failed=0, detected=3

## Score Monotonicity
- Monotonic: no
- suspicious_avg(71.64) should be lower than replay_malicious_avg(64.00).

## Group Statistics
| group | total | analyzed | failed | avg_score | clean | suspicious | malicious | unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| clean | 21 | 21 | 0 | 40.05 | 8 | 8 | 5 | 0 |
| noisy_benign | 21 | 21 | 0 | 43.14 | 6 | 8 | 7 | 0 |
| replay_clean | 5 | 5 | 0 | 2.00 | 1 | 0 | 0 | 4 |
| replay_malicious | 5 | 5 | 0 | 64.00 | 2 | 0 | 3 | 0 |
| replay_suspicious | 5 | 5 | 0 | 54.00 | 1 | 1 | 3 | 0 |
| suspicious | 28 | 28 | 0 | 71.64 | 4 | 5 | 19 | 0 |

## Coverage Warnings
- All groups have acceptable analyzed coverage.

## Confusion Matrix
- expected=clean: clean=15, malicious=12, suspicious=16, unknown=4
- expected=malicious: clean=3, malicious=4
- expected=suspicious: clean=4, malicious=21, suspicious=6

## Major False Positives
- clean_js_child_process_echo_01 | group=clean | verdict=suspicious | score=71
- clean_js_read_local_config_02 | group=clean | verdict=suspicious | score=30
- clean_plist_launchagent_template_01 | group=clean | verdict=malicious | score=91
- clean_python_config_rw_02 | group=clean | verdict=suspicious | score=30
- clean_python_directory_scan_01 | group=clean | verdict=suspicious | score=30
- clean_python_log_rotate_01 | group=clean | verdict=suspicious | score=36
- clean_python_subprocess_safe_01 | group=clean | verdict=suspicious | score=65
- clean_python_text_summary_01 | group=clean | verdict=suspicious | score=30
- clean_shell_backup_01 | group=clean | verdict=malicious | score=42
- clean_shell_backup_02 | group=clean | verdict=malicious | score=48
- clean_shell_log_archive_01 | group=clean | verdict=malicious | score=48
- clean_shell_open_safe_site_01 | group=clean | verdict=suspicious | score=69

## Major False Negatives
- replay_malicious_app_osascript_chain_02 | group=replay_malicious | verdict=clean | score=25
- replay_malicious_python_subprocess_priv_02 | group=replay_malicious | verdict=clean | score=25