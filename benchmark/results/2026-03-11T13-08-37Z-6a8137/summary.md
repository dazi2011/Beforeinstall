# Benchmark Evaluation Summary

- Run ID: 2026-03-11T13-08-37Z-6a8137
- Benchmark Root: /Users/wudazi/Beforeinstall/benchmark
- Started: 2026-03-11T13:08:37.184Z
- Finished: 2026-03-11T13:09:02.169Z
- Total Samples: 85
- Analyzed Samples: 85
- Failed Samples: 0
- Effective Coverage Rate: 100.00% (85/85)
- Average Score: 32.89
- Median Score: 17.00
- Verdict Accuracy: 70.59% (matched verdict / labeled samples)
- Score Range Match Rate: 27.40% (matched range / samples with expected range)
- False Positive Rate: 6.38% (3/expected_clean)
- False Negative Rate: 36.84% (14/expected_suspicious_or_malicious)
- Clean FP Rate: 4.76%
- Noisy Benign FP Rate: 9.52%
- Suspicious Hit Rate: 60.71%
- Replay Malicious Detection Rate: 60.00%
- Replay Malicious Detail: total=5, analyzed=5, failed=0, detected=3

## Score Monotonicity
- Monotonic: yes
- No monotonicity warning.

## Group Statistics
| group | total | analyzed | failed | avg_score | clean | suspicious | malicious | unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| clean | 21 | 21 | 0 | 11.95 | 20 | 1 | 0 | 0 |
| noisy_benign | 21 | 21 | 0 | 15.38 | 19 | 2 | 0 | 0 |
| replay_clean | 5 | 5 | 0 | 2.00 | 1 | 0 | 0 | 4 |
| replay_malicious | 5 | 5 | 0 | 64.00 | 2 | 0 | 3 | 0 |
| replay_suspicious | 5 | 5 | 0 | 54.00 | 1 | 1 | 3 | 0 |
| suspicious | 28 | 28 | 0 | 57.93 | 11 | 15 | 2 | 0 |

## Coverage Warnings
- All groups have acceptable analyzed coverage.

## Confusion Matrix
- expected=clean: clean=40, suspicious=3, unknown=4
- expected=malicious: clean=3, malicious=4
- expected=suspicious: clean=11, malicious=4, suspicious=16

## Major False Positives
- clean_plist_launchagent_template_01 | group=clean | verdict=suspicious | score=43
- noisy_js_postinstall_sim_01 | group=noisy_benign | verdict=suspicious | score=73
- noisy_shell_installer_like_01 | group=noisy_benign | verdict=suspicious | score=98

## Major False Negatives
- replay_malicious_app_osascript_chain_02 | group=replay_malicious | verdict=clean | score=25
- replay_malicious_python_subprocess_priv_02 | group=replay_malicious | verdict=clean | score=25