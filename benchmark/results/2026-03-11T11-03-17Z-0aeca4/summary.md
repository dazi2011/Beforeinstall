# Benchmark Evaluation Summary

- Run ID: 2026-03-11T11-03-17Z-0aeca4
- Benchmark Root: /Users/wudazi/Beforeinstall/benchmark
- Started: 2026-03-11T11:03:17.724Z
- Finished: 2026-03-11T11:03:43.298Z
- Total Samples: 85
- Analyzed Samples: 85
- Failed Samples: 0
- Effective Coverage Rate: 100.00% (85/85)
- Average Score: 25.58
- Median Score: 4.00
- Verdict Accuracy: 55.29% (matched verdict / labeled samples)
- Score Range Match Rate: 35.62% (matched range / samples with expected range)
- False Positive Rate: 4.26% (2/expected_clean)
- False Negative Rate: 39.47% (15/expected_suspicious_or_malicious)
- Clean FP Rate: 0.00%
- Noisy Benign FP Rate: 9.52%
- Suspicious Hit Rate: 57.14%
- Replay Malicious Detection Rate: 60.00%
- Replay Malicious Detail: total=5, analyzed=5, failed=0, detected=3

## Score Monotonicity
- Monotonic: yes
- No monotonicity warning.

## Group Statistics
| group | total | analyzed | failed | avg_score | clean | suspicious | malicious | unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| clean | 21 | 21 | 0 | 4.62 | 21 | 0 | 0 | 0 |
| noisy_benign | 21 | 21 | 0 | 9.43 | 19 | 0 | 2 | 0 |
| replay_clean | 5 | 5 | 0 | 2.00 | 1 | 0 | 0 | 4 |
| replay_malicious | 5 | 5 | 0 | 64.00 | 2 | 0 | 3 | 0 |
| replay_suspicious | 5 | 5 | 0 | 54.00 | 1 | 1 | 3 | 0 |
| suspicious | 28 | 28 | 0 | 45.68 | 12 | 1 | 15 | 0 |

## Coverage Warnings
- All groups have acceptable analyzed coverage.

## Confusion Matrix
- expected=clean: clean=41, malicious=2, unknown=4
- expected=malicious: clean=3, malicious=4
- expected=suspicious: clean=12, malicious=17, suspicious=2

## Major False Positives
- noisy_js_postinstall_sim_01 | group=noisy_benign | verdict=malicious | score=80
- noisy_shell_installer_like_01 | group=noisy_benign | verdict=malicious | score=69

## Major False Negatives
- replay_malicious_app_osascript_chain_02 | group=replay_malicious | verdict=clean | score=25
- replay_malicious_python_subprocess_priv_02 | group=replay_malicious | verdict=clean | score=25