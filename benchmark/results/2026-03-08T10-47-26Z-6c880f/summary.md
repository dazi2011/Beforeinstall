# Benchmark Evaluation Summary

- Run ID: 2026-03-08T10-47-26Z-6c880f
- Benchmark Root: /Users/wudazi/Beforeinstall/benchmark
- Started: 2026-03-08T10:47:26.728Z
- Finished: 2026-03-08T10:47:28.174Z
- Total Samples: 85
- Analyzed Samples: 85
- Failed Samples: 0
- Effective Coverage Rate: 100.00% (85/85)
- Average Score: 14.21
- Median Score: 0.00
- Verdict Accuracy: 58.82% (matched verdict / labeled samples)
- Score Range Match Rate: 35.62% (matched range / samples with expected range)
- False Positive Rate: 2.13% (1/expected_clean)
- False Negative Rate: 60.53% (23/expected_suspicious_or_malicious)
- Clean FP Rate: 0.00%
- Noisy Benign FP Rate: 4.76%
- Suspicious Hit Rate: 28.57%
- Replay Malicious Detection Rate: 60.00%
- Replay Malicious Detail: total=5, analyzed=5, failed=0, detected=3

## Score Monotonicity
- Monotonic: yes
- No monotonicity warning.

## Group Statistics
| group | total | analyzed | failed | avg_score | clean | suspicious | malicious | unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| clean | 21 | 21 | 0 | 1.76 | 21 | 0 | 0 | 0 |
| noisy_benign | 21 | 21 | 0 | 4.00 | 20 | 1 | 0 | 0 |
| replay_clean | 5 | 5 | 0 | 2.00 | 1 | 0 | 0 | 4 |
| replay_malicious | 5 | 5 | 0 | 64.00 | 2 | 0 | 3 | 0 |
| replay_suspicious | 5 | 5 | 0 | 54.00 | 1 | 1 | 3 | 0 |
| suspicious | 28 | 28 | 0 | 17.39 | 20 | 5 | 3 | 0 |

## Coverage Warnings
- All groups have acceptable analyzed coverage.

## Confusion Matrix
- expected=clean: clean=42, suspicious=1, unknown=4
- expected=malicious: clean=3, malicious=3, suspicious=1
- expected=suspicious: clean=20, malicious=6, suspicious=5

## Major False Positives
- noisy_shell_installer_like_01 | group=noisy_benign | verdict=suspicious | score=35

## Major False Negatives
- replay_malicious_app_osascript_chain_02 | group=replay_malicious | verdict=clean | score=25
- replay_malicious_python_subprocess_priv_02 | group=replay_malicious | verdict=clean | score=25