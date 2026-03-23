# Benchmark Evaluation Summary

- Run ID: 2026-03-08T10-11-22Z-441932
- Benchmark Root: /Users/wudazi/Beforeinstall/benchmark
- Started: 2026-03-08T10:11:22.651Z
- Finished: 2026-03-08T10:11:41.472Z
- Total Samples: 85
- Analyzed Samples: 73
- Failed Samples: 12
- Average Score: 13.15
- Median Score: 10.00
- Verdict Accuracy: 51.76%
- Score Range Match Rate: 32.88%
- False Positive Rate: 4.26%
- False Negative Rate: 86.84%
- Clean FP Rate: 0.00%
- Noisy Benign FP Rate: 9.52%
- Suspicious Hit Rate: 10.71%
- Replay Malicious Detection Rate: 100.00%

## Score Monotonicity
- Monotonic: yes
- No monotonicity warning.

## Group Statistics
| group | total | analyzed | failed | avg_score | clean | suspicious | malicious | unknown |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| clean | 21 | 21 | 0 | 7.38 | 21 | 0 | 0 | 0 |
| noisy_benign | 21 | 21 | 0 | 12.14 | 19 | 2 | 0 | 0 |
| replay_clean | 5 | 1 | 4 | 0.00 | 0 | 0 | 0 | 5 |
| replay_malicious | 5 | 1 | 4 | 100.00 | 0 | 0 | 1 | 4 |
| replay_suspicious | 5 | 1 | 4 | 50.00 | 0 | 1 | 0 | 4 |
| suspicious | 28 | 28 | 0 | 14.29 | 25 | 2 | 1 | 0 |

## Confusion Matrix
- expected=clean: clean=40, suspicious=2, unknown=5
- expected=malicious: clean=2, malicious=1, unknown=4
- expected=suspicious: clean=23, malicious=1, suspicious=3, unknown=4

## Major False Positives
- noisy_js_network_cache_text_01 | group=noisy_benign | verdict=suspicious | score=45
- noisy_shell_installer_like_01 | group=noisy_benign | verdict=suspicious | score=45

## Major False Negatives
- replay_malicious_app_bash_curl_persist_02 | group=replay_malicious | verdict=unknown | score=0
- replay_malicious_app_osascript_chain_02 | group=replay_malicious | verdict=unknown | score=0
- replay_malicious_pkg_postinstall_multiegres_02 | group=replay_malicious | verdict=unknown | score=0
- replay_malicious_python_subprocess_priv_02 | group=replay_malicious | verdict=unknown | score=0

## Errors
- replay_clean_app_lifecycle_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_clean_js_fetch_cache_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_clean_pkg_appsupport_install_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_clean_python_scan_report_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_malicious_app_bash_curl_persist_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_malicious_app_osascript_chain_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_malicious_pkg_postinstall_multiegres_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_malicious_python_subprocess_priv_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_suspicious_app_shell_egress_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_suspicious_pkg_persistence_mirror_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_suspicious_python_decode_plist_mirror_02 | replay_analysis | The data couldn’t be read because it is missing.
- replay_suspicious_shell_fanout_tmp_egress_02 | replay_analysis | The data couldn’t be read because it is missing.