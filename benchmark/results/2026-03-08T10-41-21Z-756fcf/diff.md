# Benchmark Regression Diff

- Previous Run: 2026-03-08T10-11-22Z-441932
- Compared At: 2026-03-08T10:41:24.224Z
- Added Samples: 0
- Removed Samples: 0
- Score Increased: 23
- Score Decreased: 41
- Verdict Changes: 14
- New False Positives: 0
- New False Negatives: 0

## New False Positives
- None

## New False Negatives
- None

## Top Score Changes
| sample_id | group | previous_score | current_score | delta | previous_verdict | current_verdict |
| --- | --- | ---: | ---: | ---: | --- | --- |
| replay_malicious_pkg_postinstall_multiegres_02 | replay_malicious | 0 | 95 | 95 | unknown | malicious |
| replay_malicious_app_bash_curl_persist_02 | replay_malicious | 0 | 75 | 75 | unknown | malicious |
| replay_suspicious_pkg_persistence_mirror_02 | replay_suspicious | 0 | 70 | 70 | unknown | malicious |
| replay_suspicious_python_decode_plist_mirror_02 | replay_suspicious | 0 | 65 | 65 | unknown | malicious |
| replay_suspicious_app_shell_egress_02 | replay_suspicious | 0 | 60 | 60 | unknown | malicious |
| suspicious_hybrid_app_bundle_fixture_02 | suspicious | 10 | 63 | 53 | clean | malicious |
| noisy_js_network_cache_text_01 | noisy_benign | 45 | 0 | -45 | suspicious | clean |
| suspicious_hybrid_dmg_mirror_fixture_02 | suspicious | 10 | 53 | 43 | clean | suspicious |
| suspicious_python_downloader_sim_01 | suspicious | 60 | 91 | 31 | malicious | malicious |
| replay_malicious_app_osascript_chain_02 | replay_malicious | 0 | 25 | 25 | unknown | clean |
| replay_malicious_python_subprocess_priv_02 | replay_malicious | 0 | 25 | 25 | unknown | clean |
| replay_suspicious_shell_fanout_tmp_egress_02 | replay_suspicious | 0 | 25 | 25 | unknown | clean |
| suspicious_js_download_execute_sim_02 | suspicious | 45 | 70 | 25 | suspicious | malicious |
| clean_js_base64_demo_01 | clean | 25 | 4 | -21 | clean | clean |
| suspicious_js_buffer_obfuscation_sim_02 | suspicious | 25 | 4 | -21 | clean | clean |
| clean_js_child_process_echo_01 | clean | 10 | 22 | 12 | clean | clean |
| clean_js_config_merge_01 | clean | 10 | 0 | -10 | clean | clean |
| clean_js_read_local_config_02 | clean | 10 | 0 | -10 | clean | clean |
| clean_python_config_rw_02 | clean | 10 | 0 | -10 | clean | clean |
| clean_python_directory_scan_01 | clean | 10 | 0 | -10 | clean | clean |

## Verdict Changes
- noisy_js_network_cache_text_01: suspicious -> clean (45 -> 0)
- replay_clean_js_fetch_cache_02: unknown -> clean (0 -> 10)
- replay_malicious_app_bash_curl_persist_02: unknown -> malicious (0 -> 75)
- replay_malicious_app_osascript_chain_02: unknown -> clean (0 -> 25)
- replay_malicious_pkg_postinstall_multiegres_02: unknown -> malicious (0 -> 95)
- replay_malicious_python_subprocess_priv_02: unknown -> clean (0 -> 25)
- replay_suspicious_app_shell_egress_02: unknown -> malicious (0 -> 60)
- replay_suspicious_pkg_persistence_mirror_02: unknown -> malicious (0 -> 70)
- replay_suspicious_python_decode_plist_mirror_02: unknown -> malicious (0 -> 65)
- replay_suspicious_shell_fanout_tmp_egress_02: unknown -> clean (0 -> 25)
- suspicious_hybrid_app_bundle_fixture_02: clean -> malicious (10 -> 63)
- suspicious_hybrid_dmg_mirror_fixture_02: clean -> suspicious (10 -> 53)
- suspicious_js_download_execute_sim_02: suspicious -> malicious (45 -> 70)
- suspicious_python_obfuscation_restore_02: clean -> suspicious (25 -> 34)

## Notes
- shared_samples=85
- verdict_changes=14
- score_increased=23
- score_decreased=41
- new_false_positives=0
- new_false_negatives=0