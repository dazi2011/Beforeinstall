# Benchmark Regression Diff

- Previous Run: 2026-03-08T10-47-26Z-6c880f
- Compared At: 2026-03-11T11:03:43.299Z
- Added Samples: 0
- Removed Samples: 0
- Score Increased: 22
- Score Decreased: 0
- Verdict Changes: 14
- New False Positives: 1
- New False Negatives: 0

## New False Positives
- noisy_js_postinstall_sim_01

## New False Negatives
- None

## Top Score Changes
| sample_id | group | previous_score | current_score | delta | previous_verdict | current_verdict |
| --- | --- | ---: | ---: | ---: | --- | --- |
| suspicious_shell_multistage_chain_note_02 | suspicious | 0 | 100 | 100 | clean | malicious |
| noisy_js_postinstall_sim_01 | noisy_benign | 0 | 80 | 80 | clean | malicious |
| suspicious_hybrid_chain_sim_01 | suspicious | 0 | 80 | 80 | clean | malicious |
| suspicious_applescript_doshell_echo_02 | suspicious | 2 | 80 | 78 | clean | malicious |
| suspicious_applescript_terminal_download_print_02 | suspicious | 2 | 80 | 78 | clean | malicious |
| suspicious_python_echo_chain_02 | suspicious | 4 | 80 | 76 | clean | malicious |
| suspicious_js_buffer_obfuscation_sim_02 | suspicious | 4 | 75 | 71 | clean | malicious |
| suspicious_js_child_process_echo_chain_02 | suspicious | 11 | 80 | 69 | clean | malicious |
| suspicious_shell_launchagent_mirror_02 | suspicious | 30 | 70 | 40 | suspicious | malicious |
| suspicious_shell_persistence_sim_01 | suspicious | 30 | 70 | 40 | suspicious | malicious |
| suspicious_js_obfuscation_sim_01 | suspicious | 21 | 60 | 39 | clean | malicious |
| noisy_shell_installer_like_01 | noisy_benign | 35 | 69 | 34 | suspicious | malicious |
| suspicious_shell_download_exec_string_02 | suspicious | 53 | 80 | 27 | suspicious | malicious |
| clean_plist_launchagent_template_01 | clean | 0 | 20 | 20 | clean | clean |
| clean_shell_open_safe_site_01 | clean | 0 | 20 | 20 | clean | clean |
| clean_shell_write_test_plist_01 | clean | 0 | 20 | 20 | clean | clean |
| suspicious_hybrid_app_bundle_fixture_02 | suspicious | 63 | 83 | 20 | malicious | malicious |
| suspicious_hybrid_dmg_mirror_fixture_02 | suspicious | 53 | 73 | 20 | suspicious | malicious |
| suspicious_python_launchagent_mirror_02 | suspicious | 0 | 20 | 20 | clean | clean |
| suspicious_python_reverse_shell_string_02 | suspicious | 0 | 20 | 20 | clean | clean |

## Verdict Changes
- noisy_js_postinstall_sim_01: clean -> malicious (0 -> 80)
- noisy_shell_installer_like_01: suspicious -> malicious (35 -> 69)
- suspicious_applescript_doshell_echo_02: clean -> malicious (2 -> 80)
- suspicious_applescript_terminal_download_print_02: clean -> malicious (2 -> 80)
- suspicious_hybrid_chain_sim_01: clean -> malicious (0 -> 80)
- suspicious_hybrid_dmg_mirror_fixture_02: suspicious -> malicious (53 -> 73)
- suspicious_js_buffer_obfuscation_sim_02: clean -> malicious (4 -> 75)
- suspicious_js_child_process_echo_chain_02: clean -> malicious (11 -> 80)
- suspicious_js_obfuscation_sim_01: clean -> malicious (21 -> 60)
- suspicious_python_echo_chain_02: clean -> malicious (4 -> 80)
- suspicious_shell_download_exec_string_02: suspicious -> malicious (53 -> 80)
- suspicious_shell_launchagent_mirror_02: suspicious -> malicious (30 -> 70)
- suspicious_shell_multistage_chain_note_02: clean -> malicious (0 -> 100)
- suspicious_shell_persistence_sim_01: suspicious -> malicious (30 -> 70)

## Notes
- shared_samples=85
- verdict_changes=14
- score_increased=22
- score_decreased=0
- new_false_positives=1
- new_false_negatives=0