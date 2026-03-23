# Benchmark Regression Diff

- Previous Run: 2026-03-11T11-03-17Z-0aeca4
- Compared At: 2026-03-11T13:09:02.170Z
- Added Samples: 0
- Removed Samples: 0
- Score Increased: 31
- Score Decreased: 4
- Verdict Changes: 18
- New False Positives: 1
- New False Negatives: 0

## New False Positives
- clean_plist_launchagent_template_01

## New False Negatives
- None

## Top Score Changes
| sample_id | group | previous_score | current_score | delta | previous_verdict | current_verdict |
| --- | --- | ---: | ---: | ---: | --- | --- |
| suspicious_js_download_execute_sim_02 | suspicious | 70 | 0 | -70 | malicious | clean |
| suspicious_python_obfuscation_restore_02 | suspicious | 34 | 100 | 66 | suspicious | suspicious |
| suspicious_js_eval_decode_message_02 | suspicious | 19 | 65 | 46 | clean | suspicious |
| suspicious_js_obfuscation_sim_01 | suspicious | 60 | 100 | 40 | malicious | suspicious |
| clean_js_base64_demo_01 | clean | 4 | 37 | 33 | clean | clean |
| suspicious_hybrid_pkg_fixture_02 | suspicious | 10 | 40 | 30 | clean | clean |
| suspicious_shell_persistence_sim_01 | suspicious | 70 | 100 | 30 | malicious | suspicious |
| noisy_shell_installer_like_01 | noisy_benign | 69 | 98 | 29 | malicious | suspicious |
| suspicious_python_reverse_shell_string_02 | suspicious | 20 | 49 | 29 | clean | suspicious |
| noisy_js_child_process_ls_01 | noisy_benign | 11 | 37 | 26 | clean | clean |
| clean_python_subprocess_safe_01 | clean | 10 | 35 | 25 | clean | clean |
| noisy_python_build_subprocess_01 | noisy_benign | 10 | 35 | 25 | clean | clean |
| suspicious_js_buffer_obfuscation_sim_02 | suspicious | 75 | 99 | 24 | malicious | suspicious |
| clean_plist_launchagent_template_01 | clean | 20 | 43 | 23 | clean | suspicious |
| suspicious_shell_launchagent_mirror_02 | suspicious | 70 | 91 | 21 | malicious | suspicious |
| suspicious_js_child_process_echo_chain_02 | suspicious | 80 | 100 | 20 | malicious | suspicious |
| suspicious_shell_download_exec_string_02 | suspicious | 80 | 100 | 20 | malicious | malicious |
| clean_js_child_process_echo_01 | clean | 22 | 41 | 19 | clean | clean |
| clean_shell_open_safe_site_01 | clean | 20 | 39 | 19 | clean | clean |
| clean_shell_write_test_plist_01 | clean | 20 | 39 | 19 | clean | clean |

## Verdict Changes
- clean_plist_launchagent_template_01: clean -> suspicious (20 -> 43)
- noisy_js_postinstall_sim_01: malicious -> suspicious (80 -> 73)
- noisy_shell_installer_like_01: malicious -> suspicious (69 -> 98)
- suspicious_applescript_doshell_echo_02: malicious -> suspicious (80 -> 84)
- suspicious_applescript_terminal_download_print_02: malicious -> suspicious (80 -> 91)
- suspicious_hybrid_app_bundle_fixture_02: malicious -> suspicious (83 -> 82)
- suspicious_hybrid_chain_sim_01: malicious -> suspicious (80 -> 97)
- suspicious_js_buffer_obfuscation_sim_02: malicious -> suspicious (75 -> 99)
- suspicious_js_child_process_echo_chain_02: malicious -> suspicious (80 -> 100)
- suspicious_js_download_execute_sim_02: malicious -> clean (70 -> 0)
- suspicious_js_eval_decode_message_02: clean -> suspicious (19 -> 65)
- suspicious_js_obfuscation_sim_01: malicious -> suspicious (60 -> 100)
- suspicious_python_downloader_sim_01: malicious -> suspicious (95 -> 100)
- suspicious_python_echo_chain_02: malicious -> suspicious (80 -> 95)
- suspicious_python_reverse_shell_string_02: clean -> suspicious (20 -> 49)
- suspicious_shell_launchagent_mirror_02: malicious -> suspicious (70 -> 91)
- suspicious_shell_multistage_chain_note_02: malicious -> suspicious (100 -> 100)
- suspicious_shell_persistence_sim_01: malicious -> suspicious (70 -> 100)

## Notes
- shared_samples=85
- verdict_changes=18
- score_increased=31
- score_decreased=4
- new_false_positives=1
- new_false_negatives=0