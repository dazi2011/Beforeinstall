# Benchmark Regression Diff

- Previous Run: 2026-03-11T13-08-37Z-6a8137
- Compared At: 2026-03-14T13:57:47.865Z
- Added Samples: 0
- Removed Samples: 0
- Score Increased: 53
- Score Decreased: 4
- Verdict Changes: 48
- New False Positives: 25
- New False Negatives: 0

## New False Positives
- clean_js_child_process_echo_01
- clean_js_read_local_config_02
- clean_python_config_rw_02
- clean_python_directory_scan_01
- clean_python_log_rotate_01
- clean_python_subprocess_safe_01
- clean_python_text_summary_01
- clean_shell_backup_01
- clean_shell_backup_02
- clean_shell_log_archive_01
- clean_shell_open_safe_site_01
- clean_shell_write_test_plist_01
- noisy_app_bundle_fixture_01
- noisy_applescript_finder_batch_rename_01
- noisy_js_child_process_ls_01
- noisy_js_network_cache_text_01
- noisy_pkg_preinstall_sim_01
- noisy_python_dynamic_loader_sim_01
- noisy_python_remote_text_api_01
- noisy_python_tempfile_cleanup_01
- noisy_python_updater_01
- noisy_shell_appsupport_style_write_01
- noisy_shell_base64_config_01
- noisy_shell_chmod_tool_01
- noisy_shell_update_checker_02

## New False Negatives
- None

## Top Score Changes
| sample_id | group | previous_score | current_score | delta | previous_verdict | current_verdict |
| --- | --- | ---: | ---: | ---: | --- | --- |
| clean_plist_launchagent_template_01 | clean | 43 | 91 | 48 | suspicious | malicious |
| clean_shell_backup_02 | clean | 0 | 48 | 48 | clean | malicious |
| clean_shell_log_archive_01 | clean | 0 | 48 | 48 | clean | malicious |
| clean_shell_write_test_plist_01 | clean | 39 | 87 | 48 | clean | malicious |
| noisy_app_bundle_fixture_01 | noisy_benign | 0 | 48 | 48 | clean | malicious |
| noisy_shell_appsupport_style_write_01 | noisy_benign | 0 | 48 | 48 | clean | malicious |
| noisy_shell_base64_config_01 | noisy_benign | 0 | 48 | 48 | clean | malicious |
| noisy_shell_update_checker_02 | noisy_benign | 0 | 48 | 48 | clean | malicious |
| suspicious_python_launchagent_mirror_02 | suspicious | 39 | 87 | 48 | clean | malicious |
| suspicious_shell_profile_mirror_02 | suspicious | 0 | 48 | 48 | clean | malicious |
| clean_shell_backup_01 | clean | 0 | 42 | 42 | clean | malicious |
| noisy_shell_chmod_tool_01 | noisy_benign | 0 | 42 | 42 | clean | malicious |
| suspicious_shell_base64_decode_print_02 | suspicious | 0 | 42 | 42 | clean | malicious |
| suspicious_shell_mktemp_chain_sim_02 | suspicious | 0 | 42 | 42 | clean | malicious |
| clean_python_log_rotate_01 | clean | 0 | 36 | 36 | clean | suspicious |
| noisy_applescript_finder_batch_rename_01 | noisy_benign | 17 | 53 | 36 | clean | suspicious |
| noisy_js_network_cache_text_01 | noisy_benign | 0 | 36 | 36 | clean | suspicious |
| noisy_pkg_preinstall_sim_01 | noisy_benign | 0 | 36 | 36 | clean | suspicious |
| noisy_python_updater_01 | noisy_benign | 0 | 36 | 36 | clean | suspicious |
| suspicious_js_download_execute_sim_02 | suspicious | 0 | 36 | 36 | clean | suspicious |

## Verdict Changes
- clean_js_child_process_echo_01: clean -> suspicious (41 -> 71)
- clean_js_read_local_config_02: clean -> suspicious (0 -> 30)
- clean_plist_launchagent_template_01: suspicious -> malicious (43 -> 91)
- clean_python_config_rw_02: clean -> suspicious (0 -> 30)
- clean_python_directory_scan_01: clean -> suspicious (0 -> 30)
- clean_python_log_rotate_01: clean -> suspicious (0 -> 36)
- clean_python_subprocess_safe_01: clean -> suspicious (35 -> 65)
- clean_python_text_summary_01: clean -> suspicious (0 -> 30)
- clean_shell_backup_01: clean -> malicious (0 -> 42)
- clean_shell_backup_02: clean -> malicious (0 -> 48)
- clean_shell_log_archive_01: clean -> malicious (0 -> 48)
- clean_shell_open_safe_site_01: clean -> suspicious (39 -> 69)
- clean_shell_write_test_plist_01: clean -> malicious (39 -> 87)
- noisy_app_bundle_fixture_01: clean -> malicious (0 -> 48)
- noisy_applescript_finder_batch_rename_01: clean -> suspicious (17 -> 53)
- noisy_js_child_process_ls_01: clean -> suspicious (37 -> 67)
- noisy_js_network_cache_text_01: clean -> suspicious (0 -> 36)
- noisy_js_postinstall_sim_01: suspicious -> malicious (73 -> 100)
- noisy_pkg_preinstall_sim_01: clean -> suspicious (0 -> 36)
- noisy_python_dynamic_loader_sim_01: clean -> suspicious (0 -> 30)
- noisy_python_remote_text_api_01: clean -> suspicious (0 -> 30)
- noisy_python_tempfile_cleanup_01: clean -> suspicious (0 -> 30)
- noisy_python_updater_01: clean -> suspicious (0 -> 36)
- noisy_shell_appsupport_style_write_01: clean -> malicious (0 -> 48)
- noisy_shell_base64_config_01: clean -> malicious (0 -> 48)
- noisy_shell_chmod_tool_01: clean -> malicious (0 -> 42)
- noisy_shell_installer_like_01: suspicious -> malicious (98 -> 100)
- noisy_shell_update_checker_02: clean -> malicious (0 -> 48)
- suspicious_applescript_doshell_echo_02: suspicious -> malicious (84 -> 100)
- suspicious_hybrid_app_bundle_fixture_02: suspicious -> malicious (82 -> 48)

## Notes
- shared_samples=85
- verdict_changes=48
- score_increased=53
- score_decreased=4
- new_false_positives=25
- new_false_negatives=0