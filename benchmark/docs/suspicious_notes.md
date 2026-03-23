# Suspicious Synthetic Fixture Notes

This document summarizes design intent for newly added `benchmark/suspicious` fixtures.
All samples are intentionally non-operational and remain within project-safe boundaries.

## Shell
- `suspicious_shell_download_exec_string_02`: contains `curl | sh` string and dry-run logging only.
- `suspicious_shell_launchagent_mirror_02`: writes LaunchAgent-like plist to `sandbox_sensitive_mirror/Library/LaunchAgents/`.
- `suspicious_shell_profile_mirror_02`: appends startup-like line to `sandbox_sensitive_mirror/home/.zshrc` only.
- `suspicious_shell_base64_decode_print_02`: decodes suspicious command text but prints it only.
- `suspicious_shell_mktemp_chain_sim_02`: simulates mktemp-download-exec sequence via would-do messages.
- `suspicious_shell_multistage_chain_note_02`: expresses multi-stage chain in comments/strings only.

## Python
- `suspicious_python_echo_chain_02`: uses `os.system/subprocess` with echo-only command simulation.
- `suspicious_python_download_would_execute_02`: downloads text and prints `would execute` marker without execution.
- `suspicious_python_launchagent_mirror_02`: writes plist artifact to sandbox mirror path.
- `suspicious_python_obfuscation_restore_02`: base64+zlib+marshal restore pipeline ending in harmless text.
- `suspicious_python_socket_metadata_sim_02`: builds C2-like target metadata without connecting.
- `suspicious_python_reverse_shell_string_02`: reverse-shell style string fixture with no runtime networking.

## AppleScript
- `suspicious_applescript_doshell_echo_02`: `do shell script` executes echo around dangerous string.
- `suspicious_applescript_terminal_download_print_02`: Terminal automation prints simulated download command.
- `suspicious_applescript_auth_lure_prompt_02`: social-engineering-style authorization prompt fixture.
- `suspicious_applescript_system_settings_text_02`: settings-related permission text without navigation.

## JavaScript
- `suspicious_js_child_process_echo_chain_02`: child_process API with echo-only suspicious command string.
- `suspicious_js_eval_decode_message_02`: eval of decoded fixed harmless literal.
- `suspicious_js_download_execute_sim_02`: network fetch plus dry-run log write, no code execution.
- `suspicious_js_buffer_obfuscation_sim_02`: Buffer/base64 obfuscation demonstration with decode-only behavior.

## Hybrid
- `suspicious_hybrid_app_bundle_fixture_02`: `.app` fixture with suspicious resource scripts that only print dry-run messages.
- `suspicious_hybrid_pkg_fixture_02`: pkg-like fixture, postinstall simulates persistence to sandbox mirror only.
- `suspicious_hybrid_dmg_mirror_fixture_02`: dmg-style mirror containing suspicious app/script composition for static analysis stress tests.

## Expected Rule Families
Common expected rule hits across this set:
- `download_execute_pattern`
- `persistence_pattern`
- `shell_spawn_pattern`
- `obfuscation_pattern`
- `installer_script_pattern`
- `social_engineering_pattern`
- `network_beacon_pattern`
