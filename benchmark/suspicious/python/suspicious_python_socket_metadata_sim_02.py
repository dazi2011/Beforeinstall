#!/usr/bin/env python3

DRY_RUN = True
target_host = "203.0.113.25"
target_port = 443
protocol = "tcp"

connection_descriptor = f"{protocol}://{target_host}:{target_port}"
print("[suspicious] socket target descriptor:", connection_descriptor)
if DRY_RUN:
    print("[dry-run] would attempt outbound connect, but networking action is intentionally skipped")
