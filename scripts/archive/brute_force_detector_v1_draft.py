from pathlib import Path

LOG_FILE = Path("data/logs/auth_logs_sample.txt")

total_events = 0
failed_logins = 0
success_logins = 0

with LOG_FILE.open("r", encoding="utf-8") as file : 
    for line in file:
        line = line.strip()

        if not line:
            continue

        total_events += 1

        if "FAILED_LOGIN" in line:
            failed_logins += 1

        if "SUCCESS_LOGIN" in line:
            success_logins += 1

print("=== Brute Force Detector v1 ===")
print(f"total eventos analizados: {total_events}")
print(f"Failed logins detectados: {failed_logins}")
print(f"Success logins detectados: {success_logins}")