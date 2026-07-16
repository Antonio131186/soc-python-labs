from pathlib import Path
from collections import Counter

LOG_FILE = Path("data/logs/auth_logs_sample.txt")
FAILED_THRESHOLD = 5

total_events = 0
failed_logins = 0
success_logins = 0

failed_by_ip = Counter()
failed_users = Counter()

with LOG_FILE.open('r', encoding='utf-8') as file:
    for line in file:
        line = line.strip()

        if not line:
            continue

        total_events += 1

        parts = line.split()

        event_date = parts[0]
        event_time = parts[1]

        fields = {}

        for item in parts[2:]:
            if '=' in item:
                key, value = item.split('=', 1)
                fields[key]= value

        event_type = fields.get('event')
        src_ip = fields.get('src_ip', 'unknown')
        user = fields.get('user', 'unknown')

        if event_type == 'FAILED_LOGIN':
            failed_logins += 1
            failed_by_ip[src_ip] += 1
            failed_users[user] += 1

        elif event_type == 'SUCCESS_LOGIN':
            success_logins += 1


print("=== Brute Force Detector v2 ===")
print(f'total eventos analizados : {total_events}')
print(f'Failed logins detectados: {failed_logins}')
print(f'Success logins detectados: {success_logins}')

print('\n Failed logins por IP:')
for ip, count in failed_by_ip.most_common(5):
    print(f'{ip} -> {count} intentos fallidos')

print('\n Failed logins por usuario:')
for user, count in failed_users.most_common(5):
    print(f'{user} -> {count} intentos fallidos')

print(f'\n IPs sospechosas Umbral >= {FAILED_THRESHOLD}')
for ip, count in failed_by_ip.most_common():
    if count >= FAILED_THRESHOLD: 
        print(f'ALERTA:{ip} -> {count} intentos fallidos')





