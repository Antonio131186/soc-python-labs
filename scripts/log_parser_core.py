from pathlib import Path
import pandas as pd 

LOG_FILE = Path('data/logs/auth_logs_sample.txt')
OUTPUT_FILE = Path('outputs/parsed_auth_events.csv')

def parse_log_line(line: str, event_id: int) -> dict:
    
    parts = line.strip().split()

    if len(parts) < 3:
        return{}
    
    record = {
        'event_id': event_id,
        'event_date': parts[0],
        'event_time': parts[1],
        'event_datetime': f'{parts[0]} {parts[1]}'
}
    
    for item in parts[2:]:
        if '=' in item:
           key, value = item.split('=', 1)
           record[key] = value

    return record 

def main() -> None:
    records = []

    with LOG_FILE.open('r', encoding='utf-8') as file:
        for event_id, line in enumerate(file, start=1):
            if not line.strip():
                continue

            record = parse_log_line(line, event_id)

            if record:
                records.append(record)

        df = pd.DataFrame(records)

        df['event_datetime'] = pd.to_datetime(df['event_datetime'])

        OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(OUTPUT_FILE, index=False)

        print('=== Log Parsing Completed ===')
        print(f'Eventos Parseados: {len(df)}')
        print(f'Archivo Generado: {OUTPUT_FILE}')

if __name__ == '__main__':
    main()
