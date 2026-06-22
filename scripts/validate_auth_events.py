from pathlib import Path
import pandas as pd

INPUT_FILE = Path('outputs/parsed_auth_events.csv')

REQUIRED_COLUMNS = {
    'event_id',
    'event_time',
    'event_date',
    'event_datetime',
    'src_ip',
    'user',
    'event',
    'service',
    'status'
}

VALID_EVENTS = {'FAILED_LOGIN', 'SUCCESS_LOGIN'}

def check_file_exists (file_path: Path) -> bool:
    if not file_path.exists():
        print(f'[ERROR] File not found: {file_path}')
        return False

    print(f'[OK] file exists: {file_path}')
    return True

def check_required_columns(df: pd.DataFrame) -> bool:
    missing_columns = []

    for column in REQUIRED_COLUMNS:
        if column not in df.columns:
            missing_columns.append(column)

    if missing_columns:
        print(f'[ERROR] Missing required columns: {missing_columns}')
        return False
    
    print(f'[OK] all required columns are present.')
    return True

def check_missing_values(df: pd.DataFrame) -> bool:
    critical_columns = ['event_id', 'event_datetime', 'src_ip', 'user', 'event']

    missing_values = df[critical_columns].isnull().sum()
    missing_values = missing_values[missing_values > 0]

    if not missing_values.empty:
        print(f'[ERROR] Missing values found in critical columns:')
        for column, count in missing_values.items():
            print(f" - {column}: {count}")
        return False

    print("[OK] No missing values in critical columns.")
    return True
def check_valid_events(df: pd.DataFrame) -> bool:
    invalid_events = df[~df["event"].isin(VALID_EVENTS)]

    if not invalid_events.empty:
        print("[ERROR] Invalid event types found:")
        print(invalid_events["event"].unique())
        return False

    print("[OK] Event types are valid.")
    return True


def check_ip_format(df: pd.DataFrame) -> bool:
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    invalid_ips = df[~df["src_ip"].astype(str).str.match(ip_pattern)]

    if not invalid_ips.empty:
        print("[ERROR] Invalid IP format found:")
        print(invalid_ips["src_ip"].unique())
        return False

    print("[OK] Source IP format looks valid.")
    return True
def main() -> None:
    print("=== Auth Events Validator ===")

    if not check_file_exists(INPUT_FILE):
        return

    df = pd.read_csv(INPUT_FILE)

    validation_results = [
        check_required_columns(df),
        check_missing_values(df),
        check_valid_events(df),
        check_ip_format(df),
    ]

    print("\n=== Validation Summary ===")
    print(f"Rows analyzed: {len(df)}")
    print(f"Columns found: {len(df.columns)}")

    if all(validation_results):
        print("[PASS] Dataset validation completed successfully.")
    else:
        print("[FAIL] Dataset validation found issues.")


if __name__ == "__main__":
    main()





