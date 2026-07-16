from pathlib import Path
import pandas as pd


LOG_FILE = Path("data/logs/auth_logs_sample.txt")
IP_SUMMARY_CSV = Path("reports/brute_force_summary_v2.csv")
USER_SUMMARY_CSV = Path("reports/brute_force_users_v2.csv")

MEDIUM_THRESHOLD = 5
HIGH_THRESHOLD = 7


def parse_log_line(line: str) -> dict:
    """
    Convierte una línea de log en un diccionario estructurado.
    """
    parts = line.strip().split()

    if len(parts) < 3:
        return {}

    record = {
        "date": parts[0],
        "time": parts[1],
    }

    for item in parts[2:]:
        if "=" in item:
            key, value = item.split("=", 1)
            record[key] = value

    return record


def assign_severity(failed_attempts: int) -> str:
    """
    Asigna severidad según número de intentos fallidos.
    """
    if failed_attempts >= HIGH_THRESHOLD:
        return "High"
    if failed_attempts >= MEDIUM_THRESHOLD:
        return "Medium"
    return "Low"


def main() -> None:
    records = []

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            record = parse_log_line(line)

            if record:
                records.append(record)

    df = pd.DataFrame(records)

    total_events = len(df)
    failed_df = df[df["event"] == "FAILED_LOGIN"].copy()
    success_df = df[df["event"] == "SUCCESS_LOGIN"].copy()

    ip_summary = (
        failed_df
        .groupby("src_ip")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values(by="failed_attempts", ascending=False)
    )

    ip_summary["severity"] = ip_summary["failed_attempts"].apply(assign_severity)

    user_summary = (
        failed_df
        .groupby("user")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values(by="failed_attempts", ascending=False)
    )

    IP_SUMMARY_CSV.parent.mkdir(parents=True, exist_ok=True)

    ip_summary.to_csv(IP_SUMMARY_CSV, index=False)
    user_summary.to_csv(USER_SUMMARY_CSV, index=False)

    print("=== Brute Force Detector v2 ===")
    print(f"Total eventos analizados: {total_events}")
    print(f"Failed logins detectados: {len(failed_df)}")
    print(f"Success logins detectados: {len(success_df)}")

    print("\n=== Resumen por IP ===")
    print(ip_summary.to_string(index=False))

    print("\n=== Resumen por usuario ===")
    print(user_summary.to_string(index=False))

    print("\nArchivos generados:")
    print(f"- {IP_SUMMARY_CSV}")
    print(f"- {USER_SUMMARY_CSV}")


if __name__ == "__main__":
    main()
