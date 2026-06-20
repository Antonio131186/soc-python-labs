from pathlib import Path
import pandas as pd

INPUT_FILE = Path('outputs/parsed_auth_events.csv')
OUTPUT_FILE = Path('outputs/brute_force_findings.csv')


MEDIUM_THRESHOLD = 5
HIGH_THRESHOLD = 7

def assign_severity(failed_attempts: int) -> str:
    if failed_attempts >= HIGH_THRESHOLD:
        return 'High'
    if failed_attempts >= MEDIUM_THRESHOLD:
        return 'Medium'
    
    return 'Low'

def assign_recommendation(severity: str) -> str:
    if severity == 'High' : 
        return 'Immediate review: possible brute force activity.'

    if severity == 'Medium' : 
        return 'Review source IP and correlate with authentication timeline.'

    return 'Monitor activity and validate if behavior repeats.' 

def main() -> None:
    df = pd.read_csv(INPUT_FILE)

    failed_df = df[df['event'] == 'FAILED_LOGIN'].copy()
    success_df = df[df['event'] == 'SUCCESS_LOGIN'].copy()

    failed_by_ip = (
        failed_df
        .groupby('src_ip')
        .size()
        .reset_index(name='failed_attempts')

    )

    success_by_ip = (
        success_df
        .groupby('src_ip')
        .size()
        .reset_index(name='successful_attempts')
    )

    total_by_ip = (
        df
        .groupby('src_ip')
        .size()
        .reset_index(name='total_events')

    )

    findings = (
        total_by_ip
        .merge(failed_by_ip, on='src_ip', how='left')
        .merge(success_by_ip, on='src_ip', how='left')  

    )

    findings['failed_attempts'] = findings['failed_attempts'].fillna(0).astype(int)
    findings['successful_attempts'] = findings['successful_attempts'].fillna(0).astype(int)

    findings['severity'] = findings['failed_attempts'].apply(assign_severity)
    findings['recommendation'] = findings['severity'].apply(assign_recommendation)

    findings = findings.sort_values(
        by=['failed_attempts', 'total_events'],
        ascending = False 
    )

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    findings.to_csv(OUTPUT_FILE, index=False)

    print('=== Brute Force Detector Core ===')
    print(f'Eventos Analizados: {len(df)}')
    print(f'IPs Analizadas: {len(findings)}')
    print(f'Archivo Generado: {OUTPUT_FILE}')

if __name__ == '__main__':
    main()
