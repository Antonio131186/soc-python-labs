from pathlib import Path
import sys
import logging
import argparse
import pandas as pd

LOG_FILE = Path('reports/detector.log')
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the Brute Force Detector Core script."""
    parser = argparse.ArgumentParser(
        description='Brute Force Detector Core - analyzes authentication events and flags suspicious IPs by severity.'
    )
    parser.add_argument(
        '--input', '-i',
        type=Path,
        default=Path('outputs/parsed_auth_events.csv'),
        help='Path to the parsed authentication events CSV (default: outputs/parsed_auth_events.csv)'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        default=Path('outputs/brute_force_findings.csv'),
        help='Path to write the findings CSV (default: outputs/brute_force_findings.csv)'
    )
    return parser.parse_args()


MEDIUM_THRESHOLD = 5
HIGH_THRESHOLD = 7

def assign_severity(failed_attempts: int) -> str:
    """Classify severity level based on the number of failed login attempts."""
    if failed_attempts >= HIGH_THRESHOLD:
        return 'High'
    if failed_attempts >= MEDIUM_THRESHOLD:
        return 'Medium'
    
    return 'Low'

def assign_recommendation(severity: str) -> str:
    """Return a SOC-oriented recommendation based on severity level."""
    if severity == 'High' : 
        return 'Immediate review: possible brute force activity.'

    if severity == 'Medium' : 
        return 'Review source IP and correlate with authentication timeline.'

    return 'Monitor activity and validate if behavior repeats.' 

def main() -> None:
    """Run the brute force detection pipeline: load events, aggregate by, 
    source IP, classify severity, generate recommendations and write findings."""

    args = parse_args()
    input_file = args.input
    output_file = args.output

    if not input_file.exists():
        logger.error(f'Error:input file not found -> {input_file}')
        sys.exit(1)

    try:
        df = pd.read_csv(input_file)
    except pd.errors.EmptyDataError:
        logger.error(f'Error: input file is empty -> {input_file}')
        sys.exit(1)
    except Exception as e:
        logger.error(f'Error reading input file: {e}')
        sys.exit(1)
    if df.empty:
        logger.warning(f'No events found in input file-> {input_file}')
        sys.exit(0)

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

    output_file.parent.mkdir(parents=True, exist_ok=True)
    findings.to_csv(output_file, index=False)

    logger.info('=== Brute Force Detector Core ===')
    logger.info(f'Eventos Analizados: {len(df)}')
    logger.info(f'IPs Analizadas: {len(findings)}')
    logger.info(f'Archivo Generado: {output_file}')

if __name__ == '__main__':
    main()
