# SOC Python Labs — Defensive Security Portfolio

Defensive cybersecurity labs focused on SOC analysis, SIEM-oriented detection logic, log parsing, brute force detection, security data analysis and technical reporting.

This repository is part of my professional transition into SOC / SIEM / Cybersecurity Data Analyst roles. The goal is to build practical, documented and defensible projects based on realistic security operations workflows.

## Current Lab

### Lab 01 — SSH Brute Force Detection

This lab simulates the analysis of authentication logs to detect possible brute force activity against SSH services.

The workflow includes:

* Parsing raw authentication logs.
* Converting unstructured log lines into structured CSV data.
* Aggregating failed login attempts by source IP.
* Classifying IP activity by severity.
* Generating SOC-style findings with recommendations.
* Preparing outputs that can be used for reports, dashboards or SIEM logic.

## Workflow

```text
Raw authentication logs
        ↓
log_parser_core.py
        ↓
parsed_auth_events.csv
        ↓
brute_force_detector_core.py
        ↓
brute_force_findings.csv
        ↓
SOC report / SIEM use case / dashboard
```

## Repository Structure

```text
data/
  logs/        Sample authentication logs

scripts/
  Python scripts for log parsing and detection

outputs/
  Generated structured datasets and detection findings

reports/
  SOC reports and analysis outputs

splunk/
  SPL queries and SIEM-oriented detection logic

docs/
  Technical notes and documentation

splunk/screenshots/
  Visual evidence for portfolio documentation
```

## Tools and Technologies

* Python
* pandas
* pathlib
* CSV
* Linux / Kali
* Git / GitHub
* Splunk SPL
* Defensive security analysis

## Detection Logic

The current brute force detection logic is based on failed authentication attempts grouped by source IP.

Severity thresholds:

```text
High   → 7 or more failed login attempts
Medium → 5 or more failed login attempts
Low    → fewer than 5 failed login attempts
```

Each finding includes:

* Source IP
* Total events
* Failed login attempts
* Successful login attempts
* Severity
* SOC-oriented recommendation

## Example Finding

```text
192.168.1.50 → 7 failed attempts → High severity
10.0.0.23    → 5 failed attempts → Medium severity
```

## Professional Value

This project demonstrates the ability to:

* Transform raw security logs into structured data.
* Build reusable Python scripts for SOC workflows.
* Identify suspicious authentication patterns.
* Generate detection outputs that support triage and reporting.
* Document security findings in a professional and reproducible way.

## Status

Actively maintained — Lab 01 core logic complete and tested.

Completed:
* Core brute force detection logic with severity classification.
* Error handling for missing, empty or corrupted input files.
* Previous script iterations preserved in `scripts/archive/` for reference.

Planned improvements:
* Add SOC incident report in Markdown.
* Add logging module for execution tracking.
* Add argparse for configurable input/output paths.
* Add docstrings to all functions.
* Add visual evidence and portfolio screenshots.
