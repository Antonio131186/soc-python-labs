# Splunk Queries — Brute Force Detection Lab

## Objetivo

Estas consultas SPL representan la lógica equivalente al script Python `brute_force_detector.py`, aplicada a un escenario SIEM con logs de autenticación.

El objetivo es detectar patrones compatibles con fuerza bruta a partir de eventos `FAILED_LOGIN`.

## Consulta 1 — Detección por IP

Archivo:

`brute_force_detection.spl`

```spl
index=soc_lab sourcetype=auth_logs event=FAILED_LOGIN
| stats count as failed_attempts by src_ip
| where failed_attempts >= 5
| sort - failed_attempts