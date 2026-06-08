# SOC Report — Brute Force Detector v2

## 1. Resumen ejecutivo

Se ha desarrollado una segunda versión del laboratorio Brute Force Detector para transformar logs de autenticación SSH en datos estructurados y exportables.

La versión v2 mejora la v1 incorporando `pandas`, generación de resúmenes por IP y usuario, clasificación de severidad y exportación de resultados en formato CSV.

## 2. Objetivo técnico

Convertir logs raw de autenticación en información analítica útil para un entorno SOC/SIEM.

Flujo aplicado:

`logs raw -> parsing Python -> DataFrame pandas -> agregación -> severidad -> CSV -> reporte`

## 3. Archivos utilizados

Entrada:

`data/logs/auth_logs_sample.txt`

Script principal:

`scripts/brute_force_detector_v2.py`

Salidas generadas:

- `reports/brute_force_summary_v2.csv`
- `reports/brute_force_users_v2.csv`
- `reports/brute_force_output_v2.txt`

## 4. Resultados generales

Total de eventos analizados: 18  
Failed logins detectados: 15  
Success logins detectados: 3  

## 5. Resumen por IP

| src_ip | failed_attempts | severity |
|---|---:|---|
| 192.168.1.50 | 7 | High |
| 10.0.0.23 | 5 | Medium |
| 203.0.113.10 | 2 | Low |
| 172.16.5.14 | 1 | Low |

## 6. Resumen por usuario

| user | failed_attempts |
|---|---:|
| admin | 5 |
| antonio | 3 |
| root | 3 |
| guest | 2 |
| maria | 1 |
| test | 1 |

## 7. Criterio de severidad

Se aplicó el siguiente criterio:

- `High`: 7 o más intentos fallidos.
- `Medium`: 5 o más intentos fallidos.
- `Low`: menos de 5 intentos fallidos.

Este criterio es válido para laboratorio. En un entorno real debería ajustarse con ventana temporal, criticidad del activo, comportamiento histórico y contexto de red.

## 8. Mejoras frente a v1

La versión v2 añade:

- parsing estructurado de logs;
- uso de `pandas`;
- creación de DataFrames;
- agrupación por IP;
- agrupación por usuario;
- clasificación por severidad;
- exportación CSV;
- base reutilizable para dashboard o carga en SIEM.

## 9. Limitaciones

Esta versión todavía no incluye:

- ventanas temporales;
- detección de login exitoso posterior a múltiples fallos;
- geolocalización o reputación de IP;
- normalización avanzada;
- argumentos por línea de comandos;
- pruebas unitarias;
- dashboard visual.

## 10. Recomendaciones

- Añadir análisis temporal por ventanas de 5 o 10 minutos.
- Exportar también eventos enriquecidos completos.
- Crear una versión compatible con carga en Splunk.
- Preparar visualización en Power BI o dashboard SOC.
- Documentar falsos positivos y escenarios de exclusión.

## 11. Conclusión

Brute Force Detector v2 convierte un análisis básico de logs en una salida estructurada y reutilizable. Esta versión es más cercana a un flujo SOC real porque produce datos exportables, clasifica severidad y prepara el terreno para dashboards, SIEM y análisis posteriores.