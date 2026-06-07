# SOC Report — Brute Force Detector v1

## 1. Resumen ejecutivo

Se ha analizado un conjunto de logs simulados de autenticación SSH con el objetivo de identificar patrones compatibles con intentos de fuerza bruta.

El análisis detectó múltiples intentos fallidos de inicio de sesión desde varias direcciones IP. Dos direcciones superaron el umbral definido de 5 intentos fallidos, por lo que se consideran sospechosas dentro del contexto del laboratorio.

## 2. Alcance

Archivo analizado:

`data/logs/auth_logs_sample.txt`

Tipo de eventos analizados:

- FAILED_LOGIN
- SUCCESS_LOGIN

Servicio observado:

- SSH

## 3. Resultados principales

Total de eventos analizados: 18  
Failed logins detectados: 15  
Success logins detectados: 3  

## 4. IPs sospechosas

| IP | Intentos fallidos | Evaluación |
|---|---:|---|
| 192.168.1.50 | 7 | Supera umbral |
| 10.0.0.23 | 5 | Igual al umbral |

## 5. Usuarios afectados

| Usuario | Intentos fallidos |
|---|---:|
| admin | 5 |
| root | 3 |
| antonio | 3 |
| guest | 2 |
| test | 1 |

## 6. Criterio de detección

Se ha definido un umbral de alerta de:

`>= 5 failed logins por IP`

Este umbral es válido para laboratorio, pero en un entorno real debería ajustarse según:

- ventana temporal;
- criticidad del activo;
- comportamiento habitual del usuario;
- origen interno o externo;
- reputación de la IP;
- volumen normal de autenticaciones.

## 7. Limitaciones

Esta versión no incluye todavía:

- análisis por ventana temporal;
- geolocalización o reputación de IP;
- correlación con login exitoso posterior;
- severidad automática;
- exportación CSV;
- integración SIEM real.

## 8. Recomendaciones

- Revisar las IPs que superan el umbral.
- Correlacionar con eventos de login exitoso posteriores.
- Añadir ventana temporal para reducir falsos positivos.
- Crear una consulta equivalente en Splunk.
- Generar salida CSV para análisis posterior.

## 9. Conclusión

El análisis identifica actividad compatible con fuerza bruta en entorno simulado. Las IPs `192.168.1.50` y `10.0.0.23` requieren revisión prioritaria dentro del contexto del laboratorio.