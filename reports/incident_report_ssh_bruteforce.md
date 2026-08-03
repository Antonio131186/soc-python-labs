# Informe de Incidente SOC — Actividad de Fuerza Bruta SSH

**ID de incidente:** SOC-LAB-2026-001
**Fecha de detección:** 2026-08-03
**Analista:** Antonio Farci
**Fuente de detección:** `brute_force_detector_core.py` — análisis automatizado de logs de autenticación
**Severidad global del caso:** Alta
**Estado:** Cerrado (entorno de laboratorio)

## 1. Resumen

Durante el análisis rutinario de logs de autenticación SSH se detectó actividad compatible con un ataque de fuerza bruta contra un host interno, junto con actividad secundaria de menor severidad en otras cinco IPs. El análisis se generó ejecutando el detector sobre 18 eventos de autenticación, identificando 6 IPs origen distintas.

## 2. Línea temporal

| Hora (UTC) | Evento |
|---|---|
| 07:32:44 | Ejecución del detector sobre `outputs/parsed_auth_events.csv` |
| 07:32:44 | Clasificación de severidad completada — 6 IPs procesadas |
| 07:32:44 | Generación de `outputs/brute_force_findings.csv` |

*(Nota: timestamps de laboratorio: reflejan el momento de ejecución del análisis, no de los eventos originales, ya que el dataset es una muestra estática.)*

## 3. Evidencia

Evidencia recogida en `scripts/screenshots/`:
- `detector_run_log.png` — log de ejecución con niveles INFO
- `detector_findings_csv.png` — salida estructurada con severidad por IP

### Hallazgos por IP origen

| IP origen | Eventos totales | Intentos fallidos | Logins exitosos | Severidad |
|---|---:|---:|---:|---|
| 192.168.1.50 | 7 | 7 | 0 | **High** |
| 10.0.0.23 | 5 | 5 | 0 | Medium |
| 203.0.113.10 | 2 | 2 | 0 | Low |
| 172.16.5.14 | 2 | 1 | 1 | Low |
| 192.168.1.77 | 1 | 0 | 1 | Low |
| 192.168.1.88 | 1 | 0 | 1 | Low |

## 4. Análisis

**192.168.1.50 (High):** 7 intentos fallidos sin ningún login exitoso registrado. Patrón consistente con fuerza bruta activa sin éxito — el atacante no comprometió la cuenta en la ventana analizada. Requiere revisión inmediata y bloqueo preventivo del origen.

**10.0.0.23 (Medium):** 5 intentos fallidos, sin éxito. IP en rango privado (10.0.0.0/8), lo que sugiere origen interno o VPN — a diferenciar de un atacante externo. Se recomienda correlacionar con inventario de activos internos antes de escalar como amenaza externa.

**203.0.113.10 y 172.16.5.14 (Low):** Volumen de fallos insuficiente para clasificar como ataque activo. 172.16.5.14 incluye un login exitoso tras un fallo — patrón normal de error humano (typo de contraseña), no indicador de compromiso.

**192.168.1.77 y 192.168.1.88 (Low, benignas):** Sin intentos fallidos, solo login exitoso directo. Incluidas en el informe para documentar que el detector no genera falsos positivos sobre actividad legítima — punto relevante para validar la lógica de clasificación.

## 5. Acción tomada (simulada, entorno de laboratorio)

- Clasificación automática de severidad aplicada según umbrales documentados (High ≥7, Medium ≥5, Low <5 intentos fallidos).
- Generación de recomendación específica por IP (ver `brute_force_findings.csv`, columna `recommendation`).
- Caso de 192.168.1.50 marcado para escalado a Nivel 2 por severidad High.

## 6. Recomendación / siguientes pasos

- Bloquear o poner en lista de vigilancia 192.168.1.50 a nivel de firewall/fail2ban.
- Confirmar titularidad y legitimidad de 10.0.0.23 antes de tratarlo como amenaza.
- Ampliar el detector con ventana temporal (actualmente no distingue ráfagas de intentos dispersos en el tiempo vs. concentrados en segundos, lo cual es relevante para diferenciar fuerza bruta real de errores dispersos de usuario).
- Añadir enriquecimiento de geolocalización/reputación de IP en una futura iteración.

## 7. Conclusión

El caso valida el flujo completo de detección: ingestión de logs → parsing → clasificación de severidad → generación de hallazgos accionables. El único hallazgo de severidad alta (192.168.1.50) representa un caso claro de fuerza bruta sin éxito, correctamente aislado del resto de actividad benigna o de bajo riesgo mediante el criterio de clasificación aplicado.